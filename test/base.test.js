/*
 * SPDX-FileCopyrightText: Copyright Corsinvest Srl
 * SPDX-License-Identifier: MIT
 */

// Offline tests of the hand-written base (src/index.js): https.request is replaced by a fake,
// so no cluster is needed. Run with: npm test

const test = require("node:test");
const assert = require("node:assert/strict");
const https = require("https");
const { EventEmitter } = require("events");
const { PveClient, PveResultException, ResponseType } = require("../src/index.js");

const UPID = "UPID:pve01:0012A3F4:05C1B2D3:6720F1A0:qmsnapshot:100:root@pam:";

/**
 * Replace https.request. `respond(options, body, callNumber)` returns
 * { statusCode, statusMessage, body } (body: string or Buffer), an Error, or "timeout".
 */
function fakeHttps(t, respond) {
  const calls = [];
  const original = https.request;
  https.request = (options, callback) => {
    const req = new EventEmitter();
    let written = "";
    req.write = (data) => (written += data);
    req.destroy = () => {};
    req.end = () => {
      calls.push({ options, body: written });
      const answer = respond(options, written, calls.length);
      setImmediate(() => {
        if (answer instanceof Error) return req.emit("error", answer);
        if (answer === "timeout") return req.emit("timeout");

        const res = new EventEmitter();
        res.statusCode = answer.statusCode;
        res.statusMessage = answer.statusMessage ?? "";
        res.setEncoding = () => {};
        callback(res);
        if (answer.body !== undefined && answer.body !== "") res.emit("data", answer.body);
        res.emit("end");
      });
    };
    return req;
  };
  t.after(() => (https.request = original));
  return calls;
}

const json = (statusCode, data, statusMessage = "OK") => ({
  statusCode,
  statusMessage,
  body: JSON.stringify(data),
});

/** Capture what the client writes to its debug log. */
function captureLog(t, client) {
  const debug = require("debug");
  const lines = [];
  const original = debug.log;
  debug.log = (...args) => lines.push(require("util").format(...args));
  client.logEnabled = true;
  t.after(() => (debug.log = original));
  return lines;
}

test("a body that is the literal null gives a result, not a crash", async (t) => {
  fakeHttps(t, () => ({ statusCode: 200, statusMessage: "OK", body: "null" }));
  const client = new PveClient("pve01");

  const result = await client.get("/version");

  assert.equal(result.response, null);
  assert.equal(result.responseInError, false);
  assert.equal(typeof result.toString(), "string");
});

test("an error status with an empty body keeps status and reason", async (t) => {
  fakeHttps(t, () => ({ statusCode: 401, statusMessage: "authentication failure", body: "" }));
  const client = new PveClient("pve01");

  const result = await client.get("/version");

  assert.equal(result.statusCode, 401);
  assert.equal(result.reasonPhrase, "authentication failure");
  assert.equal(result.isSuccessStatusCode, false);
  assert.equal(client.lastResult, result);
});

test("a success status with a body that is not JSON is an error", async (t) => {
  fakeHttps(t, () => ({ statusCode: 200, statusMessage: "OK", body: "<html>proxy login</html>" }));
  const client = new PveClient("pve01");

  const result = await client.get("/version");

  assert.equal(result.isSuccessStatusCode, false);
  assert.equal(result.statusCode, 502);
  assert.equal(result.reasonPhrase, "The answer is not JSON (HTTP 200): <html>proxy login</html>");
});

test("an error answer with errors is reported by responseInError", async (t) => {
  fakeHttps(t, () =>
    json(400, { data: null, errors: { vmid: "invalid format" } }, "Parameter verification failed.")
  );
  const client = new PveClient("pve01");

  const result = await client.get("/nodes/pve01/qemu/abc/config");

  assert.equal(result.statusCode, 400);
  assert.equal(result.responseInError, true);
});

test("the certificate is not validated unless asked", async (t) => {
  const calls = fakeHttps(t, () => json(200, { data: {} }));
  const client = new PveClient("pve01");

  await client.get("/version");
  assert.equal(calls[0].options.rejectUnauthorized, false);

  client.validateCertificate = true;
  await client.get("/version");
  assert.equal(calls[1].options.rejectUnauthorized, true);
});

test("the method of the request is in the result", async (t) => {
  fakeHttps(t, () => json(200, { data: {} }));
  const client = new PveClient("pve01");

  assert.equal((await client.get("/version")).methodType, "GET");
  assert.equal((await client.create("/nodes/pve01/qemu")).methodType, "POST");
});

test("a task id that is not a UPID is refused before any request", async (t) => {
  const calls = fakeHttps(t, () => json(200, { data: { status: "stopped" } }));
  const client = new PveClient("pve01");

  for (const task of [null, undefined, "", "abc", 100]) {
    await assert.rejects(
      () => client.taskIsRunning(task),
      (error) => error instanceof PveResultException && /not a valid task/.test(error.message)
    );
    await assert.rejects(() => client.waitForTaskToFinish(task, 1, 5), PveResultException);
    await assert.rejects(() => client.getExitStatusTask(task), PveResultException);
  }
  assert.equal(calls.length, 0);
});

test("exit status of a running task is null, of a stopped task is read", async (t) => {
  let status = { status: "running" };
  fakeHttps(t, () => json(200, { data: status }));
  const client = new PveClient("pve01");

  assert.equal(await client.taskIsRunning(UPID), true);
  assert.equal(await client.getExitStatusTask(UPID), null);

  status = { status: "stopped", exitstatus: "OK" };
  assert.equal(await client.taskIsRunning(UPID), false);
  assert.equal(await client.getExitStatusTask(UPID), "OK");
});

test("wait for a task: true when it stops, false when still running at the timeout", async (t) => {
  let status = { status: "stopped", exitstatus: "OK" };
  const calls = fakeHttps(t, () => json(200, { data: status }));
  const client = new PveClient("pve01");

  assert.equal(await client.waitForTaskToFinish(UPID, 5, 100), true);
  assert.match(calls[0].options.path, /^\/api2\/json\/nodes\/pve01\/tasks\/UPID:pve01:.*\/status$/);

  status = { status: "running" };
  assert.equal(await client.waitForTaskToFinish(UPID, 5, 30), false);
});

test("the debug log does not show the ticket, the CSRF token or secrets in the query", async (t) => {
  fakeHttps(t, (options) =>
    options.path.startsWith("/api2/json/access/ticket")
      ? json(200, { data: { ticket: "PVE:root@pam:SECRETTICKET", CSRFPreventionToken: "SECRETCSRF", username: "root@pam" } })
      : json(200, { data: {} })
  );
  const client = new PveClient("pve01");
  const lines = captureLog(t, client);

  assert.equal(await client.login("root@pam", "SECRETPASSWORD"), true);
  await client.get("/access/users", { password: "SECRETQUERY", full: true });

  const log = lines.join("\n");
  assert.ok(log.length > 0, "nothing was logged");
  for (const secret of ["SECRETTICKET", "SECRETCSRF", "SECRETPASSWORD", "SECRETQUERY"]) {
    assert.ok(!log.includes(secret), `the log shows ${secret}`);
  }
  assert.ok(log.includes("root@pam"), "values that are not secret are still logged");
});

test("login reads the realm from user@realm", async (t) => {
  const calls = fakeHttps(t, () => json(200, { data: { ticket: "T", CSRFPreventionToken: "C" } }));
  const client = new PveClient("pve01");

  await client.login("automation@pve", "pw");
  assert.deepEqual(JSON.parse(calls[0].body), { password: "pw", username: "automation", realm: "pve" });

  await client.login("root", "pw");
  assert.deepEqual(JSON.parse(calls[1].body), { password: "pw", username: "root", realm: "pam" });

  await client.login("automation", "pw", "pve");
  assert.deepEqual(JSON.parse(calls[2].body), { password: "pw", username: "automation", realm: "pve" });
});

test("a failed login forgets the previous ticket", async (t) => {
  let ok = true;
  const calls = fakeHttps(t, (options) =>
    options.path.startsWith("/api2/json/access/ticket")
      ? ok
        ? json(200, { data: { ticket: "T1", CSRFPreventionToken: "C1" } })
        : json(401, { data: null }, "authentication failure")
      : json(200, { data: {} })
  );
  const client = new PveClient("pve01");

  assert.equal(await client.login("root@pam", "pw"), true);
  await client.get("/version");
  assert.equal(calls[1].options.headers.Cookie, "PVEAuthCookie=T1");

  ok = false;
  assert.equal(await client.login("root@pam", "wrong"), false);
  assert.equal(calls[2].options.headers.Cookie, undefined, "the old ticket is not sent with a new login");
  await client.get("/version");
  assert.equal(calls[3].options.headers.Cookie, undefined);
});

test("a login answered without a ticket is not a login", async (t) => {
  fakeHttps(t, () => json(200, { data: {} }));
  const client = new PveClient("pve01");

  assert.equal(await client.login("root@pam", "pw"), false);
});

test("a timeout rejects with code ETIMEDOUT", async (t) => {
  fakeHttps(t, () => "timeout");
  const client = new PveClient("pve01");
  client.timeout = 50;

  await assert.rejects(
    () => client.get("/version"),
    (error) => error.code === "ETIMEDOUT" && /timeout after 50ms/.test(error.message)
  );
});

test("a network error rejects with the error of Node", async (t) => {
  fakeHttps(t, () => Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" }));
  const client = new PveClient("pve01");

  await assert.rejects(() => client.get("/version"), (error) => error.code === "ECONNREFUSED");
});

test("png: the png format is asked and the bytes are returned as a data URI", async (t) => {
  const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0x00, 0xfe]);
  const calls = fakeHttps(t, () => ({ statusCode: 200, statusMessage: "OK", body: png }));
  const client = new PveClient("pve01");
  client.responseType = ResponseType.PNG;

  const result = await client.get("/nodes/pve01/rrd", { ds: "cpu", timeframe: "day" });

  assert.match(calls[0].options.path, /^\/api2\/png\/nodes\/pve01\/rrd\?/);
  assert.equal(result.response, "data:image/png;base64," + png.toString("base64"));
  assert.equal(result.responseInError, false);
});

test("png: an error answer keeps its status and reason", async (t) => {
  fakeHttps(t, () => json(500, { data: null }, "no such data source"));
  const client = new PveClient("pve01");
  client.responseType = ResponseType.PNG;

  const result = await client.get("/nodes/pve01/rrd", { ds: "x", timeframe: "day" });

  assert.equal(result.statusCode, 500);
  assert.equal(result.reasonPhrase, "no such data source");
  assert.equal(result.isSuccessStatusCode, false);
});

test("png: login and task status are still read as json", async (t) => {
  const calls = fakeHttps(t, (options) =>
    options.path.includes("/access/ticket")
      ? json(200, { data: { ticket: "T", CSRFPreventionToken: "C" } })
      : json(200, { data: { status: "stopped", exitstatus: "OK" } })
  );
  const client = new PveClient("pve01");
  client.responseType = ResponseType.PNG;

  assert.equal(await client.login("root@pam", "pw"), true);
  assert.equal(await client.getExitStatusTask(UPID), "OK");
  assert.ok(calls.every((call) => call.options.path.startsWith("/api2/json/")));
  assert.equal(client.responseType, ResponseType.PNG);
});
