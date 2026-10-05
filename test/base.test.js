/*
 * SPDX-FileCopyrightText: Copyright Corsinvest Srl
 * SPDX-License-Identifier: MIT
 */

// Offline tests of the hand-written base (src/index.js): https.request is replaced by a fake,
// so no cluster is needed. Run with: npm test

const test = require("node:test");
const assert = require("node:assert/strict");
const { PveClient, PveResultException, ResponseType } = require("../src/index.js");
const { fakeHttps, json, sent } = require("./fake-https.js");

const UPID = "UPID:pve01:0012A3F4:05C1B2D3:6720F1A0:qmsnapshot:100:root@pam:";
const TICKET = { ticket: "PVE:root@pam:TICKET", CSRFPreventionToken: "CSRF", username: "root@pam" };
const NEED_TFA = { ticket: "PVE:!tfa!challenge", NeedTFA: 1, username: "root@pam" };

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

test("the debug log does not show the value of a new API token", async (t) => {
  let data = { "full-tokenid": "automation@pve!app", info: { privsep: 1 }, value: "SECRETVALUE" };
  fakeHttps(t, () => json(200, { data }));
  const client = new PveClient("pve01");
  const lines = captureLog(t, client);

  await client.create("/access/users/automation@pve/token/app");
  assert.ok(!lines.join("\n").includes("SECRETVALUE"), "the log shows the value of the token");
  assert.ok(lines.join("\n").includes("privsep"), "values that are not secret are still logged");

  // a member named value of any other answer is not a secret
  data = { key: "keyboard", value: "PLAINVALUE" };
  await client.get("/cluster/options");
  assert.ok(lines.join("\n").includes("PLAINVALUE"), "a value that is not a token is logged");
});

test("the debug log does not show the API token or the second factor", async (t) => {
  fakeHttps(t, (options, body, callNumber) => json(200, { data: callNumber === 1 ? NEED_TFA : TICKET }));
  const client = new PveClient("pve01");
  const lines = captureLog(t, client);

  assert.equal(await client.login("root@pam", "SECRETPASSWORD", "pam", "SECRETOTP"), true);
  client.apiToken = "root@pam!test=SECRETAPITOKEN";
  await client.get("/nodes/pve01/qemu/100/vncwebsocket", { port: 5900, vncticket: "SECRETQUERY" });

  const log = lines.join("\n");
  for (const secret of [
    "SECRETPASSWORD",
    "SECRETOTP",
    "SECRETAPITOKEN",
    "SECRETQUERY",
    NEED_TFA.ticket,
    TICKET.ticket,
  ]) {
    assert.ok(!log.includes(secret), `the log shows ${secret}`);
  }
  assert.ok(log.includes("5900"), "parameters that are not secret are still logged");
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

test("png: an error answer keeps its errors", async (t) => {
  fakeHttps(t, () => json(400, { data: null, errors: { ds: "invalid" } }, "Parameter verification failed."));
  const client = new PveClient("pve01");
  client.responseType = ResponseType.PNG;

  const result = await client.get("/nodes/pve01/rrd", { ds: "x", timeframe: "day" });

  assert.equal(result.statusCode, 400);
  assert.equal(result.responseInError, true);
  assert.equal(result.response.errors.ds, "invalid");
});

test("an error answer without errors is not in error for responseInError", async (t) => {
  fakeHttps(t, () => json(500, { data: null }, "Configuration file 'nodes/pve01/qemu-server/999999.conf' does not exist"));
  const client = new PveClient("pve01");

  const result = await client.get("/nodes/pve01/qemu/999999/config");

  assert.equal(result.isSuccessStatusCode, false);
  assert.match(result.reasonPhrase, /does not exist/);
  assert.equal(result.responseInError, false);
});

test("an error status with a body that is not JSON keeps its status", async (t) => {
  fakeHttps(t, () => ({ statusCode: 502, statusMessage: "Bad Gateway", body: "<html>Bad Gateway</html>" }));
  const client = new PveClient("pve01");

  const result = await client.get("/version");

  assert.equal(result.statusCode, 502);
  assert.equal(result.isSuccessStatusCode, false);
  assert.equal(result.response, null);
  assert.equal(result.reasonPhrase, "The answer is not JSON (HTTP 502): <html>Bad Gateway</html>");
});

test("the timeout of the client is the timeout of the request", async (t) => {
  const calls = fakeHttps(t, () => json(200, { data: {} }));
  const client = new PveClient("pve01");

  await client.get("/version");
  assert.equal(calls[0].options.timeout, 30000);

  client.timeout = 5000;
  await client.get("/version");
  assert.equal(calls[1].options.timeout, 5000);
});

test("a timeout that is negative or not a number is refused", () => {
  const client = new PveClient("pve01");

  for (const timeout of [-1, NaN, Infinity, "1000", null, undefined]) {
    assert.throws(() => (client.timeout = timeout), RangeError);
  }
  assert.equal(client.timeout, 30000);

  client.timeout = 1500;
  assert.equal(client.timeout, 1500);
  client.timeout = 0;
  assert.equal(client.timeout, 0);
});

test("parameters that cannot be encoded are refused, not sent changed", async (t) => {
  const calls = fakeHttps(t, () => json(200, { data: null }));
  const client = new PveClient("pve01");
  const circular = {};
  circular.self = circular;

  for (const method of ["set", "create"]) {
    for (const value of [circular, 10n]) {
      await assert.rejects(
        () => client[method]("/nodes/pve01/qemu/100/config", { description: value }),
        (error) => error instanceof TypeError && /cannot be encoded as JSON/.test(error.message)
      );
    }
  }

  // JSON would drop these or send null in their place
  for (const method of ["get", "delete", "set", "create"]) {
    for (const value of [NaN, Infinity, () => 1, Symbol("x")]) {
      await assert.rejects(
        () => client[method]("/nodes/pve01/qemu/100/config", { memory: value }),
        (error) => error instanceof TypeError && /Parameter 'memory' cannot be encoded/.test(error.message)
      );
    }
  }

  assert.equal(calls.length, 0, "requests sent");
});

test("a value that cannot be encoded is refused also inside an array or an object", async (t) => {
  const calls = fakeHttps(t, () => json(200, { data: null }));
  const client = new PveClient("pve01");
  const circular = { list: [] };
  circular.list.push(circular);

  for (const method of ["get", "delete", "set", "create"]) {
    for (const value of [{ size: NaN }, [1, Infinity], { deep: [{ fn: () => 1 }] }]) {
      await assert.rejects(
        () => client[method]("/nodes/pve01/qemu/100/config", { memory: value }),
        (error) => error instanceof TypeError && /Parameter 'memory' cannot be encoded/.test(error.message)
      );
    }
    await assert.rejects(
      () => client[method]("/nodes/pve01/qemu/100/config", { memory: circular }),
      (error) => error instanceof TypeError && /cannot be encoded as JSON: circular/.test(error.message)
    );
  }
  assert.equal(calls.length, 0, "requests sent");

  // the same object twice is not a circular reference; a Date is encoded by JSON
  const shared = { a: 1 };
  await client.create("/nodes/pve01/execute", { commands: [shared, shared], when: new Date(0) });
  assert.deepEqual(sent(calls[0]).body, {
    commands: [{ a: 1 }, { a: 1 }],
    when: "1970-01-01T00:00:00.000Z",
  });
});

test("the log is off unless asked, also for the error of a request", async (t) => {
  fakeHttps(t, () => Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" }));
  const debug = require("debug");
  const lines = [];
  const original = debug.log;
  debug.log = (...args) => lines.push(require("util").format(...args));
  t.after(() => (debug.log = original));
  const client = new PveClient("pve01");

  assert.equal(client.logEnabled, false);
  await assert.rejects(() => client.get("/version"));
  assert.equal(lines.length, 0, "an error was logged with the log off");

  client.logEnabled = true;
  assert.equal(client.logEnabled, true);
  await assert.rejects(() => client.get("/version"));
  assert.ok(lines.join("\n").includes("ECONNREFUSED"), "the error is not logged with the log on");

  client.logEnabled = false;
  assert.equal(client.logEnabled, false);
});

test("the node is read from the task identifier", () => {
  assert.equal(PveClient.getNodeFromTask(UPID), "pve01");
  assert.equal(PveClient.getNodeFromTask("UPID:cc01:0012A3F4:05C1B2D3:6720F1A0:qmstart:100:root@pam:"), "cc01");

  for (const task of [null, undefined, "", "abc", 100, "UPID:"]) {
    assert.throws(
      () => PveClient.getNodeFromTask(task),
      (error) => error instanceof PveResultException && /not a valid task/.test(error.message)
    );
  }
});

test("error of a result lists the refused parameters, one per line", async (t) => {
  let answer = json(
    400,
    { data: null, errors: { vmid: "invalid format - value does not look like a valid VM ID\n", name: "too long" } },
    "Parameter verification failed."
  );
  fakeHttps(t, () => answer);
  const client = new PveClient("pve01");

  let result = await client.get("/nodes/pve01/qemu/abc/config");
  assert.equal(result.responseInError, true);
  assert.equal(
    result.error,
    "vmid : invalid format - value does not look like a valid VM ID\nname : too long"
  );

  // without errors, and without an answer, the text is empty
  answer = json(500, { data: null }, "does not exist");
  result = await client.get("/nodes/pve01/qemu/999999/config");
  assert.equal(result.error, "");

  answer = { statusCode: 401, statusMessage: "authentication failure", body: "" };
  result = await client.get("/version");
  assert.equal(result.error, "");
});

test("get and delete send the parameters in the query string", async (t) => {
  const calls = fakeHttps(t, () => json(200, { data: {} }));
  const client = new PveClient("pve01");
  const parameters = { type: "vm", full: true, quiet: false, skipped: null, missing: undefined };

  await client.get("/nodes", parameters);
  assert.deepEqual(sent(calls[0]), {
    method: "GET",
    path: "/api2/json/nodes",
    query: { type: "vm", full: "1", quiet: "0" },
    body: null,
  });

  await client.delete("/nodes/pve01/qemu/100/snapshot/snap1", parameters);
  assert.equal(sent(calls[1]).method, "DELETE");
  assert.deepEqual(sent(calls[1]).query, { type: "vm", full: "1", quiet: "0" });
  assert.equal(sent(calls[1]).body, null);
});

test("a get without parameters has no query string", async (t) => {
  const calls = fakeHttps(t, () => json(200, { data: {} }));
  const client = new PveClient("pve01");

  await client.get("/version");
  await client.get("/version", null);

  assert.equal(calls[0].options.path, "/api2/json/version");
  assert.equal(calls[1].options.path, "/api2/json/version");
});

test("create and set send the parameters as a JSON body", async (t) => {
  const calls = fakeHttps(t, () => json(200, { data: {} }));
  const client = new PveClient("pve01");

  await client.create("/nodes/pve01/qemu", { vmid: 100, name: "àèì", start: true, pool: null });
  assert.equal(sent(calls[0]).method, "POST");
  assert.equal(calls[0].options.path, "/api2/json/nodes/pve01/qemu");
  assert.deepEqual(sent(calls[0]).body, { vmid: 100, name: "àèì", start: 1 });
  assert.equal(calls[0].options.headers["Content-Type"], "application/json");
  assert.equal(calls[0].options.headers["Content-Length"], Buffer.byteLength(calls[0].body));

  await client.set("/nodes/pve01/qemu/100/config", { memory: 2048 });
  assert.equal(sent(calls[1]).method, "PUT");
  assert.deepEqual(sent(calls[1]).body, { memory: 2048 });
});

test("the request goes to the host and the port of the client", async (t) => {
  const calls = fakeHttps(t, () => json(200, { data: {} }));

  await new PveClient("pve01").get("/version");
  assert.equal(calls[0].options.host, "pve01");
  assert.equal(calls[0].options.port, 8006);

  await new PveClient("pve.local", 443).get("/version");
  assert.equal(calls[1].options.host, "pve.local");
  assert.equal(calls[1].options.port, 443);
});

test("the API token is sent in the Authorization header", async (t) => {
  const calls = fakeHttps(t, () => json(200, { data: {} }));
  const client = new PveClient("pve01");
  client.apiToken = "root@pam!test=11111111-2222-3333-4444-555555555555";

  await client.get("/version");

  const headers = calls[0].options.headers;
  assert.equal(
    headers.Authorization,
    "PVEAPIToken=root@pam!test=11111111-2222-3333-4444-555555555555"
  );
  assert.equal(headers.Cookie, undefined);
  assert.equal(headers.CSRFPreventionToken, undefined);
});

test("a success answer becomes a result", async (t) => {
  fakeHttps(t, () => json(200, { data: { version: "9.2.1", release: "9.2" } }));
  const client = new PveClient("pve01");

  const result = await client.get("/version", { verbose: true });

  assert.equal(result.isSuccessStatusCode, true);
  assert.equal(result.statusCode, 200);
  assert.equal(result.reasonPhrase, "OK");
  assert.equal(result.response.data.version, "9.2.1");
  assert.equal(result.responseInError, false);
  assert.equal(result.requestResource, "/version");
  assert.deepEqual(result.requestParameters, { verbose: 1 });
  assert.equal(result.responseType, ResponseType.JSON);
  assert.equal(client.lastResult, result);
});

test("toString of a result does not show the secrets of the parameters", async (t) => {
  fakeHttps(t, () => json(200, { data: {} }));
  const client = new PveClient("pve01");

  const result = await client.create("/access/users", { userid: "u@pve", password: "SECRET" });

  assert.ok(!result.toString().includes("SECRET"), result.toString());
  assert.ok(result.toString().includes("u@pve"), result.toString());
});

test("login asks the ticket and uses it in the next requests", async (t) => {
  const calls = fakeHttps(t, (options) =>
    options.path.startsWith("/api2/json/access/ticket")
      ? json(200, { data: TICKET })
      : json(200, { data: {} })
  );
  const client = new PveClient("pve01");

  assert.equal(await client.login("root", "pw"), true);
  assert.equal(sent(calls[0]).method, "POST");
  assert.equal(sent(calls[0]).path, "/api2/json/access/ticket");

  await client.create("/nodes/pve01/qemu", { vmid: 100 });
  assert.equal(calls[1].options.headers.Cookie, "PVEAuthCookie=PVE:root@pam:TICKET");
  assert.equal(calls[1].options.headers.CSRFPreventionToken, "CSRF");
});

test("login: the realm is what follows the last @", async (t) => {
  const calls = fakeHttps(t, () => json(200, { data: TICKET }));
  const client = new PveClient("pve01");

  await client.login("user@example.com@ldap", "pw");

  assert.deepEqual(sent(calls[0]).body, {
    password: "pw",
    username: "user@example.com",
    realm: "ldap",
  });
});

test("login: a second factor asked without a code throws", async (t) => {
  const calls = fakeHttps(t, () => json(200, { data: NEED_TFA }));
  const client = new PveClient("pve01");

  for (const otp of [undefined, null, "", "  "]) {
    await assert.rejects(
      () => client.login("root@pam", "pw", "pam", otp),
      (error) =>
        error instanceof PveResultException &&
        /missing Two Factor Authentication/.test(error.message) &&
        error.result.statusCode === 200
    );
  }
  assert.equal(calls.length, 4, "the challenge is not answered without a code");

  await client.get("/version");
  assert.equal(calls[4].options.headers.Cookie, undefined, "the challenge is not a ticket");
});

test("login: the second factor is sent in a second call with the challenge", async (t) => {
  const calls = fakeHttps(t, (options, body, callNumber) =>
    json(200, { data: callNumber === 1 ? NEED_TFA : TICKET })
  );
  const client = new PveClient("pve01");

  assert.equal(await client.login("root@pam", "pw", "pam", "123456"), true);

  assert.equal(calls.length, 2);
  assert.deepEqual(sent(calls[0]).body, { password: "pw", username: "root", realm: "pam" });
  assert.deepEqual(sent(calls[1]).body, {
    password: "totp:123456",
    username: "root",
    realm: "pam",
    "tfa-challenge": "PVE:!tfa!challenge",
  });

  await client.get("/version");
  assert.equal(calls[2].options.headers.Cookie, "PVEAuthCookie=PVE:root@pam:TICKET");
});

test("login: a second factor with a type is sent as it is", async (t) => {
  const calls = fakeHttps(t, (options, body, callNumber) =>
    json(200, { data: callNumber === 1 ? NEED_TFA : TICKET })
  );
  const client = new PveClient("pve01");

  assert.equal(await client.login("root@pam", "pw", "pam", "recovery:abcd-1234"), true);

  assert.equal(sent(calls[1]).body.password, "recovery:abcd-1234");
});

test("login: a second factor that is rejected returns false", async (t) => {
  const calls = fakeHttps(t, (options, body, callNumber) =>
    callNumber === 1
      ? json(200, { data: NEED_TFA })
      : json(401, { data: null }, "authentication failure")
  );
  const client = new PveClient("pve01");

  assert.equal(await client.login("root@pam", "pw", "pam", "000000"), false);
  assert.equal(client.lastResult.statusCode, 401);

  await client.get("/version");
  assert.equal(calls[2].options.headers.Cookie, undefined);
});

test("the status of a task is read from the node of the task", async (t) => {
  const calls = fakeHttps(t, () => json(200, { data: { status: "running" } }));
  const client = new PveClient("pve01");

  const result = await client.readTaskStatus(UPID);

  assert.equal(sent(calls[0]).method, "GET");
  assert.equal(calls[0].options.path, `/api2/json/nodes/pve01/tasks/${UPID}/status`);
  assert.equal(result.response.data.status, "running");
});

test("the exit status of a failed task is its error", async (t) => {
  const exitstatus = "command 'qm' failed: exit code 255";
  fakeHttps(t, () => json(200, { data: { status: "stopped", exitstatus } }));
  const client = new PveClient("pve01");

  assert.equal(await client.getExitStatusTask(UPID), exitstatus);
});

test("wait for a task checks until it stops", async (t) => {
  const calls = fakeHttps(t, (options, body, callNumber) =>
    json(200, {
      data: callNumber < 3 ? { status: "running" } : { status: "stopped", exitstatus: "OK" },
    })
  );
  const client = new PveClient("pve01");

  assert.equal(await client.waitForTaskToFinish(UPID, 5, 1000), true);
  assert.equal(calls.length, 3);
});

test("a task status that cannot be read throws with the HTTP status", async (t) => {
  let answer = json(500, { data: null, errors: { upid: "no such task" } }, "Internal Server Error");
  fakeHttps(t, () => answer);
  const client = new PveClient("pve01");

  await assert.rejects(
    () => client.taskIsRunning(UPID),
    (error) =>
      error instanceof PveResultException &&
      error.result.statusCode === 500 &&
      error.message.startsWith(`Read status of task '${UPID}' failed (500 Internal Server Error)`) &&
      error.message.includes("no such task")
  );

  answer = { statusCode: 403, statusMessage: "Permission check failed", body: "" };
  await assert.rejects(
    () => client.getExitStatusTask(UPID),
    (error) =>
      error instanceof PveResultException && /\(403 Permission check failed\)/.test(error.message)
  );

  answer = json(200, { data: null });
  await assert.rejects(
    () => client.taskIsRunning(UPID),
    (error) => error instanceof PveResultException && /does not contain 'data'/.test(error.message)
  );
});

test("wait for a task stops when the status cannot be read", async (t) => {
  const calls = fakeHttps(t, (options, body, callNumber) =>
    callNumber === 1
      ? json(200, { data: { status: "running" } })
      : json(500, { data: null }, "node down")
  );
  const client = new PveClient("pve01");

  await assert.rejects(() => client.waitForTaskToFinish(UPID, 5, 1000), PveResultException);
  assert.equal(calls.length, 2);
});
