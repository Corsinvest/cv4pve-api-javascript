/*
 * SPDX-FileCopyrightText: Copyright Corsinvest Srl
 * SPDX-License-Identifier: MIT
 */

// Fake of https.request shared by the offline tests: no cluster is needed.

const https = require("https");
const { EventEmitter } = require("events");

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

/** A call as { method, path, query, body }: query as an object, body parsed or null. */
function sent(call) {
  const url = new URL(call.options.path, "https://pve01");
  return {
    method: call.options.method,
    path: url.pathname,
    query: Object.fromEntries(url.searchParams),
    body: call.body === "" ? null : JSON.parse(call.body),
  };
}

module.exports = { fakeHttps, json, sent };
