/*
 * SPDX-FileCopyrightText: Copyright Corsinvest Srl
 * SPDX-License-Identifier: MIT
 */

//@ts-check

/**
 * Result
 */
class Result {
  /**
   *
   * @param {any} response Parsed answer (object), data URI (png) or null
   * @param {number} statusCode
   * @param {string} reasonPhrase
   * @param {string} requestResource
   * @param {object} requestParameters
   * @param {string} methodType
   * @param {string} responseType
   */
  constructor(
    response,
    statusCode,
    reasonPhrase,
    requestResource,
    requestParameters,
    methodType,
    responseType
  ) {
    this.#response = response;
    this.#statusCode = statusCode;
    this.#reasonPhrase = reasonPhrase;
    this.#requestResource = requestResource;
    this.#requestParameters = requestParameters;
    this.#methodType = methodType;
    this.#responseType = responseType;
  }

  #response = null;
  /**
   * Get response
   */
  get response() {
    return this.#response;
  }

  #statusCode = 0;
  /**
   *  Get status code
   */
  get statusCode() {
    return this.#statusCode;
  }

  #reasonPhrase = "";
  /**
   * Get reason phrase
   */
  get reasonPhrase() {
    return this.#reasonPhrase;
  }

  #requestResource = "";
  /**
   * Get request resource
   */
  get requestResource() {
    return this.#requestResource;
  }

  #requestParameters = null;
  /**
   * Get request parameters
   */
  get requestParameters() {
    return this.#requestParameters;
  }

  #methodType = "";
  /**
   * Get method type
   */
  get methodType() {
    return this.#methodType;
  }

  #responseType = "";
  /**
   * Get response type
   */
  get responseType() {
    return this.#responseType;
  }

  /**
   * Is success code
   */
  get isSuccessStatusCode() {
    return this.#statusCode === 200;
  }

  /**
   * Get if response Proxmox VE contain errors
   */
  get responseInError() {
    return (
      this.#response !== null &&
      typeof this.#response === "object" &&
      typeof this.#response.errors !== "undefined"
    );
  }

  /**
   * Get the parameters refused by Proxmox VE, one per line as 'name : message'.
   * Empty string when the response has no errors.
   * @returns {string}
   */
  get error() {
    if (!this.responseInError) {
      return "";
    }
    const errors = this.#response.errors;
    if (errors === null || typeof errors !== "object") {
      return "";
    }
    return Object.entries(errors)
      .map(([name, message]) => `${name} : ${String(message).trim()}`)
      .join("\n");
  }

  /**
   * Mask sensitive parameter values (password, token, ticket, otp, apitoken)
   * for safe logging. Returns a shallow copy; does not mutate the original.
   *
   * @param {object|null} parameters
   * @returns {object|null}
   */
  static maskSensitiveParameters(parameters) {
    if (parameters === null || typeof parameters !== "object") {
      return parameters;
    }
    const sensitiveParams = ["password", "token", "ticket", "otp", "apitoken", "tfa-challenge"];
    /** @type {Object<string, any>} */
    const masked = {};
    for (const [key, value] of Object.entries(parameters)) {
      const paramName = key.toLowerCase();
      masked[key] = sensitiveParams.some((p) => paramName.includes(p)) ? "****" : value;
    }
    return masked;
  }

  /**
   * ToString
   *
   * @returns info class
   */
  toString() {
    return [
      "Is Success Status Code: " + this.isSuccessStatusCode,
      "Status Code: " + this.#statusCode,
      "Reason Phrase: " + this.#reasonPhrase,
      "Request Resource: " + this.#requestResource,
      "Method Type: " + this.#methodType,
      "Response Type: " + this.#responseType,
      "Response In Error: " + this.responseInError,
      "Request Parameters: " +
        JSON.stringify(Result.maskSensitiveParameters(this.#requestParameters)),
    ].join("\n");
  }
}

/**
 * Response type
 */
/**
 * Call to the Proxmox VE API that did not return the expected result,
 * e.g. the status of a task that cannot be read.
 */
class PveResultException extends Error {
  /**
   * @param {Result|null} result Result of the call
   * @param {string} message
   */
  constructor(result, message) {
    super(message);
    this.name = "PveResultException";
    this.result = result;
  }
}

class ResponseType {
  static JSON = "json";
  static PNG = "png";
}

/**
 * Proxmox VE Client Api Base
 */
class PveClientBase {
  /**
   * Constructor
   *
   * @param {string} hostname
   * @param {number} port
   */
  constructor(hostname, port = 8006) {
    this.#hostname = hostname;
    this.#port = port;
  }

  // @ts-ignore
  #http = require("https");
  // @ts-ignore
  #debug = require("debug");
  #log = this.#debug("proxmox-ve:debug");
  #error = this.#debug("proxmox-ve:error");

  #ticketCSRFPreventionToken = "";
  #ticketPVEAuthCookie = "";

  #hostname = "";
  /**
   * Get host name
   */
  get hostname() {
    return this.#hostname;
  }

  #port = 8006;
  /**
   * Get port
   */
  get port() {
    return this.#port;
  }

  #responseType = ResponseType.JSON;
  /**
   * Get response type
   */
  get responseType() {
    return this.#responseType;
  }
  /**
   * Set response type
   */
  set responseType(value) {
    this.#responseType = value;
  }

  #lastResult = new Result("", 0, "", "", "", "", "");
  /**
   * Get last result
   */
  get lastResult() {
    return this.#lastResult;
  }

  #apiToken = "";
  /**
   * Get Api token
   */
  get apiToken() {
    return this.#apiToken;
  }
  /**
   * Set Api token
   */
  set apiToken(value) {
    this.#apiToken = value;
  }

  #timeout = 30000;
  /**
   * Get timeout in milliseconds
   */
  get timeout() {
    return this.#timeout;
  }
  /**
   * Set timeout in milliseconds, 0 for no limit
   * @throws {RangeError} The timeout is not a number or is negative.
   */
  set timeout(value) {
    if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
      throw new RangeError("timeout must be a number of milliseconds, not negative");
    }
    this.#timeout = value;
  }

  #validateCertificate = false;
  /**
   * Get if the certificate of the node is validated (default false: a new
   * Proxmox VE installation has a self-signed certificate)
   */
  get validateCertificate() {
    return this.#validateCertificate;
  }
  /**
   * Set if the certificate of the node is validated
   */
  set validateCertificate(value) {
    this.#validateCertificate = value === true;
  }

  /**
   * Get if the log is enabled (default false). The log is written with the
   * 'debug' package: 'proxmox-ve:debug' for requests and answers,
   * 'proxmox-ve:error' for the errors of a request.
   * @returns {boolean}
   */
  get logEnabled() {
    return this.#log.enabled === true;
  }
  /**
   * Set if the log is enabled
   */
  set logEnabled(value) {
    this.#log.enabled = value;
    this.#error.enabled = value;
  }

  /**
   * Mask sensitive HTTP headers (authentication ticket and API token)
   * for safe logging. Returns a shallow copy; does not mutate the original.
   *
   * @param {Object<string, any>} headers
   * @returns {Object<string, any>}
   */
  static #maskSensitiveHeaders(headers) {
    const sensitiveHeaders = ["cookie", "authorization", "csrfpreventiontoken"];
    /** @type {Object<string, any>} */
    const masked = {};
    for (const [key, value] of Object.entries(headers)) {
      masked[key] = sensitiveHeaders.includes(key.toLowerCase()) ? "****" : value;
    }
    return masked;
  }

  /**
   * Copy of an answer for the log, without the secrets it carries: the ticket and
   * the CSRF token of a login, the value of a new API token.
   *
   * @param {any} response
   * @param {string} resource
   * @returns {any}
   */
  static #maskSensitiveResponse(response, resource) {
    if (response === null || typeof response !== "object") {
      return response;
    }
    const data = response.data;
    if (data === null || typeof data !== "object" || Array.isArray(data)) {
      return response;
    }
    const masked = Result.maskSensitiveParameters(data);
    if (resource.includes("/token") && "value" in masked) {
      masked.value = "****";
    }
    return { ...response, data: masked };
  }

  /**
   * Status and reason for a body that is not JSON (a proxy page, another service
   * on that port): the HTTP status is kept (a success becomes 502, since the answer
   * cannot be used) and the reason shows the start of the body.
   *
   * @param {number} statusCode
   * @param {string} body
   * @returns {{statusCode: number, reasonPhrase: string}}
   */
  static #notJsonAnswer(statusCode, body) {
    const start = (body.length > 100 ? body.substring(0, 100) + "…" : body)
      .replace(/\r\n|\r|\n/g, " ")
      .trim();
    return {
      statusCode: statusCode >= 200 && statusCode <= 299 ? 502 : statusCode,
      reasonPhrase: `The answer is not JSON (HTTP ${statusCode}): ${start}`,
    };
  }

  /**
   * Refuse a value that JSON would drop or send as null (NaN, Infinity, a function,
   * a Symbol), also inside an array or an object, and a circular reference.
   *
   * @param {string} name Name of the parameter
   * @param {any} value
   * @param {any[]} parents Arrays and objects that contain the value
   * @throws {TypeError} The value cannot be encoded.
   */
  static #ensureEncodable(name, value, parents) {
    if (
      typeof value === "function" ||
      typeof value === "symbol" ||
      (typeof value === "number" && !Number.isFinite(value))
    ) {
      throw new TypeError(
        `Parameter '${name}' cannot be encoded: ${typeof value === "number" ? value : typeof value}`
      );
    }

    if (value === null || typeof value !== "object") {
      return;
    }
    // only what JSON reads member by member: an array or a plain object
    const prototype = Object.getPrototypeOf(value);
    if (!Array.isArray(value) && prototype !== Object.prototype && prototype !== null) {
      return;
    }
    if (parents.includes(value)) {
      throw new TypeError(
        `Parameters cannot be encoded as JSON: circular reference in parameter '${name}'`
      );
    }
    parents.push(value);
    for (const member of Object.values(value)) {
      PveClientBase.#ensureEncodable(name, member, parents);
    }
    parents.pop();
  }

  /**
   * Parameters as the JSON body of a request.
   *
   * @param {object} parameters
   * @returns {string}
   * @throws {TypeError} A value cannot be encoded (e.g. a circular reference, a BigInt).
   */
  static #encodeParameters(parameters) {
    try {
      return JSON.stringify(parameters);
    } catch (error) {
      // @ts-ignore
      throw new TypeError("Parameters cannot be encoded as JSON: " + error.message);
    }
  }

  /**
   * Execute request and return response
   *
   * @param {string} method
   * @param {string} resource
   * @param {any} parameters
   * @param {string} responseType Format asked to Proxmox VE: the one of the client unless given
   * @returns {Promise<Result>} An HTTP answer, also an error one, resolves with its Result.
   * A request that gets no answer (connection refused, name not resolved, certificate refused,
   * timeout) rejects with the error of Node; a timeout has code ETIMEDOUT.
   * Parameters that cannot be encoded reject with a TypeError and no request is sent.
   */
  async #execute(method, resource, parameters, responseType = this.#responseType) {
    const ref = this;

    if (parameters === null || parameters === undefined) {
      parameters = {};
    }

    let tmpParameters = {};
    for (const [key, value] of Object.entries(parameters)) {
      if (value !== null && value !== undefined) {
        if (typeof value === "boolean") {
          tmpParameters[key] = value ? 1 : 0;
        } else {
          PveClientBase.#ensureEncodable(key, value, []);
          tmpParameters[key] = value;
        }
      }
    }
    parameters = tmpParameters;

    let body = "";
    let headers = {};
    const path = "/api2/" + responseType + resource;
    let url = path;

    if (method === "GET" || method === "DELETE") {
      const urlParams = new URLSearchParams(parameters).toString();
      if (urlParams.length > 0) {
        url += "?" + urlParams;
      }
    } else {
      body = PveClientBase.#encodeParameters(parameters);
      headers["Content-Type"] = "application/json";
      // @ts-ignore
      headers["Content-Length"] = Buffer.byteLength(body);
    }

    if (this.#ticketCSRFPreventionToken !== "") {
      headers["CSRFPreventionToken"] = this.#ticketCSRFPreventionToken;
      headers["Cookie"] = "PVEAuthCookie=" + this.#ticketPVEAuthCookie;
    }

    if (this.apiToken !== "") {
      headers["Authorization"] = "PVEAPIToken=" + this.apiToken;
    }

    const options = {
      rejectUnauthorized: this.#validateCertificate,
      host: this.hostname,
      port: this.port,
      path: url,
      method: method,
      headers: headers,
      timeout: this.#timeout,
    };

    //debug: log a sanitized copy, masking sensitive parameters and headers;
    //the path without the query string, which repeats the parameters unmasked
    if (this.#log.enabled) {
      this.#log({
        ...options,
        path: path,
        headers: PveClientBase.#maskSensitiveHeaders(headers),
        parameters: Result.maskSensitiveParameters(parameters),
      });
    }

    return new Promise((resolve, reject) => {
      // @ts-ignore
      let req = this.#http.request(options, (response) => {
        /** @type {any[]} */
        const chunks = [];

        response.on("data", (chunk) => {
          // @ts-ignore
          chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        });

        response.on("end", () => {
          // @ts-ignore
          const body = Buffer.concat(chunks);
          let statusCode = response.statusCode;
          let reasonPhrase = response.statusMessage;
          let data = null;

          if (responseType === ResponseType.PNG && statusCode === 200) {
            data = "data:image/png;base64," + body.toString("base64");
          } else {
            // json, or the error answer of a png request
            const text = body.toString("utf8");
            if (text.trim() !== "") {
              try {
                data = JSON.parse(text);
              } catch (error) {
                // not an answer of the API: keep the HTTP status, show the start of the body
                this.#error(error);
                ({ statusCode, reasonPhrase } = PveClientBase.#notJsonAnswer(statusCode, text));
              }
            }
          }

          const result = new Result(
            data,
            statusCode,
            reasonPhrase,
            resource,
            parameters,
            method,
            responseType
          );

          ref.#lastResult = result;

          //debug
          if (this.#log.enabled) {
            this.#log(result.toString());
            this.#log(PveClientBase.#maskSensitiveResponse(result.response, resource));
          }

          resolve(result);
        });

        response.on("error", (error) => {
          this.#error(error);
          reject(error);
        });
      });

      req.on("error", (error) => {
        this.#error(error);
        reject(error);
      });

      req.on("timeout", () => {
        req.destroy();
        const error = new Error(`Request timeout after ${this.#timeout}ms`);
        // @ts-ignore
        error.code = "ETIMEDOUT";
        this.#error(error);
        reject(error);
      });

      if (body !== "") {
        req.write(body);
      }
      req.end();
    });
  }

  /**
   * Login
   *
   * @param {string} username User name, or user@realm
   * @param {string} password
   * @param {string} realm pam/pve or custom; ignored when username is user@realm
   * @param {string} otp Second factor of a user with two-factor authentication:
   * a TOTP code (e.g. 123456) or 'type:value' (e.g. recovery:abcd-1234).
   * @returns {Promise<boolean>} True when Proxmox VE gave a ticket; when false the
   * reason is in lastResult.
   * @throws {PveResultException} The user needs a second factor and otp is missing.
   */
  async login(username, password, realm = "pam", otp = null) {
    // user@realm: the realm is what follows the last @
    const at = String(username).lastIndexOf("@");
    if (at > 0) {
      realm = String(username).substring(at + 1);
      username = String(username).substring(0, at);
    }

    // a new login does not send, and on failure does not keep, the ticket of the previous one
    this.#ticketCSRFPreventionToken = "";
    this.#ticketPVEAuthCookie = "";

    let result = await this.#execute(
      "POST",
      "/access/ticket",
      { password: password, username: username, realm: realm },
      ResponseType.JSON
    );

    if (result.isSuccessStatusCode && result.response?.data?.NeedTFA) {
      if (otp === null || otp === undefined || String(otp).trim() === "") {
        throw new PveResultException(
          result,
          "Couldn't authenticate user: missing Two Factor Authentication (TFA)"
        );
      }

      // second step: the response to the challenge of the first one
      result = await this.#execute(
        "POST",
        "/access/ticket",
        {
          password: PveClientBase.#getTfaResponse(String(otp)),
          username: username,
          realm: realm,
          "tfa-challenge": result.response.data.ticket,
        },
        ResponseType.JSON
      );
    }

    const data = result.isSuccessStatusCode ? result.response?.data : null;
    if (!data || !data.ticket || !data.CSRFPreventionToken) {
      return false;
    }

    this.#ticketCSRFPreventionToken = data.CSRFPreventionToken;
    this.#ticketPVEAuthCookie = data.ticket;
    return true;
  }

  /**
   * Second factor as Proxmox VE expects it in the response to a TFA challenge:
   * 'type:value'. A code without a type is a TOTP code.
   * @param {string} otp
   * @returns {string}
   */
  static #getTfaResponse(otp) {
    return otp.includes(":") ? otp : "totp:" + otp;
  }

  /**
   * Get
   *
   * @param {string} resource
   * @param {object} parameters
   * @returns {Promise<Result>}
   */
  async get(resource, parameters = {}) {
    return this.#execute("GET", resource, parameters);
  }

  /**
   * Set
   *
   * @param {string} resource
   * @param {object} parameters
   * @returns {Promise<Result>}
   */
  async set(resource, parameters = {}) {
    return this.#execute("PUT", resource, parameters);
  }

  /**
   * Create
   *
   * @param {string} resource
   * @param {object} parameters
   * @returns {Promise<Result>}
   */
  async create(resource, parameters = {}) {
    return this.#execute("POST", resource, parameters);
  }

  /**
   * Delete
   *
   * @param {string} resource
   * @param {object} parameters
   * @returns {Promise<Result>}
   */
  async delete(resource, parameters = {}) {
    return this.#execute("DELETE", resource, parameters);
  }

  /**
   * Get node from task
   *
   * @param {string} task Task identifier (UPID)
   * @return {string} Node of the task
   * @throws {PveResultException} The task identifier is not valid.
   */
  static getNodeFromTask(task) {
    if (typeof task !== "string" || !/^UPID:[^:]+:/.test(task)) {
      throw new PveResultException(null, `'${task}' is not a valid task identifier (UPID)`);
    }
    return task.split(":")[1];
  }

  /**
   * Wait for task to finish
   *
   * @param {string} task Task identifier
   * @param {number} wait Millisecond wait next check
   * @param {number} timeOut Millisecond timeout
   * @return {Promise<boolean>} True when the task is finished, false when it is still running at the timeout.
   * @throws {PveResultException} The status of the task cannot be read.
   */
  async waitForTaskToFinish(task, wait = 500, timeOut = 10000) {
    if (wait <= 0) {
      wait = 500;
    }
    if (timeOut < wait) {
      timeOut = wait + 5000;
    }

    // one check at a time: the next one starts after the previous one has answered
    const timeStart = Date.now();
    let isRunning = true;
    while (isRunning && Date.now() - timeStart < timeOut) {
      await new Promise((resolve) => setTimeout(resolve, wait));
      isRunning = await this.taskIsRunning(task);
    }

    // finished, also when the last check came after the timeout
    return !isRunning;
  }

  /**
   * Task is running
   *
   * @param {string} task Task identifier
   * @returns {Promise<boolean>}
   * @throws {PveResultException} The status of the task cannot be read.
   */
  async taskIsRunning(task) {
    return (
      PveClientBase.#ensureTaskStatus(await this.readTaskStatus(task), task).status === "running"
    );
  }

  /**
   * Get exit status of a task.
   *
   * @param {string} task Task identifier
   * @returns {Promise<string|null>} 'OK', 'WARNINGS: n' or the error; null while the task is running.
   * @throws {PveResultException} The status of the task cannot be read.
   */
  async getExitStatusTask(task) {
    const data = PveClientBase.#ensureTaskStatus(await this.readTaskStatus(task), task);
    return data.exitstatus ?? null;
  }

  /**
   * Read task status.
   *
   * @param {string} task
   * @returns {Promise<Result>}
   * @throws {PveResultException} The task identifier is not valid.
   */
  async readTaskStatus(task) {
    return this.#execute(
      "GET",
      "/nodes/" + PveClientBase.getNodeFromTask(task) + "/tasks/" + task + "/status",
      {},
      ResponseType.JSON
    );
  }

  /**
   * Data of a task status result, checked before it is read, so that an API
   * failure (node down, missing privilege) is reported with the HTTP status and
   * the Proxmox VE error instead of a TypeError.
   *
   * @param {Result} result Result of the status read
   * @param {string} task Task identifier
   * @returns {any} Data of the task status
   * @throws {PveResultException} The status of the task cannot be read.
   */
  static #ensureTaskStatus(result, task) {
    if (!result) {
      throw new PveResultException(null, `Read status of task '${task}' returned no result`);
    }

    const response = result.response;
    const inError = response !== null && typeof response === "object" && result.responseInError;
    const data = response !== null && typeof response === "object" ? response.data : undefined;
    if (inError || !result.isSuccessStatusCode || data === null || typeof data !== "object") {
      const detail = inError
        ? JSON.stringify(response.errors)
        : !result.isSuccessStatusCode
          ? result.reasonPhrase
          : "response does not contain 'data'";

      throw new PveResultException(
        result,
        `Read status of task '${task}' failed (${result.statusCode} ${result.reasonPhrase}): ${detail}`
      );
    }

    return data;
  }
}

// Export base classes first so that api-autogenerated.js (which requires this
// module to extend PveClientBase) sees them populated despite the circular require.
module.exports = { PveClientBase, Result, ResponseType, PveResultException };

const { PveClient } = require("./api-autogenerated.js");
module.exports.PveClient = PveClient;
