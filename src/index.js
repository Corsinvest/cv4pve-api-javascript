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
   * @param {string} response
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
    return typeof this.#response.errors !== "undefined";
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
    const sensitiveParams = ["password", "token", "ticket", "otp", "apitoken"];
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
    this.#error.enabled = true;
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
   * Set timeout in milliseconds
   */
  set timeout(value) {
    this.#timeout = value;
  }

  /**
   * Log enabled
   */
  get logEnabled() {
    return this.#log.enabled;
  }
  /**
   * Set Api token
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
   * Execute request and return response
   *
   * @param {string} method
   * @param {string} resource
   * @param {any} parameters
   * @returns {Promise<Result>}
   */
  async #execute(method, resource, parameters) {
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
          tmpParameters[key] = value;
        }
      }
    }
    parameters = tmpParameters;

    let body = "";
    let headers = {};
    let url = "/api2/json" + resource;

    if (method === "GET" || method === "DELETE") {
      const urlParams = new URLSearchParams(parameters).toString();
      if (urlParams.length > 0) {
        url += "?" + urlParams;
      }
    } else {
      body = JSON.stringify(parameters);
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
      rejectUnauthorized: false, // Proxmox VE uses self-signed certificates by default
      host: this.hostname,
      port: this.port,
      path: url,
      method: method,
      headers: headers,
      timeout: this.#timeout,
    };

    //debug: log a sanitized copy, masking sensitive parameters and headers
    this.#log({
      ...options,
      headers: PveClientBase.#maskSensitiveHeaders(headers),
      parameters: Result.maskSensitiveParameters(parameters),
    });

    return new Promise((resolve, reject) => {
      // @ts-ignore
      let req = this.#http.request(options, (response) => {
        response.setEncoding("utf8");
        let chunks = "";

        response.on("data", (chunk) => {
          chunks += chunk;
        });

        response.on("end", () => {
          let data = null;

          try {
            if (ref.responseType === ResponseType.JSON) {
              data = JSON.parse(chunks);
            } else if (ref.responseType === ResponseType.PNG) {
              if (!/^[A-Za-z0-9+/]*={0,2}$/.test(chunks.trim())) {
                throw new Error("Invalid base64 format for PNG response");
              }
              data = "data:image/png;base64," + chunks;
            }
          } catch (error) {
            this.#error(error);
            reject(new Error("Invalid response format: " + error.message));
            return;
          }

          const result = new Result(
            data,
            response.statusCode,
            response.statusMessage,
            resource,
            parameters,
            response.method,
            ref.responseType
          );

          ref.#lastResult = result;

          //debug
          this.#log(result.toString());
          this.#log(result.response);

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
   * @param {string} username
   * @param {string} password
   * @param {string} realm pam/pve or custom
   * @param {string} otp One-time password for Two-factor authentication.
   * @returns {Promise<boolean>}
   */
  login(username, password, realm = "pam", otp = null) {
    const ref = this;

    return new Promise((resolve, reject) => {
      this.create("/access/ticket", {
        password: password,
        username: username,
        realm: realm,
        otp: otp,
      })
        .then((result) => {
          if (result.isSuccessStatusCode) {
            ref.#ticketCSRFPreventionToken = result.response.data.CSRFPreventionToken;
            ref.#ticketPVEAuthCookie = result.response.data.ticket;
          }

          resolve(result.isSuccessStatusCode);
        })
        .catch((error) => {
          reject(error);
        });
    });
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
   * Return node from task
   * @param {string} task Task identifier
   * @return {string} Node name
   */
  #getNodeFromTask(task) {
    return task.split(":")[1];
  }

  /**
   * Wait for task to finish
   *
   * @param {string} task Task identifier
   * @param {number} wait Millisecond wait next check
   * @param {number} timeOut Millisecond timeout
   * @return {Promise<boolean>}
   */
  async waitForTaskToFinish(task, wait = 500, timeOut = 10000) {
    if (wait <= 0) {
      wait = 500;
    }
    if (timeOut < wait) {
      timeOut = wait + 5000;
    }
    let numberInterval = 0;
    const ref = this;

    return new Promise((resolve, reject) => {
      const interval = setInterval(function () {
        numberInterval++;

        if (numberInterval * wait >= timeOut) {
          clearInterval(interval);
          resolve(false);
        } else {
          ref.taskIsRunning(task).then((running) => {
            if (!running) {
              clearInterval(interval);
              resolve(true);
            }
          });
        }
      }, wait);
    });
  }

  /**
   * Task is running
   *
   * @param {string} task Task identifier
   * @returns {Promise<boolean>}
   */
  async taskIsRunning(task) {
    return (await this.readTaskStatus(task)).response.data.status === "running";
  }

  /**
   * Get exists status task.
   *
   * @param {string} task Task identifier
   * @returns {Promise<string>}
   */
  async getExitStatusTask(task) {
    return (await this.readTaskStatus(task)).response.data.exitstatus;
  }

  /**
   * Read task status.
   *
   * @param {string} task
   * @returns {Promise<Result>}
   */
  async readTaskStatus(task) {
    return this.get("/nodes/" + this.#getNodeFromTask(task) + "/tasks/" + task + "/status");
  }
}

// Export base classes first so that api-autogenerated.js (which requires this
// module to extend PveClientBase) sees them populated despite the circular require.
module.exports = { PveClientBase, Result, ResponseType };

const { PveClient } = require("./api-autogenerated.js");
module.exports.PveClient = PveClient;
