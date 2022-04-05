/*
 * SPDX-FileCopyrightText: 2022 Daniele Corsini <daniele.corsini@corsinvest.it>
 * SPDX-FileCopyrightText: Copyright Corsinvest Srl
 * SPDX-License-Identifier: GPL-3.0-only
 */

/**
 * Result
 */
class Result {
  /**
   *
   * @param {string} response
   * @param {int} statusCode
   * @param {string} reasonPhrase
   * @param {string} requestResource
   * @param {object} requestParameters
   * @param {string} methodType
   * @param {string} responseType
   */
  constructor(response, statusCode, reasonPhrase, requestResource,
    requestParameters, methodType, responseType) {

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
  get response() { return this.#response; }

  #statusCode = 0;
  /**
   *  Get status code
   */
  get statusCode() { return this.#statusCode; }

  #reasonPhrase = '';
  /**
   * Get reason phrase
   */
  get reasonPhrase() { return this.#reasonPhrase; }

  #requestResource = '';
  /**
   * Get request resource
   */
  get requestResource() { return this.#requestResource; }

  #requestParameters = null;
  /**
   * Get request parameters
   */
  get requestParameters() { return this.#requestParameters; }

  #methodType = '';
  /**
   * Get method type
   */
  get methodType() { return this.#methodType; }

  #responseType = '';
  /**
   * Get response type
   */
  get responseType() { return this.#responseType; }

  /**
   * Is success code
   */
  get isSuccessStatusCode() { return this.#statusCode == 200 }

  /**
   * Get if response Proxmox VE contain errors
   */
  get responseInError() { return typeof (this.#response.errors) != 'undefined'; }

  /**
   * ToString
   *
   * @returns info class
   */
  toString() {
    return ["Is Success Status Code: " + this.isSuccessStatusCode,
    "Status Code: " + this.#statusCode,
    "Reason Phrase: " + this.#reasonPhrase,
    "Request Resource: " + this.#requestResource,
    "Method Type: " + this.#methodType,
    "Response Type: " + this.#responseType,
    "Response In Error: " + this.responseInError,
    "Request Parameters: " + JSON.stringify(this.#requestParameters)].join('\n');
  }
}

/**
  * Response type
  */
class ResponseType {
  static JSON = 'json';
  static PNG = 'png';
}

/**
 * Proxmox VE Client Api Base
 */
class PveClientBase {
  /**
   * Constructor
   *
   * @param {string} hostname
   * @param {int} port
   */
  constructor(hostname, port = 8006) {
    this.#hostname = hostname;
    this.#port = port;
    this.#error.enabled = true;
  }

  #http = require('https');
  #debug = require('debug');
  #log = this.#debug('proxmox-ve:debug');
  #error = this.#debug('proxmox-ve:error');

  #ticketCSRFPreventionToken = '';
  #ticketPVEAuthCookie = '';

  #hostname = '';
  /**
   * Get host name
   */
  get hostname() { return this.#hostname; }

  #port = 8006;
  /**
   * Get port
   */
  get port() { return this.#port; }

  #responseType = ResponseType.JSON;
  /**
   * Get response type
   */
  get responseType() { return this.#responseType; }
  /**
   * Set response type
   */
  set responseType(value) { this.#responseType = value; }

  #lastResult = new Result('', 0, '', '', '', '', '');
  /**
   * Get last result
   */
  get lastResult() { return this.#lastResult; }

  #apiToken = '';
  /**
   * Get Api token
   */
  get apiToken() { return this.#apiToken; }
  /**
   * Set Api token
   */
  set apiToken(value) { this.#apiToken = value; }

  /**
   * Log enabled
   */
  get logEnabled() { return this.#log.enabled; }
  /**
   * Set Api token
   */
  set logEnabled(value) {
    this.#log.enabled = value;
    this.#error.enabled = value;
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

    if (parameters == null || parameters == undefined) { parameters = Object.create({}); }

    let tmpParameters = Object.create({});
    for (const [key, value] of Object.entries(parameters)) {
      if (value != null && value != undefined) {
        if (typeof value == "boolean") {
          tmpParameters[key] = value ? 1 : 0;
        }
        else {
          tmpParameters[key] = value;
        }
      }
    }
    parameters = tmpParameters;

    let body = '';
    let headers = {};
    let url = '/api2/json' + resource;
    const urlParams = new URLSearchParams(parameters).toString();

    if (method == 'GET' || method == 'DELETE') {
      if (urlParams.length > 0) { url += '?' + urlParams; }
    } else {
      body = urlParams;
      headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
      };
    }

    if (this.#ticketCSRFPreventionToken != '') {
      headers['CSRFPreventionToken'] = this.#ticketCSRFPreventionToken;
      headers['Cookie'] = 'PVEAuthCookie=' + this.#ticketPVEAuthCookie;
    }

    if (this.apiToken != '') { headers['Authorization'] = "PVEAPIToken " + this.apiToken; }

    const options = {
      rejectUnauthorized: false,
      host: this.hostname,
      port: this.port,
      path: url,
      method: method,
      headers: headers
    };

    //debug
    this.#log(options);

    return new Promise((resolve, reject) => {
      let req = this.#http.request(options, (response) => {
        response.setEncoding('utf8');
        let chunks = '';

        response.on('data', (chunk) => { chunks += chunk; });

        response.on('end', () => {
          let data = null;

          if (ref.responseType == ResponseType.JSON) {
            data = JSON.parse(chunks);
          }
          else if (ref.responseType == ResponseType.PNG) {
            data = "data:image/png;base64," + chunks;
          }

          const result = new Result(data,
            response.statusCode,
            response.statusMessage,
            resource,
            parameters,
            response.method,
            ref.responseType);

          ref.#lastResult = result;

          //debug
          this.#log(result.toString());
          this.#log(result.response);

          resolve(result);
        });

        response.on('error', (error) => {
          this.#error(error)
          reject(error);
        });
      });

      if (body != '') { req.write(body); }
      req.end();
    });
  }

  /**
   * Login
   *
   * @param {string} username
   * @param {string} password
   * @param {string} realm
   * @returns {Promise<boolean>}
   */
  login(username, password, realm = 'pam') {
    const ref = this;

    return new Promise((resolve, reject) => {
      this.create("/access/ticket", { password: password, username: username, realm: realm })
        .then((result) => {
          if (result.isSuccessStatusCode) {
            ref.#ticketCSRFPreventionToken = result.response.data.CSRFPreventionToken;
            ref.#ticketPVEAuthCookie = result.response.data.ticket;
          }

          resolve(result.isSuccessStatusCode);
        }).catch((error) => { reject(error) });
    });
  }

  /**
   * Get
   *
   * @param {string} resource
   * @param {object} parameters
   * @returns {Promise<Result>}
   */
  async get(resource, parameters = {}) { return this.#execute('GET', resource, parameters); }

  /**
   * Set
   *
   * @param {string} resource
   * @param {object} parameters
   * @returns {Promise<Result>}
   */
  async set(resource, parameters = {}) { return this.#execute('PUT', resource, parameters); }

  /**
   * Create
   *
   * @param {string} resource
   * @param {float} parameters
   * @returns {Promise<Result>}
   */
  async create(resource, parameters = {}) { return this.#execute('POST', resource, parameters); }

  /**
   * Delete
   *
   * @param {string} resource
   * @param {object} parameters
   * @returns {Promise<Result>}
   */
  async delete(resource, parameters = {}) { return this.#execute('DELETE', resource, parameters); }

  /**
   * Return node from task
   * @param {string} task Task identifier
   * @return {string} Node name
   */
  #getNodeFromTask(task) { return task.split(':')[1]; }

  /**
   * Wait for task to finish
   *
   * @param {string} task Task identifier
   * @param {int} wait Millisecond wait next check
   * @param {int} timeOut Millisecond timeout
   * @return {Promise<boolean>}
   */
  async waitForTaskToFinish(task, wait = 500, timeOut = 10000) {
    if (wait <= 0) { wait = 500; }
    if (timeOut < wait) { timeOut = wait + 5000; }
    let numberInterval = 0;
    const ref = this;

    return new Promise((resolve, reject) => {
      const interval = setInterval(function () {
        numberInterval++;

        if (numberInterval * wait >= timeOut) {
          clearInterval(interval);
          resolve(false);
        }
        else {
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
   * @returns {Promise<bool>}
   */
  async taskIsRunning(task) { return await this.readTaskStatus(task).Response.data.status == "running"; }

  /**
   * Get exists status task.
   *
   * @param {string} task Task identifier
   * @returns {string}
   * @returns {Promise<string>}
   */
  async getExitStatusTask(task) { return await this.readTaskStatus(task).response.data.exitstatus; }

  /**
   * Read task status.
   *
   * @param {string} task
   * @returns {Promise<Result>}
   */
  async readTaskStatus(task) { return this.get('/nodes/' + this.#getNodeFromTask(node) + '/tasks/' + task + '/status'); }
}

//////////////////////////////////////
///////// API auto generated /////////
//////////////////////////////////////

/**
 * Proxmox VE Client Api
 */
class PveClient extends PveClientBase {
  /** @type {PveClient} */
  #client;

  /**
   * Constructor
   *
   * @param {string} hostname
   * @param {int} port
   */
  constructor(hostname, port = 8006) {
    super(hostname, port);
    this.#client = this;
  }

  /**
    * Add index parameter to parameters
    * @param {array} parameters Parameters
    * @param {string} name name
    * @param {array} values values
    */
  addIndexedParameter(parameters, name, values) {
    if (values == null) { return; }

    for (const [key, value] of Object.entries(parameters)) {
      parameters[name + key] = value;
    }
  }

  #cluster;
  /**
   * Get Cluster
   * @returns {PVECluster}
   */
  get cluster() { return this.#cluster == null ? (this.#cluster = new PVECluster(this.#client)) : this.#cluster; }
  #nodes;
  /**
   * Get Nodes
   * @returns {PVENodes}
   */
  get nodes() { return this.#nodes == null ? (this.#nodes = new PVENodes(this.#client)) : this.#nodes; }
  #storage;
  /**
   * Get Storage
   * @returns {PVEStorage}
   */
  get storage() { return this.#storage == null ? (this.#storage = new PVEStorage(this.#client)) : this.#storage; }
  #access;
  /**
   * Get Access
   * @returns {PVEAccess}
   */
  get access() { return this.#access == null ? (this.#access = new PVEAccess(this.#client)) : this.#access; }
  #pools;
  /**
   * Get Pools
   * @returns {PVEPools}
   */
  get pools() { return this.#pools == null ? (this.#pools = new PVEPools(this.#client)) : this.#pools; }
  #version;
  /**
   * Get Version
   * @returns {PVEVersion}
   */
  get version() { return this.#version == null ? (this.#version = new PVEVersion(this.#client)) : this.#version; }


}
/**
 * Class PVECluster
 */
class PVECluster {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }

  #replication;
  /**
   * Get ClusterReplication
   * @returns {PVEClusterReplication}
   */
  get replication() { return this.#replication == null ? (this.#replication = new PVEClusterReplication(this.#client)) : this.#replication; }
  #metrics;
  /**
   * Get ClusterMetrics
   * @returns {PVEClusterMetrics}
   */
  get metrics() { return this.#metrics == null ? (this.#metrics = new PVEClusterMetrics(this.#client)) : this.#metrics; }
  #config;
  /**
   * Get ClusterConfig
   * @returns {PVEClusterConfig}
   */
  get config() { return this.#config == null ? (this.#config = new PVEClusterConfig(this.#client)) : this.#config; }
  #firewall;
  /**
   * Get ClusterFirewall
   * @returns {PVEClusterFirewall}
   */
  get firewall() { return this.#firewall == null ? (this.#firewall = new PVEClusterFirewall(this.#client)) : this.#firewall; }
  #backup;
  /**
   * Get ClusterBackup
   * @returns {PVEClusterBackup}
   */
  get backup() { return this.#backup == null ? (this.#backup = new PVEClusterBackup(this.#client)) : this.#backup; }
  #backupInfo;
  /**
   * Get ClusterBackupInfo
   * @returns {PVEClusterBackupInfo}
   */
  get backupInfo() { return this.#backupInfo == null ? (this.#backupInfo = new PVEClusterBackupInfo(this.#client)) : this.#backupInfo; }
  #ha;
  /**
   * Get ClusterHa
   * @returns {PVEClusterHa}
   */
  get ha() { return this.#ha == null ? (this.#ha = new PVEClusterHa(this.#client)) : this.#ha; }
  #acme;
  /**
   * Get ClusterAcme
   * @returns {PVEClusterAcme}
   */
  get acme() { return this.#acme == null ? (this.#acme = new PVEClusterAcme(this.#client)) : this.#acme; }
  #ceph;
  /**
   * Get ClusterCeph
   * @returns {PVEClusterCeph}
   */
  get ceph() { return this.#ceph == null ? (this.#ceph = new PVEClusterCeph(this.#client)) : this.#ceph; }
  #jobs;
  /**
   * Get ClusterJobs
   * @returns {PVEClusterJobs}
   */
  get jobs() { return this.#jobs == null ? (this.#jobs = new PVEClusterJobs(this.#client)) : this.#jobs; }
  #sdn;
  /**
   * Get ClusterSdn
   * @returns {PVEClusterSdn}
   */
  get sdn() { return this.#sdn == null ? (this.#sdn = new PVEClusterSdn(this.#client)) : this.#sdn; }
  #log;
  /**
   * Get ClusterLog
   * @returns {PVEClusterLog}
   */
  get log() { return this.#log == null ? (this.#log = new PVEClusterLog(this.#client)) : this.#log; }
  #resources;
  /**
   * Get ClusterResources
   * @returns {PVEClusterResources}
   */
  get resources() { return this.#resources == null ? (this.#resources = new PVEClusterResources(this.#client)) : this.#resources; }
  #tasks;
  /**
   * Get ClusterTasks
   * @returns {PVEClusterTasks}
   */
  get tasks() { return this.#tasks == null ? (this.#tasks = new PVEClusterTasks(this.#client)) : this.#tasks; }
  #options;
  /**
   * Get ClusterOptions
   * @returns {PVEClusterOptions}
   */
  get options() { return this.#options == null ? (this.#options = new PVEClusterOptions(this.#client)) : this.#options; }
  #status;
  /**
   * Get ClusterStatus
   * @returns {PVEClusterStatus}
   */
  get status() { return this.#status == null ? (this.#status = new PVEClusterStatus(this.#client)) : this.#status; }
  #nextid;
  /**
   * Get ClusterNextid
   * @returns {PVEClusterNextid}
   */
  get nextid() { return this.#nextid == null ? (this.#nextid = new PVEClusterNextid(this.#client)) : this.#nextid; }


  /**
  * Cluster index.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/cluster`);
  }

}
/**
 * Class PVEClusterReplication
 */
class PVEClusterReplication {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }


  /**
   * Get ItemReplicationClusterId
   * @param id
   * @returns {PVEItemReplicationClusterId}
   */
  get(id) { return new PVEItemReplicationClusterId(this.#client, id); }

  /**
  * List replication jobs.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/cluster/replication`);
  }
  /**
  * Create a new replication job
  * @param {string} id Replication Job ID. The ID is composed of a Guest ID and a job number, separated by a hyphen, i.e. '&amp;lt;GUEST&amp;gt;-&amp;lt;JOBNUM&amp;gt;'.
  * @param {string} target Target node.
  * @param {string} type Section type.
  *   Enum: local
  * @param {string} comment Description.
  * @param {bool} disable Flag to disable/deactivate the entry.
  * @param {float} rate Rate limit in mbps (megabytes per second) as floating point number.
  * @param {string} remove_job Mark the replication job for removal. The job will remove all local replication snapshots. When set to 'full', it also tries to remove replicated volumes on the target. The job then removes itself from the configuration file.
  *   Enum: local,full
  * @param {string} schedule Storage replication schedule. The format is a subset of `systemd` calendar events.
  * @param {string} source For internal use, to detect if the guest was stolen.
  * @returns {Result}
  */
  async create(id, target, type, comment, disable, rate, remove_job, schedule, source) {
    const parameters = {
      'id': id,
      'target': target,
      'type': type,
      'comment': comment,
      'disable': disable,
      'rate': rate,
      'remove_job': remove_job,
      'schedule': schedule,
      'source': source
    };
    return await this.#client.create(`/cluster/replication`, parameters);
  }

}
/**
 * Class PVEItemReplicationClusterId
 */
class PVEItemReplicationClusterId {
  #id;
  /** @type {PveClient} */
  #client;

  constructor(client, id) {
    this.#client = client;
    this.#id = id;
  }



  /**
  * Mark replication job for removal.
  * @param {bool} force Will remove the jobconfig entry, but will not cleanup.
  * @param {bool} keep Keep replicated data at target (do not remove).
  * @returns {Result}
  */
  async delete_(force, keep) {
    const parameters = {
      'force': force,
      'keep': keep
    };
    return await this.#client.delete(`/cluster/replication/${this.#id}`, parameters);
  }
  /**
  * Read replication job configuration.
  * @returns {Result}
  */
  async read() {
    return await this.#client.get(`/cluster/replication/${this.#id}`);
  }
  /**
  * Update replication job configuration.
  * @param {string} comment Description.
  * @param {string} delete_ A list of settings you want to delete.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {bool} disable Flag to disable/deactivate the entry.
  * @param {float} rate Rate limit in mbps (megabytes per second) as floating point number.
  * @param {string} remove_job Mark the replication job for removal. The job will remove all local replication snapshots. When set to 'full', it also tries to remove replicated volumes on the target. The job then removes itself from the configuration file.
  *   Enum: local,full
  * @param {string} schedule Storage replication schedule. The format is a subset of `systemd` calendar events.
  * @param {string} source For internal use, to detect if the guest was stolen.
  * @returns {Result}
  */
  async update(comment, delete_, digest, disable, rate, remove_job, schedule, source) {
    const parameters = {
      'comment': comment,
      'delete': delete_,
      'digest': digest,
      'disable': disable,
      'rate': rate,
      'remove_job': remove_job,
      'schedule': schedule,
      'source': source
    };
    return await this.#client.set(`/cluster/replication/${this.#id}`, parameters);
  }

}

/**
 * Class PVEClusterMetrics
 */
class PVEClusterMetrics {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }

  #server;
  /**
   * Get MetricsClusterServer
   * @returns {PVEMetricsClusterServer}
   */
  get server() { return this.#server == null ? (this.#server = new PVEMetricsClusterServer(this.#client)) : this.#server; }


  /**
  * Metrics index.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/cluster/metrics`);
  }

}
/**
 * Class PVEMetricsClusterServer
 */
class PVEMetricsClusterServer {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }


  /**
   * Get ItemServerMetricsClusterId
   * @param id
   * @returns {PVEItemServerMetricsClusterId}
   */
  get(id) { return new PVEItemServerMetricsClusterId(this.#client, id); }

  /**
  * List configured metric servers.
  * @returns {Result}
  */
  async serverIndex() {
    return await this.#client.get(`/cluster/metrics/server`);
  }

}
/**
 * Class PVEItemServerMetricsClusterId
 */
class PVEItemServerMetricsClusterId {
  #id;
  /** @type {PveClient} */
  #client;

  constructor(client, id) {
    this.#client = client;
    this.#id = id;
  }



  /**
  * Remove Metric server.
  * @returns {Result}
  */
  async delete_() {
    return await this.#client.delete(`/cluster/metrics/server/${this.#id}`);
  }
  /**
  * Read metric server configuration.
  * @returns {Result}
  */
  async read() {
    return await this.#client.get(`/cluster/metrics/server/${this.#id}`);
  }
  /**
  * Create a new external metric server config
  * @param {int} port server network port
  * @param {string} server server dns name or IP address
  * @param {string} type Plugin type.
  *   Enum: graphite,influxdb
  * @param {string} api_path_prefix An API path prefix inserted between '&amp;lt;host&amp;gt;:&amp;lt;port&amp;gt;/' and '/api2/'. Can be useful if the InfluxDB service runs behind a reverse proxy.
  * @param {string} bucket The InfluxDB bucket/db. Only necessary when using the http v2 api.
  * @param {bool} disable Flag to disable the plugin.
  * @param {string} influxdbproto
  *   Enum: udp,http,https
  * @param {int} max_body_size InfluxDB max-body-size in bytes. Requests are batched up to this size.
  * @param {int} mtu MTU for metrics transmission over UDP
  * @param {string} organization The InfluxDB organization. Only necessary when using the http v2 api. Has no meaning when using v2 compatibility api.
  * @param {string} path root graphite path (ex: proxmox.mycluster.mykey)
  * @param {string} proto Protocol to send graphite data. TCP or UDP (default)
  *   Enum: udp,tcp
  * @param {int} timeout graphite TCP socket timeout (default=1)
  * @param {string} token The InfluxDB access token. Only necessary when using the http v2 api. If the v2 compatibility api is used, use 'user:password' instead.
  * @param {bool} verify_certificate Set to 0 to disable certificate verification for https endpoints.
  * @returns {Result}
  */
  async create(port, server, type, api_path_prefix, bucket, disable, influxdbproto, max_body_size, mtu, organization, path, proto, timeout, token, verify_certificate) {
    const parameters = {
      'port': port,
      'server': server,
      'type': type,
      'api-path-prefix': api_path_prefix,
      'bucket': bucket,
      'disable': disable,
      'influxdbproto': influxdbproto,
      'max-body-size': max_body_size,
      'mtu': mtu,
      'organization': organization,
      'path': path,
      'proto': proto,
      'timeout': timeout,
      'token': token,
      'verify-certificate': verify_certificate
    };
    return await this.#client.create(`/cluster/metrics/server/${this.#id}`, parameters);
  }
  /**
  * Update metric server configuration.
  * @param {int} port server network port
  * @param {string} server server dns name or IP address
  * @param {string} api_path_prefix An API path prefix inserted between '&amp;lt;host&amp;gt;:&amp;lt;port&amp;gt;/' and '/api2/'. Can be useful if the InfluxDB service runs behind a reverse proxy.
  * @param {string} bucket The InfluxDB bucket/db. Only necessary when using the http v2 api.
  * @param {string} delete_ A list of settings you want to delete.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {bool} disable Flag to disable the plugin.
  * @param {string} influxdbproto
  *   Enum: udp,http,https
  * @param {int} max_body_size InfluxDB max-body-size in bytes. Requests are batched up to this size.
  * @param {int} mtu MTU for metrics transmission over UDP
  * @param {string} organization The InfluxDB organization. Only necessary when using the http v2 api. Has no meaning when using v2 compatibility api.
  * @param {string} path root graphite path (ex: proxmox.mycluster.mykey)
  * @param {string} proto Protocol to send graphite data. TCP or UDP (default)
  *   Enum: udp,tcp
  * @param {int} timeout graphite TCP socket timeout (default=1)
  * @param {string} token The InfluxDB access token. Only necessary when using the http v2 api. If the v2 compatibility api is used, use 'user:password' instead.
  * @param {bool} verify_certificate Set to 0 to disable certificate verification for https endpoints.
  * @returns {Result}
  */
  async update(port, server, api_path_prefix, bucket, delete_, digest, disable, influxdbproto, max_body_size, mtu, organization, path, proto, timeout, token, verify_certificate) {
    const parameters = {
      'port': port,
      'server': server,
      'api-path-prefix': api_path_prefix,
      'bucket': bucket,
      'delete': delete_,
      'digest': digest,
      'disable': disable,
      'influxdbproto': influxdbproto,
      'max-body-size': max_body_size,
      'mtu': mtu,
      'organization': organization,
      'path': path,
      'proto': proto,
      'timeout': timeout,
      'token': token,
      'verify-certificate': verify_certificate
    };
    return await this.#client.set(`/cluster/metrics/server/${this.#id}`, parameters);
  }

}

/**
 * Class PVEClusterConfig
 */
class PVEClusterConfig {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }

  #apiversion;
  /**
   * Get ConfigClusterApiversion
   * @returns {PVEConfigClusterApiversion}
   */
  get apiversion() { return this.#apiversion == null ? (this.#apiversion = new PVEConfigClusterApiversion(this.#client)) : this.#apiversion; }
  #nodes;
  /**
   * Get ConfigClusterNodes
   * @returns {PVEConfigClusterNodes}
   */
  get nodes() { return this.#nodes == null ? (this.#nodes = new PVEConfigClusterNodes(this.#client)) : this.#nodes; }
  #join;
  /**
   * Get ConfigClusterJoin
   * @returns {PVEConfigClusterJoin}
   */
  get join() { return this.#join == null ? (this.#join = new PVEConfigClusterJoin(this.#client)) : this.#join; }
  #totem;
  /**
   * Get ConfigClusterTotem
   * @returns {PVEConfigClusterTotem}
   */
  get totem() { return this.#totem == null ? (this.#totem = new PVEConfigClusterTotem(this.#client)) : this.#totem; }
  #qdevice;
  /**
   * Get ConfigClusterQdevice
   * @returns {PVEConfigClusterQdevice}
   */
  get qdevice() { return this.#qdevice == null ? (this.#qdevice = new PVEConfigClusterQdevice(this.#client)) : this.#qdevice; }


  /**
  * Directory index.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/cluster/config`);
  }
  /**
  * Generate new cluster configuration. If no links given, default to local IP address as link0.
  * @param {string} clustername The name of the cluster.
  * @param {array} linkN Address and priority information of a single corosync link. (up to 8 links supported; link0..link7)
  * @param {int} nodeid Node id for this node.
  * @param {int} votes Number of votes for this node.
  * @returns {Result}
  */
  async create(clustername, linkN, nodeid, votes) {
    const parameters = {
      'clustername': clustername,
      'nodeid': nodeid,
      'votes': votes
    };
    this.#client.addIndexedParameter(parameters, 'link', linkN);
    return await this.#client.create(`/cluster/config`, parameters);
  }

}
/**
 * Class PVEConfigClusterApiversion
 */
class PVEConfigClusterApiversion {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }



  /**
  * Return the version of the cluster join API available on this node.
  * @returns {Result}
  */
  async joinApiVersion() {
    return await this.#client.get(`/cluster/config/apiversion`);
  }

}

/**
 * Class PVEConfigClusterNodes
 */
class PVEConfigClusterNodes {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }


  /**
   * Get ItemNodesConfigClusterNode
   * @param node
   * @returns {PVEItemNodesConfigClusterNode}
   */
  get(node) { return new PVEItemNodesConfigClusterNode(this.#client, node); }

  /**
  * Corosync node list.
  * @returns {Result}
  */
  async nodes() {
    return await this.#client.get(`/cluster/config/nodes`);
  }

}
/**
 * Class PVEItemNodesConfigClusterNode
 */
class PVEItemNodesConfigClusterNode {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Removes a node from the cluster configuration.
  * @returns {Result}
  */
  async delnode() {
    return await this.#client.delete(`/cluster/config/nodes/${this.#node}`);
  }
  /**
  * Adds a node to the cluster configuration. This call is for internal use.
  * @param {int} apiversion The JOIN_API_VERSION of the new node.
  * @param {bool} force Do not throw error if node already exists.
  * @param {array} linkN Address and priority information of a single corosync link. (up to 8 links supported; link0..link7)
  * @param {string} new_node_ip IP Address of node to add. Used as fallback if no links are given.
  * @param {int} nodeid Node id for this node.
  * @param {int} votes Number of votes for this node
  * @returns {Result}
  */
  async addnode(apiversion, force, linkN, new_node_ip, nodeid, votes) {
    const parameters = {
      'apiversion': apiversion,
      'force': force,
      'new_node_ip': new_node_ip,
      'nodeid': nodeid,
      'votes': votes
    };
    this.#client.addIndexedParameter(parameters, 'link', linkN);
    return await this.#client.create(`/cluster/config/nodes/${this.#node}`, parameters);
  }

}

/**
 * Class PVEConfigClusterJoin
 */
class PVEConfigClusterJoin {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }



  /**
  * Get information needed to join this cluster over the connected node.
  * @param {string} node The node for which the joinee gets the nodeinfo.
  * @returns {Result}
  */
  async joinInfo(node) {
    const parameters = { 'node': node };
    return await this.#client.get(`/cluster/config/join`, parameters);
  }
  /**
  * Joins this node into an existing cluster. If no links are given, default to IP resolved by node's hostname on single link (fallback fails for clusters with multiple links).
  * @param {string} fingerprint Certificate SHA 256 fingerprint.
  * @param {string} hostname Hostname (or IP) of an existing cluster member.
  * @param {string} password Superuser (root) password of peer node.
  * @param {bool} force Do not throw error if node already exists.
  * @param {array} linkN Address and priority information of a single corosync link. (up to 8 links supported; link0..link7)
  * @param {int} nodeid Node id for this node.
  * @param {int} votes Number of votes for this node
  * @returns {Result}
  */
  async join(fingerprint, hostname, password, force, linkN, nodeid, votes) {
    const parameters = {
      'fingerprint': fingerprint,
      'hostname': hostname,
      'password': password,
      'force': force,
      'nodeid': nodeid,
      'votes': votes
    };
    this.#client.addIndexedParameter(parameters, 'link', linkN);
    return await this.#client.create(`/cluster/config/join`, parameters);
  }

}

/**
 * Class PVEConfigClusterTotem
 */
class PVEConfigClusterTotem {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }



  /**
  * Get corosync totem protocol settings.
  * @returns {Result}
  */
  async totem() {
    return await this.#client.get(`/cluster/config/totem`);
  }

}

/**
 * Class PVEConfigClusterQdevice
 */
class PVEConfigClusterQdevice {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }



  /**
  * Get QDevice status
  * @returns {Result}
  */
  async status() {
    return await this.#client.get(`/cluster/config/qdevice`);
  }

}

/**
 * Class PVEClusterFirewall
 */
class PVEClusterFirewall {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }

  #groups;
  /**
   * Get FirewallClusterGroups
   * @returns {PVEFirewallClusterGroups}
   */
  get groups() { return this.#groups == null ? (this.#groups = new PVEFirewallClusterGroups(this.#client)) : this.#groups; }
  #rules;
  /**
   * Get FirewallClusterRules
   * @returns {PVEFirewallClusterRules}
   */
  get rules() { return this.#rules == null ? (this.#rules = new PVEFirewallClusterRules(this.#client)) : this.#rules; }
  #ipset;
  /**
   * Get FirewallClusterIpset
   * @returns {PVEFirewallClusterIpset}
   */
  get ipset() { return this.#ipset == null ? (this.#ipset = new PVEFirewallClusterIpset(this.#client)) : this.#ipset; }
  #aliases;
  /**
   * Get FirewallClusterAliases
   * @returns {PVEFirewallClusterAliases}
   */
  get aliases() { return this.#aliases == null ? (this.#aliases = new PVEFirewallClusterAliases(this.#client)) : this.#aliases; }
  #options;
  /**
   * Get FirewallClusterOptions
   * @returns {PVEFirewallClusterOptions}
   */
  get options() { return this.#options == null ? (this.#options = new PVEFirewallClusterOptions(this.#client)) : this.#options; }
  #macros;
  /**
   * Get FirewallClusterMacros
   * @returns {PVEFirewallClusterMacros}
   */
  get macros() { return this.#macros == null ? (this.#macros = new PVEFirewallClusterMacros(this.#client)) : this.#macros; }
  #refs;
  /**
   * Get FirewallClusterRefs
   * @returns {PVEFirewallClusterRefs}
   */
  get refs() { return this.#refs == null ? (this.#refs = new PVEFirewallClusterRefs(this.#client)) : this.#refs; }


  /**
  * Directory index.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/cluster/firewall`);
  }

}
/**
 * Class PVEFirewallClusterGroups
 */
class PVEFirewallClusterGroups {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }


  /**
   * Get ItemGroupsFirewallClusterGroup
   * @param group
   * @returns {PVEItemGroupsFirewallClusterGroup}
   */
  get(group) { return new PVEItemGroupsFirewallClusterGroup(this.#client, group); }

  /**
  * List security groups.
  * @returns {Result}
  */
  async listSecurityGroups() {
    return await this.#client.get(`/cluster/firewall/groups`);
  }
  /**
  * Create new security group.
  * @param {string} group Security Group name.
  * @param {string} comment
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {string} rename Rename/update an existing security group. You can set 'rename' to the same value as 'name' to update the 'comment' of an existing group.
  * @returns {Result}
  */
  async createSecurityGroup(group, comment, digest, rename) {
    const parameters = {
      'group': group,
      'comment': comment,
      'digest': digest,
      'rename': rename
    };
    return await this.#client.create(`/cluster/firewall/groups`, parameters);
  }

}
/**
 * Class PVEItemGroupsFirewallClusterGroup
 */
class PVEItemGroupsFirewallClusterGroup {
  #group;
  /** @type {PveClient} */
  #client;

  constructor(client, group) {
    this.#client = client;
    this.#group = group;
  }


  /**
   * Get ItemGroupGroupsFirewallClusterPos
   * @param pos
   * @returns {PVEItemGroupGroupsFirewallClusterPos}
   */
  get(pos) { return new PVEItemGroupGroupsFirewallClusterPos(this.#client, this.#group, pos); }

  /**
  * Delete security group.
  * @returns {Result}
  */
  async deleteSecurityGroup() {
    return await this.#client.delete(`/cluster/firewall/groups/${this.#group}`);
  }
  /**
  * List rules.
  * @returns {Result}
  */
  async getRules() {
    return await this.#client.get(`/cluster/firewall/groups/${this.#group}`);
  }
  /**
  * Create new rule.
  * @param {string} action Rule action ('ACCEPT', 'DROP', 'REJECT') or security group name.
  * @param {string} type Rule type.
  *   Enum: in,out,group
  * @param {string} comment Descriptive comment.
  * @param {string} dest Restrict packet destination address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {string} dport Restrict TCP/UDP destination port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
  * @param {int} enable Flag to enable/disable a rule.
  * @param {string} icmp_type Specify icmp-type. Only valid if proto equals 'icmp'.
  * @param {string} iface Network interface name. You have to use network configuration key names for VMs and containers ('net\d+'). Host related rules can use arbitrary strings.
  * @param {string} log Log level for firewall rule.
  *   Enum: emerg,alert,crit,err,warning,notice,info,debug,nolog
  * @param {string} macro Use predefined standard macro.
  * @param {int} pos Update rule at position &amp;lt;pos&amp;gt;.
  * @param {string} proto IP protocol. You can use protocol names ('tcp'/'udp') or simple numbers, as defined in '/etc/protocols'.
  * @param {string} source Restrict packet source address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
  * @param {string} sport Restrict TCP/UDP source port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
  * @returns {Result}
  */
  async createRule(action, type, comment, dest, digest, dport, enable, icmp_type, iface, log, macro, pos, proto, source, sport) {
    const parameters = {
      'action': action,
      'type': type,
      'comment': comment,
      'dest': dest,
      'digest': digest,
      'dport': dport,
      'enable': enable,
      'icmp-type': icmp_type,
      'iface': iface,
      'log': log,
      'macro': macro,
      'pos': pos,
      'proto': proto,
      'source': source,
      'sport': sport
    };
    return await this.#client.create(`/cluster/firewall/groups/${this.#group}`, parameters);
  }

}
/**
 * Class PVEItemGroupGroupsFirewallClusterPos
 */
class PVEItemGroupGroupsFirewallClusterPos {
  #group;
  #pos;
  /** @type {PveClient} */
  #client;

  constructor(client, group, pos) {
    this.#client = client;
    this.#group = group;
    this.#pos = pos;
  }



  /**
  * Delete rule.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @returns {Result}
  */
  async deleteRule(digest) {
    const parameters = { 'digest': digest };
    return await this.#client.delete(`/cluster/firewall/groups/${this.#group}/${this.#pos}`, parameters);
  }
  /**
  * Get single rule data.
  * @returns {Result}
  */
  async getRule() {
    return await this.#client.get(`/cluster/firewall/groups/${this.#group}/${this.#pos}`);
  }
  /**
  * Modify rule data.
  * @param {string} action Rule action ('ACCEPT', 'DROP', 'REJECT') or security group name.
  * @param {string} comment Descriptive comment.
  * @param {string} delete_ A list of settings you want to delete.
  * @param {string} dest Restrict packet destination address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {string} dport Restrict TCP/UDP destination port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
  * @param {int} enable Flag to enable/disable a rule.
  * @param {string} icmp_type Specify icmp-type. Only valid if proto equals 'icmp'.
  * @param {string} iface Network interface name. You have to use network configuration key names for VMs and containers ('net\d+'). Host related rules can use arbitrary strings.
  * @param {string} log Log level for firewall rule.
  *   Enum: emerg,alert,crit,err,warning,notice,info,debug,nolog
  * @param {string} macro Use predefined standard macro.
  * @param {int} moveto Move rule to new position &amp;lt;moveto&amp;gt;. Other arguments are ignored.
  * @param {string} proto IP protocol. You can use protocol names ('tcp'/'udp') or simple numbers, as defined in '/etc/protocols'.
  * @param {string} source Restrict packet source address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
  * @param {string} sport Restrict TCP/UDP source port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
  * @param {string} type Rule type.
  *   Enum: in,out,group
  * @returns {Result}
  */
  async updateRule(action, comment, delete_, dest, digest, dport, enable, icmp_type, iface, log, macro, moveto, proto, source, sport, type) {
    const parameters = {
      'action': action,
      'comment': comment,
      'delete': delete_,
      'dest': dest,
      'digest': digest,
      'dport': dport,
      'enable': enable,
      'icmp-type': icmp_type,
      'iface': iface,
      'log': log,
      'macro': macro,
      'moveto': moveto,
      'proto': proto,
      'source': source,
      'sport': sport,
      'type': type
    };
    return await this.#client.set(`/cluster/firewall/groups/${this.#group}/${this.#pos}`, parameters);
  }

}

/**
 * Class PVEFirewallClusterRules
 */
class PVEFirewallClusterRules {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }


  /**
   * Get ItemRulesFirewallClusterPos
   * @param pos
   * @returns {PVEItemRulesFirewallClusterPos}
   */
  get(pos) { return new PVEItemRulesFirewallClusterPos(this.#client, pos); }

  /**
  * List rules.
  * @returns {Result}
  */
  async getRules() {
    return await this.#client.get(`/cluster/firewall/rules`);
  }
  /**
  * Create new rule.
  * @param {string} action Rule action ('ACCEPT', 'DROP', 'REJECT') or security group name.
  * @param {string} type Rule type.
  *   Enum: in,out,group
  * @param {string} comment Descriptive comment.
  * @param {string} dest Restrict packet destination address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {string} dport Restrict TCP/UDP destination port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
  * @param {int} enable Flag to enable/disable a rule.
  * @param {string} icmp_type Specify icmp-type. Only valid if proto equals 'icmp'.
  * @param {string} iface Network interface name. You have to use network configuration key names for VMs and containers ('net\d+'). Host related rules can use arbitrary strings.
  * @param {string} log Log level for firewall rule.
  *   Enum: emerg,alert,crit,err,warning,notice,info,debug,nolog
  * @param {string} macro Use predefined standard macro.
  * @param {int} pos Update rule at position &amp;lt;pos&amp;gt;.
  * @param {string} proto IP protocol. You can use protocol names ('tcp'/'udp') or simple numbers, as defined in '/etc/protocols'.
  * @param {string} source Restrict packet source address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
  * @param {string} sport Restrict TCP/UDP source port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
  * @returns {Result}
  */
  async createRule(action, type, comment, dest, digest, dport, enable, icmp_type, iface, log, macro, pos, proto, source, sport) {
    const parameters = {
      'action': action,
      'type': type,
      'comment': comment,
      'dest': dest,
      'digest': digest,
      'dport': dport,
      'enable': enable,
      'icmp-type': icmp_type,
      'iface': iface,
      'log': log,
      'macro': macro,
      'pos': pos,
      'proto': proto,
      'source': source,
      'sport': sport
    };
    return await this.#client.create(`/cluster/firewall/rules`, parameters);
  }

}
/**
 * Class PVEItemRulesFirewallClusterPos
 */
class PVEItemRulesFirewallClusterPos {
  #pos;
  /** @type {PveClient} */
  #client;

  constructor(client, pos) {
    this.#client = client;
    this.#pos = pos;
  }



  /**
  * Delete rule.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @returns {Result}
  */
  async deleteRule(digest) {
    const parameters = { 'digest': digest };
    return await this.#client.delete(`/cluster/firewall/rules/${this.#pos}`, parameters);
  }
  /**
  * Get single rule data.
  * @returns {Result}
  */
  async getRule() {
    return await this.#client.get(`/cluster/firewall/rules/${this.#pos}`);
  }
  /**
  * Modify rule data.
  * @param {string} action Rule action ('ACCEPT', 'DROP', 'REJECT') or security group name.
  * @param {string} comment Descriptive comment.
  * @param {string} delete_ A list of settings you want to delete.
  * @param {string} dest Restrict packet destination address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {string} dport Restrict TCP/UDP destination port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
  * @param {int} enable Flag to enable/disable a rule.
  * @param {string} icmp_type Specify icmp-type. Only valid if proto equals 'icmp'.
  * @param {string} iface Network interface name. You have to use network configuration key names for VMs and containers ('net\d+'). Host related rules can use arbitrary strings.
  * @param {string} log Log level for firewall rule.
  *   Enum: emerg,alert,crit,err,warning,notice,info,debug,nolog
  * @param {string} macro Use predefined standard macro.
  * @param {int} moveto Move rule to new position &amp;lt;moveto&amp;gt;. Other arguments are ignored.
  * @param {string} proto IP protocol. You can use protocol names ('tcp'/'udp') or simple numbers, as defined in '/etc/protocols'.
  * @param {string} source Restrict packet source address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
  * @param {string} sport Restrict TCP/UDP source port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
  * @param {string} type Rule type.
  *   Enum: in,out,group
  * @returns {Result}
  */
  async updateRule(action, comment, delete_, dest, digest, dport, enable, icmp_type, iface, log, macro, moveto, proto, source, sport, type) {
    const parameters = {
      'action': action,
      'comment': comment,
      'delete': delete_,
      'dest': dest,
      'digest': digest,
      'dport': dport,
      'enable': enable,
      'icmp-type': icmp_type,
      'iface': iface,
      'log': log,
      'macro': macro,
      'moveto': moveto,
      'proto': proto,
      'source': source,
      'sport': sport,
      'type': type
    };
    return await this.#client.set(`/cluster/firewall/rules/${this.#pos}`, parameters);
  }

}

/**
 * Class PVEFirewallClusterIpset
 */
class PVEFirewallClusterIpset {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }


  /**
   * Get ItemIpsetFirewallClusterName
   * @param name
   * @returns {PVEItemIpsetFirewallClusterName}
   */
  get(name) { return new PVEItemIpsetFirewallClusterName(this.#client, name); }

  /**
  * List IPSets
  * @returns {Result}
  */
  async ipsetIndex() {
    return await this.#client.get(`/cluster/firewall/ipset`);
  }
  /**
  * Create new IPSet
  * @param {string} name IP set name.
  * @param {string} comment
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {string} rename Rename an existing IPSet. You can set 'rename' to the same value as 'name' to update the 'comment' of an existing IPSet.
  * @returns {Result}
  */
  async createIpset(name, comment, digest, rename) {
    const parameters = {
      'name': name,
      'comment': comment,
      'digest': digest,
      'rename': rename
    };
    return await this.#client.create(`/cluster/firewall/ipset`, parameters);
  }

}
/**
 * Class PVEItemIpsetFirewallClusterName
 */
class PVEItemIpsetFirewallClusterName {
  #name;
  /** @type {PveClient} */
  #client;

  constructor(client, name) {
    this.#client = client;
    this.#name = name;
  }


  /**
   * Get ItemNameIpsetFirewallClusterCidr
   * @param cidr
   * @returns {PVEItemNameIpsetFirewallClusterCidr}
   */
  get(cidr) { return new PVEItemNameIpsetFirewallClusterCidr(this.#client, this.#name, cidr); }

  /**
  * Delete IPSet
  * @returns {Result}
  */
  async deleteIpset() {
    return await this.#client.delete(`/cluster/firewall/ipset/${this.#name}`);
  }
  /**
  * List IPSet content
  * @returns {Result}
  */
  async getIpset() {
    return await this.#client.get(`/cluster/firewall/ipset/${this.#name}`);
  }
  /**
  * Add IP or Network to IPSet.
  * @param {string} cidr Network/IP specification in CIDR format.
  * @param {string} comment
  * @param {bool} nomatch
  * @returns {Result}
  */
  async createIp(cidr, comment, nomatch) {
    const parameters = {
      'cidr': cidr,
      'comment': comment,
      'nomatch': nomatch
    };
    return await this.#client.create(`/cluster/firewall/ipset/${this.#name}`, parameters);
  }

}
/**
 * Class PVEItemNameIpsetFirewallClusterCidr
 */
class PVEItemNameIpsetFirewallClusterCidr {
  #name;
  #cidr;
  /** @type {PveClient} */
  #client;

  constructor(client, name, cidr) {
    this.#client = client;
    this.#name = name;
    this.#cidr = cidr;
  }



  /**
  * Remove IP or Network from IPSet.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @returns {Result}
  */
  async removeIp(digest) {
    const parameters = { 'digest': digest };
    return await this.#client.delete(`/cluster/firewall/ipset/${this.#name}/${this.#cidr}`, parameters);
  }
  /**
  * Read IP or Network settings from IPSet.
  * @returns {Result}
  */
  async readIp() {
    return await this.#client.get(`/cluster/firewall/ipset/${this.#name}/${this.#cidr}`);
  }
  /**
  * Update IP or Network settings
  * @param {string} comment
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {bool} nomatch
  * @returns {Result}
  */
  async updateIp(comment, digest, nomatch) {
    const parameters = {
      'comment': comment,
      'digest': digest,
      'nomatch': nomatch
    };
    return await this.#client.set(`/cluster/firewall/ipset/${this.#name}/${this.#cidr}`, parameters);
  }

}

/**
 * Class PVEFirewallClusterAliases
 */
class PVEFirewallClusterAliases {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }


  /**
   * Get ItemAliasesFirewallClusterName
   * @param name
   * @returns {PVEItemAliasesFirewallClusterName}
   */
  get(name) { return new PVEItemAliasesFirewallClusterName(this.#client, name); }

  /**
  * List aliases
  * @returns {Result}
  */
  async getAliases() {
    return await this.#client.get(`/cluster/firewall/aliases`);
  }
  /**
  * Create IP or Network Alias.
  * @param {string} cidr Network/IP specification in CIDR format.
  * @param {string} name Alias name.
  * @param {string} comment
  * @returns {Result}
  */
  async createAlias(cidr, name, comment) {
    const parameters = {
      'cidr': cidr,
      'name': name,
      'comment': comment
    };
    return await this.#client.create(`/cluster/firewall/aliases`, parameters);
  }

}
/**
 * Class PVEItemAliasesFirewallClusterName
 */
class PVEItemAliasesFirewallClusterName {
  #name;
  /** @type {PveClient} */
  #client;

  constructor(client, name) {
    this.#client = client;
    this.#name = name;
  }



  /**
  * Remove IP or Network alias.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @returns {Result}
  */
  async removeAlias(digest) {
    const parameters = { 'digest': digest };
    return await this.#client.delete(`/cluster/firewall/aliases/${this.#name}`, parameters);
  }
  /**
  * Read alias.
  * @returns {Result}
  */
  async readAlias() {
    return await this.#client.get(`/cluster/firewall/aliases/${this.#name}`);
  }
  /**
  * Update IP or Network alias.
  * @param {string} cidr Network/IP specification in CIDR format.
  * @param {string} comment
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {string} rename Rename an existing alias.
  * @returns {Result}
  */
  async updateAlias(cidr, comment, digest, rename) {
    const parameters = {
      'cidr': cidr,
      'comment': comment,
      'digest': digest,
      'rename': rename
    };
    return await this.#client.set(`/cluster/firewall/aliases/${this.#name}`, parameters);
  }

}

/**
 * Class PVEFirewallClusterOptions
 */
class PVEFirewallClusterOptions {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }



  /**
  * Get Firewall options.
  * @returns {Result}
  */
  async getOptions() {
    return await this.#client.get(`/cluster/firewall/options`);
  }
  /**
  * Set Firewall options.
  * @param {string} delete_ A list of settings you want to delete.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {bool} ebtables Enable ebtables rules cluster wide.
  * @param {int} enable Enable or disable the firewall cluster wide.
  * @param {string} log_ratelimit Log ratelimiting settings
  * @param {string} policy_in Input policy.
  *   Enum: ACCEPT,REJECT,DROP
  * @param {string} policy_out Output policy.
  *   Enum: ACCEPT,REJECT,DROP
  * @returns {Result}
  */
  async setOptions(delete_, digest, ebtables, enable, log_ratelimit, policy_in, policy_out) {
    const parameters = {
      'delete': delete_,
      'digest': digest,
      'ebtables': ebtables,
      'enable': enable,
      'log_ratelimit': log_ratelimit,
      'policy_in': policy_in,
      'policy_out': policy_out
    };
    return await this.#client.set(`/cluster/firewall/options`, parameters);
  }

}

/**
 * Class PVEFirewallClusterMacros
 */
class PVEFirewallClusterMacros {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }



  /**
  * List available macros
  * @returns {Result}
  */
  async getMacros() {
    return await this.#client.get(`/cluster/firewall/macros`);
  }

}

/**
 * Class PVEFirewallClusterRefs
 */
class PVEFirewallClusterRefs {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }



  /**
  * Lists possible IPSet/Alias reference which are allowed in source/dest properties.
  * @param {string} type Only list references of specified type.
  *   Enum: alias,ipset
  * @returns {Result}
  */
  async refs(type) {
    const parameters = { 'type': type };
    return await this.#client.get(`/cluster/firewall/refs`, parameters);
  }

}

/**
 * Class PVEClusterBackup
 */
class PVEClusterBackup {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }


  /**
   * Get ItemBackupClusterId
   * @param id
   * @returns {PVEItemBackupClusterId}
   */
  get(id) { return new PVEItemBackupClusterId(this.#client, id); }

  /**
  * List vzdump backup schedule.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/cluster/backup`);
  }
  /**
  * Create new vzdump backup job.
  * @param {bool} all Backup all known guest systems on this host.
  * @param {int} bwlimit Limit I/O bandwidth (KBytes per second).
  * @param {string} comment Description for the Job.
  * @param {string} compress Compress dump file.
  *   Enum: 0,1,gzip,lzo,zstd
  * @param {string} dow Day of week selection.
  * @param {string} dumpdir Store resulting files to specified directory.
  * @param {bool} enabled Enable or disable the job.
  * @param {string} exclude Exclude specified guest systems (assumes --all)
  * @param {string} exclude_path Exclude certain files/directories (shell globs). Paths starting with '/' are anchored to the container's root,  other paths match relative to each subdirectory.
  * @param {string} id Job ID (will be autogenerated).
  * @param {int} ionice Set CFQ ionice priority.
  * @param {int} lockwait Maximal time to wait for the global lock (minutes).
  * @param {string} mailnotification Specify when to send an email
  *   Enum: always,failure
  * @param {string} mailto Comma-separated list of email addresses or users that should receive email notifications.
  * @param {int} maxfiles Deprecated: use 'prune-backups' instead. Maximal number of backup files per guest system.
  * @param {string} mode Backup mode.
  *   Enum: snapshot,suspend,stop
  * @param {string} node Only run if executed on this node.
  * @param {int} pigz Use pigz instead of gzip when N&amp;gt;0. N=1 uses half of cores, N&amp;gt;1 uses N as thread count.
  * @param {string} pool Backup all known guest systems included in the specified pool.
  * @param {string} prune_backups Use these retention options instead of those from the storage configuration.
  * @param {bool} quiet Be quiet.
  * @param {bool} remove Prune older backups according to 'prune-backups'.
  * @param {string} schedule Backup schedule. The format is a subset of `systemd` calendar events.
  * @param {string} script Use specified hook script.
  * @param {string} starttime Job Start time.
  * @param {bool} stdexcludes Exclude temporary files and logs.
  * @param {bool} stop Stop running backup jobs on this host.
  * @param {int} stopwait Maximal time to wait until a guest system is stopped (minutes).
  * @param {string} storage Store resulting file to this storage.
  * @param {string} tmpdir Store temporary files to specified directory.
  * @param {string} vmid The ID of the guest system you want to backup.
  * @param {int} zstd Zstd threads. N=0 uses half of the available cores, N&amp;gt;0 uses N as thread count.
  * @returns {Result}
  */
  async createJob(all, bwlimit, comment, compress, dow, dumpdir, enabled, exclude, exclude_path, id, ionice, lockwait, mailnotification, mailto, maxfiles, mode, node, pigz, pool, prune_backups, quiet, remove, schedule, script, starttime, stdexcludes, stop, stopwait, storage, tmpdir, vmid, zstd) {
    const parameters = {
      'all': all,
      'bwlimit': bwlimit,
      'comment': comment,
      'compress': compress,
      'dow': dow,
      'dumpdir': dumpdir,
      'enabled': enabled,
      'exclude': exclude,
      'exclude-path': exclude_path,
      'id': id,
      'ionice': ionice,
      'lockwait': lockwait,
      'mailnotification': mailnotification,
      'mailto': mailto,
      'maxfiles': maxfiles,
      'mode': mode,
      'node': node,
      'pigz': pigz,
      'pool': pool,
      'prune-backups': prune_backups,
      'quiet': quiet,
      'remove': remove,
      'schedule': schedule,
      'script': script,
      'starttime': starttime,
      'stdexcludes': stdexcludes,
      'stop': stop,
      'stopwait': stopwait,
      'storage': storage,
      'tmpdir': tmpdir,
      'vmid': vmid,
      'zstd': zstd
    };
    return await this.#client.create(`/cluster/backup`, parameters);
  }

}
/**
 * Class PVEItemBackupClusterId
 */
class PVEItemBackupClusterId {
  #id;
  /** @type {PveClient} */
  #client;

  constructor(client, id) {
    this.#client = client;
    this.#id = id;
  }

  #includedVolumes;
  /**
   * Get IdBackupClusterIncludedVolumes
   * @returns {PVEIdBackupClusterIncludedVolumes}
   */
  get includedVolumes() { return this.#includedVolumes == null ? (this.#includedVolumes = new PVEIdBackupClusterIncludedVolumes(this.#client, this.#id)) : this.#includedVolumes; }


  /**
  * Delete vzdump backup job definition.
  * @returns {Result}
  */
  async deleteJob() {
    return await this.#client.delete(`/cluster/backup/${this.#id}`);
  }
  /**
  * Read vzdump backup job definition.
  * @returns {Result}
  */
  async readJob() {
    return await this.#client.get(`/cluster/backup/${this.#id}`);
  }
  /**
  * Update vzdump backup job definition.
  * @param {bool} all Backup all known guest systems on this host.
  * @param {int} bwlimit Limit I/O bandwidth (KBytes per second).
  * @param {string} comment Description for the Job.
  * @param {string} compress Compress dump file.
  *   Enum: 0,1,gzip,lzo,zstd
  * @param {string} delete_ A list of settings you want to delete.
  * @param {string} dow Day of week selection.
  * @param {string} dumpdir Store resulting files to specified directory.
  * @param {bool} enabled Enable or disable the job.
  * @param {string} exclude Exclude specified guest systems (assumes --all)
  * @param {string} exclude_path Exclude certain files/directories (shell globs). Paths starting with '/' are anchored to the container's root,  other paths match relative to each subdirectory.
  * @param {int} ionice Set CFQ ionice priority.
  * @param {int} lockwait Maximal time to wait for the global lock (minutes).
  * @param {string} mailnotification Specify when to send an email
  *   Enum: always,failure
  * @param {string} mailto Comma-separated list of email addresses or users that should receive email notifications.
  * @param {int} maxfiles Deprecated: use 'prune-backups' instead. Maximal number of backup files per guest system.
  * @param {string} mode Backup mode.
  *   Enum: snapshot,suspend,stop
  * @param {string} node Only run if executed on this node.
  * @param {int} pigz Use pigz instead of gzip when N&amp;gt;0. N=1 uses half of cores, N&amp;gt;1 uses N as thread count.
  * @param {string} pool Backup all known guest systems included in the specified pool.
  * @param {string} prune_backups Use these retention options instead of those from the storage configuration.
  * @param {bool} quiet Be quiet.
  * @param {bool} remove Prune older backups according to 'prune-backups'.
  * @param {string} schedule Backup schedule. The format is a subset of `systemd` calendar events.
  * @param {string} script Use specified hook script.
  * @param {string} starttime Job Start time.
  * @param {bool} stdexcludes Exclude temporary files and logs.
  * @param {bool} stop Stop running backup jobs on this host.
  * @param {int} stopwait Maximal time to wait until a guest system is stopped (minutes).
  * @param {string} storage Store resulting file to this storage.
  * @param {string} tmpdir Store temporary files to specified directory.
  * @param {string} vmid The ID of the guest system you want to backup.
  * @param {int} zstd Zstd threads. N=0 uses half of the available cores, N&amp;gt;0 uses N as thread count.
  * @returns {Result}
  */
  async updateJob(all, bwlimit, comment, compress, delete_, dow, dumpdir, enabled, exclude, exclude_path, ionice, lockwait, mailnotification, mailto, maxfiles, mode, node, pigz, pool, prune_backups, quiet, remove, schedule, script, starttime, stdexcludes, stop, stopwait, storage, tmpdir, vmid, zstd) {
    const parameters = {
      'all': all,
      'bwlimit': bwlimit,
      'comment': comment,
      'compress': compress,
      'delete': delete_,
      'dow': dow,
      'dumpdir': dumpdir,
      'enabled': enabled,
      'exclude': exclude,
      'exclude-path': exclude_path,
      'ionice': ionice,
      'lockwait': lockwait,
      'mailnotification': mailnotification,
      'mailto': mailto,
      'maxfiles': maxfiles,
      'mode': mode,
      'node': node,
      'pigz': pigz,
      'pool': pool,
      'prune-backups': prune_backups,
      'quiet': quiet,
      'remove': remove,
      'schedule': schedule,
      'script': script,
      'starttime': starttime,
      'stdexcludes': stdexcludes,
      'stop': stop,
      'stopwait': stopwait,
      'storage': storage,
      'tmpdir': tmpdir,
      'vmid': vmid,
      'zstd': zstd
    };
    return await this.#client.set(`/cluster/backup/${this.#id}`, parameters);
  }

}
/**
 * Class PVEIdBackupClusterIncludedVolumes
 */
class PVEIdBackupClusterIncludedVolumes {
  #id;
  /** @type {PveClient} */
  #client;

  constructor(client, id) {
    this.#client = client;
    this.#id = id;
  }



  /**
  * Returns included guests and the backup status of their disks. Optimized to be used in ExtJS tree views.
  * @returns {Result}
  */
  async getVolumeBackupIncluded() {
    return await this.#client.get(`/cluster/backup/${this.#id}/included_volumes`);
  }

}

/**
 * Class PVEClusterBackupInfo
 */
class PVEClusterBackupInfo {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }

  #notBackedUp;
  /**
   * Get BackupInfoClusterNotBackedUp
   * @returns {PVEBackupInfoClusterNotBackedUp}
   */
  get notBackedUp() { return this.#notBackedUp == null ? (this.#notBackedUp = new PVEBackupInfoClusterNotBackedUp(this.#client)) : this.#notBackedUp; }


  /**
  * Index for backup info related endpoints
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/cluster/backup-info`);
  }

}
/**
 * Class PVEBackupInfoClusterNotBackedUp
 */
class PVEBackupInfoClusterNotBackedUp {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }



  /**
  * Shows all guests which are not covered by any backup job.
  * @returns {Result}
  */
  async getGuestsNotInBackup() {
    return await this.#client.get(`/cluster/backup-info/not-backed-up`);
  }

}

/**
 * Class PVEClusterHa
 */
class PVEClusterHa {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }

  #resources;
  /**
   * Get HaClusterResources
   * @returns {PVEHaClusterResources}
   */
  get resources() { return this.#resources == null ? (this.#resources = new PVEHaClusterResources(this.#client)) : this.#resources; }
  #groups;
  /**
   * Get HaClusterGroups
   * @returns {PVEHaClusterGroups}
   */
  get groups() { return this.#groups == null ? (this.#groups = new PVEHaClusterGroups(this.#client)) : this.#groups; }
  #status;
  /**
   * Get HaClusterStatus
   * @returns {PVEHaClusterStatus}
   */
  get status() { return this.#status == null ? (this.#status = new PVEHaClusterStatus(this.#client)) : this.#status; }


  /**
  * Directory index.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/cluster/ha`);
  }

}
/**
 * Class PVEHaClusterResources
 */
class PVEHaClusterResources {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }


  /**
   * Get ItemResourcesHaClusterSid
   * @param sid
   * @returns {PVEItemResourcesHaClusterSid}
   */
  get(sid) { return new PVEItemResourcesHaClusterSid(this.#client, sid); }

  /**
  * List HA resources.
  * @param {string} type Only list resources of specific type
  *   Enum: ct,vm
  * @returns {Result}
  */
  async index(type) {
    const parameters = { 'type': type };
    return await this.#client.get(`/cluster/ha/resources`, parameters);
  }
  /**
  * Create a new HA resource.
  * @param {string} sid HA resource ID. This consists of a resource type followed by a resource specific name, separated with colon (example: vm:100 / ct:100). For virtual machines and containers, you can simply use the VM or CT id as a shortcut (example: 100).
  * @param {string} comment Description.
  * @param {string} group The HA group identifier.
  * @param {int} max_relocate Maximal number of service relocate tries when a service failes to start.
  * @param {int} max_restart Maximal number of tries to restart the service on a node after its start failed.
  * @param {string} state Requested resource state.
  *   Enum: started,stopped,enabled,disabled,ignored
  * @param {string} type Resource type.
  *   Enum: ct,vm
  * @returns {Result}
  */
  async create(sid, comment, group, max_relocate, max_restart, state, type) {
    const parameters = {
      'sid': sid,
      'comment': comment,
      'group': group,
      'max_relocate': max_relocate,
      'max_restart': max_restart,
      'state': state,
      'type': type
    };
    return await this.#client.create(`/cluster/ha/resources`, parameters);
  }

}
/**
 * Class PVEItemResourcesHaClusterSid
 */
class PVEItemResourcesHaClusterSid {
  #sid;
  /** @type {PveClient} */
  #client;

  constructor(client, sid) {
    this.#client = client;
    this.#sid = sid;
  }

  #migrate;
  /**
   * Get SidResourcesHaClusterMigrate
   * @returns {PVESidResourcesHaClusterMigrate}
   */
  get migrate() { return this.#migrate == null ? (this.#migrate = new PVESidResourcesHaClusterMigrate(this.#client, this.#sid)) : this.#migrate; }
  #relocate;
  /**
   * Get SidResourcesHaClusterRelocate
   * @returns {PVESidResourcesHaClusterRelocate}
   */
  get relocate() { return this.#relocate == null ? (this.#relocate = new PVESidResourcesHaClusterRelocate(this.#client, this.#sid)) : this.#relocate; }


  /**
  * Delete resource configuration.
  * @returns {Result}
  */
  async delete_() {
    return await this.#client.delete(`/cluster/ha/resources/${this.#sid}`);
  }
  /**
  * Read resource configuration.
  * @returns {Result}
  */
  async read() {
    return await this.#client.get(`/cluster/ha/resources/${this.#sid}`);
  }
  /**
  * Update resource configuration.
  * @param {string} comment Description.
  * @param {string} delete_ A list of settings you want to delete.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {string} group The HA group identifier.
  * @param {int} max_relocate Maximal number of service relocate tries when a service failes to start.
  * @param {int} max_restart Maximal number of tries to restart the service on a node after its start failed.
  * @param {string} state Requested resource state.
  *   Enum: started,stopped,enabled,disabled,ignored
  * @returns {Result}
  */
  async update(comment, delete_, digest, group, max_relocate, max_restart, state) {
    const parameters = {
      'comment': comment,
      'delete': delete_,
      'digest': digest,
      'group': group,
      'max_relocate': max_relocate,
      'max_restart': max_restart,
      'state': state
    };
    return await this.#client.set(`/cluster/ha/resources/${this.#sid}`, parameters);
  }

}
/**
 * Class PVESidResourcesHaClusterMigrate
 */
class PVESidResourcesHaClusterMigrate {
  #sid;
  /** @type {PveClient} */
  #client;

  constructor(client, sid) {
    this.#client = client;
    this.#sid = sid;
  }



  /**
  * Request resource migration (online) to another node.
  * @param {string} node Target node.
  * @returns {Result}
  */
  async migrate(node) {
    const parameters = { 'node': node };
    return await this.#client.create(`/cluster/ha/resources/${this.#sid}/migrate`, parameters);
  }

}

/**
 * Class PVESidResourcesHaClusterRelocate
 */
class PVESidResourcesHaClusterRelocate {
  #sid;
  /** @type {PveClient} */
  #client;

  constructor(client, sid) {
    this.#client = client;
    this.#sid = sid;
  }



  /**
  * Request resource relocatzion to another node. This stops the service on the old node, and restarts it on the target node.
  * @param {string} node Target node.
  * @returns {Result}
  */
  async relocate(node) {
    const parameters = { 'node': node };
    return await this.#client.create(`/cluster/ha/resources/${this.#sid}/relocate`, parameters);
  }

}

/**
 * Class PVEHaClusterGroups
 */
class PVEHaClusterGroups {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }


  /**
   * Get ItemGroupsHaClusterGroup
   * @param group
   * @returns {PVEItemGroupsHaClusterGroup}
   */
  get(group) { return new PVEItemGroupsHaClusterGroup(this.#client, group); }

  /**
  * Get HA groups.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/cluster/ha/groups`);
  }
  /**
  * Create a new HA group.
  * @param {string} group The HA group identifier.
  * @param {string} nodes List of cluster node names with optional priority.
  * @param {string} comment Description.
  * @param {bool} nofailback The CRM tries to run services on the node with the highest priority. If a node with higher priority comes online, the CRM migrates the service to that node. Enabling nofailback prevents that behavior.
  * @param {bool} restricted Resources bound to restricted groups may only run on nodes defined by the group.
  * @param {string} type Group type.
  *   Enum: group
  * @returns {Result}
  */
  async create(group, nodes, comment, nofailback, restricted, type) {
    const parameters = {
      'group': group,
      'nodes': nodes,
      'comment': comment,
      'nofailback': nofailback,
      'restricted': restricted,
      'type': type
    };
    return await this.#client.create(`/cluster/ha/groups`, parameters);
  }

}
/**
 * Class PVEItemGroupsHaClusterGroup
 */
class PVEItemGroupsHaClusterGroup {
  #group;
  /** @type {PveClient} */
  #client;

  constructor(client, group) {
    this.#client = client;
    this.#group = group;
  }



  /**
  * Delete ha group configuration.
  * @returns {Result}
  */
  async delete_() {
    return await this.#client.delete(`/cluster/ha/groups/${this.#group}`);
  }
  /**
  * Read ha group configuration.
  * @returns {Result}
  */
  async read() {
    return await this.#client.get(`/cluster/ha/groups/${this.#group}`);
  }
  /**
  * Update ha group configuration.
  * @param {string} comment Description.
  * @param {string} delete_ A list of settings you want to delete.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {string} nodes List of cluster node names with optional priority.
  * @param {bool} nofailback The CRM tries to run services on the node with the highest priority. If a node with higher priority comes online, the CRM migrates the service to that node. Enabling nofailback prevents that behavior.
  * @param {bool} restricted Resources bound to restricted groups may only run on nodes defined by the group.
  * @returns {Result}
  */
  async update(comment, delete_, digest, nodes, nofailback, restricted) {
    const parameters = {
      'comment': comment,
      'delete': delete_,
      'digest': digest,
      'nodes': nodes,
      'nofailback': nofailback,
      'restricted': restricted
    };
    return await this.#client.set(`/cluster/ha/groups/${this.#group}`, parameters);
  }

}

/**
 * Class PVEHaClusterStatus
 */
class PVEHaClusterStatus {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }

  #current;
  /**
   * Get StatusHaClusterCurrent
   * @returns {PVEStatusHaClusterCurrent}
   */
  get current() { return this.#current == null ? (this.#current = new PVEStatusHaClusterCurrent(this.#client)) : this.#current; }
  #managerStatus;
  /**
   * Get StatusHaClusterManagerStatus
   * @returns {PVEStatusHaClusterManagerStatus}
   */
  get managerStatus() { return this.#managerStatus == null ? (this.#managerStatus = new PVEStatusHaClusterManagerStatus(this.#client)) : this.#managerStatus; }


  /**
  * Directory index.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/cluster/ha/status`);
  }

}
/**
 * Class PVEStatusHaClusterCurrent
 */
class PVEStatusHaClusterCurrent {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }



  /**
  * Get HA manger status.
  * @returns {Result}
  */
  async status() {
    return await this.#client.get(`/cluster/ha/status/current`);
  }

}

/**
 * Class PVEStatusHaClusterManagerStatus
 */
class PVEStatusHaClusterManagerStatus {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }



  /**
  * Get full HA manger status, including LRM status.
  * @returns {Result}
  */
  async managerStatus() {
    return await this.#client.get(`/cluster/ha/status/manager_status`);
  }

}

/**
 * Class PVEClusterAcme
 */
class PVEClusterAcme {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }

  #plugins;
  /**
   * Get AcmeClusterPlugins
   * @returns {PVEAcmeClusterPlugins}
   */
  get plugins() { return this.#plugins == null ? (this.#plugins = new PVEAcmeClusterPlugins(this.#client)) : this.#plugins; }
  #account;
  /**
   * Get AcmeClusterAccount
   * @returns {PVEAcmeClusterAccount}
   */
  get account() { return this.#account == null ? (this.#account = new PVEAcmeClusterAccount(this.#client)) : this.#account; }
  #tos;
  /**
   * Get AcmeClusterTos
   * @returns {PVEAcmeClusterTos}
   */
  get tos() { return this.#tos == null ? (this.#tos = new PVEAcmeClusterTos(this.#client)) : this.#tos; }
  #directories;
  /**
   * Get AcmeClusterDirectories
   * @returns {PVEAcmeClusterDirectories}
   */
  get directories() { return this.#directories == null ? (this.#directories = new PVEAcmeClusterDirectories(this.#client)) : this.#directories; }
  #challengeSchema;
  /**
   * Get AcmeClusterChallengeSchema
   * @returns {PVEAcmeClusterChallengeSchema}
   */
  get challengeSchema() { return this.#challengeSchema == null ? (this.#challengeSchema = new PVEAcmeClusterChallengeSchema(this.#client)) : this.#challengeSchema; }


  /**
  * ACMEAccount index.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/cluster/acme`);
  }

}
/**
 * Class PVEAcmeClusterPlugins
 */
class PVEAcmeClusterPlugins {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }


  /**
   * Get ItemPluginsAcmeClusterId
   * @param id
   * @returns {PVEItemPluginsAcmeClusterId}
   */
  get(id) { return new PVEItemPluginsAcmeClusterId(this.#client, id); }

  /**
  * ACME plugin index.
  * @param {string} type Only list ACME plugins of a specific type
  *   Enum: dns,standalone
  * @returns {Result}
  */
  async index(type) {
    const parameters = { 'type': type };
    return await this.#client.get(`/cluster/acme/plugins`, parameters);
  }
  /**
  * Add ACME plugin configuration.
  * @param {string} id ACME Plugin ID name
  * @param {string} type ACME challenge type.
  *   Enum: dns,standalone
  * @param {string} api API plugin name
  *   Enum: 1984hosting,acmedns,acmeproxy,active24,ad,ali,anx,arvan,aurora,autodns,aws,azion,azure,cf,clouddns,cloudns,cn,conoha,constellix,cx,cyon,da,ddnss,desec,df,dgon,dnsimple,do,doapi,domeneshop,dp,dpi,dreamhost,duckdns,durabledns,dyn,dynu,dynv6,easydns,edgedns,euserv,exoscale,freedns,gandi_livedns,gcloud,gd,gdnsdk,he,hetzner,hexonet,hostingde,huaweicloud,infoblox,infomaniak,internetbs,inwx,ionos,ispconfig,jd,joker,kappernet,kas,kinghost,knot,leaseweb,lexicon,linode,linode_v4,loopia,lua,maradns,me,miab,misaka,myapi,mydevil,mydnsjp,namecheap,namecom,namesilo,nederhost,neodigit,netcup,netlify,nic,njalla,nm,nsd,nsone,nsupdate,nw,oci,one,online,openprovider,openstack,opnsense,ovh,pdns,pleskxml,pointhq,porkbun,rackcorp,rackspace,rcode0,regru,scaleway,schlundtech,selectel,servercow,simply,tele3,transip,ultra,unoeuro,variomedia,veesp,vscale,vultr,websupport,world4you,yandex,zilore,zone,zonomi
  * @param {string} data DNS plugin data. (base64 encoded)
  * @param {bool} disable Flag to disable the config.
  * @param {string} nodes List of cluster node names.
  * @param {int} validation_delay Extra delay in seconds to wait before requesting validation. Allows to cope with a long TTL of DNS records.
  * @returns {Result}
  */
  async addPlugin(id, type, api, data, disable, nodes, validation_delay) {
    const parameters = {
      'id': id,
      'type': type,
      'api': api,
      'data': data,
      'disable': disable,
      'nodes': nodes,
      'validation-delay': validation_delay
    };
    return await this.#client.create(`/cluster/acme/plugins`, parameters);
  }

}
/**
 * Class PVEItemPluginsAcmeClusterId
 */
class PVEItemPluginsAcmeClusterId {
  #id;
  /** @type {PveClient} */
  #client;

  constructor(client, id) {
    this.#client = client;
    this.#id = id;
  }



  /**
  * Delete ACME plugin configuration.
  * @returns {Result}
  */
  async deletePlugin() {
    return await this.#client.delete(`/cluster/acme/plugins/${this.#id}`);
  }
  /**
  * Get ACME plugin configuration.
  * @returns {Result}
  */
  async getPluginConfig() {
    return await this.#client.get(`/cluster/acme/plugins/${this.#id}`);
  }
  /**
  * Update ACME plugin configuration.
  * @param {string} api API plugin name
  *   Enum: 1984hosting,acmedns,acmeproxy,active24,ad,ali,anx,arvan,aurora,autodns,aws,azion,azure,cf,clouddns,cloudns,cn,conoha,constellix,cx,cyon,da,ddnss,desec,df,dgon,dnsimple,do,doapi,domeneshop,dp,dpi,dreamhost,duckdns,durabledns,dyn,dynu,dynv6,easydns,edgedns,euserv,exoscale,freedns,gandi_livedns,gcloud,gd,gdnsdk,he,hetzner,hexonet,hostingde,huaweicloud,infoblox,infomaniak,internetbs,inwx,ionos,ispconfig,jd,joker,kappernet,kas,kinghost,knot,leaseweb,lexicon,linode,linode_v4,loopia,lua,maradns,me,miab,misaka,myapi,mydevil,mydnsjp,namecheap,namecom,namesilo,nederhost,neodigit,netcup,netlify,nic,njalla,nm,nsd,nsone,nsupdate,nw,oci,one,online,openprovider,openstack,opnsense,ovh,pdns,pleskxml,pointhq,porkbun,rackcorp,rackspace,rcode0,regru,scaleway,schlundtech,selectel,servercow,simply,tele3,transip,ultra,unoeuro,variomedia,veesp,vscale,vultr,websupport,world4you,yandex,zilore,zone,zonomi
  * @param {string} data DNS plugin data. (base64 encoded)
  * @param {string} delete_ A list of settings you want to delete.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {bool} disable Flag to disable the config.
  * @param {string} nodes List of cluster node names.
  * @param {int} validation_delay Extra delay in seconds to wait before requesting validation. Allows to cope with a long TTL of DNS records.
  * @returns {Result}
  */
  async updatePlugin(api, data, delete_, digest, disable, nodes, validation_delay) {
    const parameters = {
      'api': api,
      'data': data,
      'delete': delete_,
      'digest': digest,
      'disable': disable,
      'nodes': nodes,
      'validation-delay': validation_delay
    };
    return await this.#client.set(`/cluster/acme/plugins/${this.#id}`, parameters);
  }

}

/**
 * Class PVEAcmeClusterAccount
 */
class PVEAcmeClusterAccount {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }


  /**
   * Get ItemAccountAcmeClusterName
   * @param name
   * @returns {PVEItemAccountAcmeClusterName}
   */
  get(name) { return new PVEItemAccountAcmeClusterName(this.#client, name); }

  /**
  * ACMEAccount index.
  * @returns {Result}
  */
  async accountIndex() {
    return await this.#client.get(`/cluster/acme/account`);
  }
  /**
  * Register a new ACME account with CA.
  * @param {string} contact Contact email addresses.
  * @param {string} directory URL of ACME CA directory endpoint.
  * @param {string} name ACME account config file name.
  * @param {string} tos_url URL of CA TermsOfService - setting this indicates agreement.
  * @returns {Result}
  */
  async registerAccount(contact, directory, name, tos_url) {
    const parameters = {
      'contact': contact,
      'directory': directory,
      'name': name,
      'tos_url': tos_url
    };
    return await this.#client.create(`/cluster/acme/account`, parameters);
  }

}
/**
 * Class PVEItemAccountAcmeClusterName
 */
class PVEItemAccountAcmeClusterName {
  #name;
  /** @type {PveClient} */
  #client;

  constructor(client, name) {
    this.#client = client;
    this.#name = name;
  }



  /**
  * Deactivate existing ACME account at CA.
  * @returns {Result}
  */
  async deactivateAccount() {
    return await this.#client.delete(`/cluster/acme/account/${this.#name}`);
  }
  /**
  * Return existing ACME account information.
  * @returns {Result}
  */
  async getAccount() {
    return await this.#client.get(`/cluster/acme/account/${this.#name}`);
  }
  /**
  * Update existing ACME account information with CA. Note: not specifying any new account information triggers a refresh.
  * @param {string} contact Contact email addresses.
  * @returns {Result}
  */
  async updateAccount(contact) {
    const parameters = { 'contact': contact };
    return await this.#client.set(`/cluster/acme/account/${this.#name}`, parameters);
  }

}

/**
 * Class PVEAcmeClusterTos
 */
class PVEAcmeClusterTos {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }



  /**
  * Retrieve ACME TermsOfService URL from CA.
  * @param {string} directory URL of ACME CA directory endpoint.
  * @returns {Result}
  */
  async getTos(directory) {
    const parameters = { 'directory': directory };
    return await this.#client.get(`/cluster/acme/tos`, parameters);
  }

}

/**
 * Class PVEAcmeClusterDirectories
 */
class PVEAcmeClusterDirectories {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }



  /**
  * Get named known ACME directory endpoints.
  * @returns {Result}
  */
  async getDirectories() {
    return await this.#client.get(`/cluster/acme/directories`);
  }

}

/**
 * Class PVEAcmeClusterChallengeSchema
 */
class PVEAcmeClusterChallengeSchema {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }



  /**
  * Get schema of ACME challenge types.
  * @returns {Result}
  */
  async challengeschema() {
    return await this.#client.get(`/cluster/acme/challenge-schema`);
  }

}

/**
 * Class PVEClusterCeph
 */
class PVEClusterCeph {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }

  #metadata;
  /**
   * Get CephClusterMetadata
   * @returns {PVECephClusterMetadata}
   */
  get metadata() { return this.#metadata == null ? (this.#metadata = new PVECephClusterMetadata(this.#client)) : this.#metadata; }
  #status;
  /**
   * Get CephClusterStatus
   * @returns {PVECephClusterStatus}
   */
  get status() { return this.#status == null ? (this.#status = new PVECephClusterStatus(this.#client)) : this.#status; }
  #flags;
  /**
   * Get CephClusterFlags
   * @returns {PVECephClusterFlags}
   */
  get flags() { return this.#flags == null ? (this.#flags = new PVECephClusterFlags(this.#client)) : this.#flags; }


  /**
  * Cluster ceph index.
  * @returns {Result}
  */
  async cephindex() {
    return await this.#client.get(`/cluster/ceph`);
  }

}
/**
 * Class PVECephClusterMetadata
 */
class PVECephClusterMetadata {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }



  /**
  * Get ceph metadata.
  * @param {string} scope
  *   Enum: all,versions
  * @returns {Result}
  */
  async metadata(scope) {
    const parameters = { 'scope': scope };
    return await this.#client.get(`/cluster/ceph/metadata`, parameters);
  }

}

/**
 * Class PVECephClusterStatus
 */
class PVECephClusterStatus {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }



  /**
  * Get ceph status.
  * @returns {Result}
  */
  async status() {
    return await this.#client.get(`/cluster/ceph/status`);
  }

}

/**
 * Class PVECephClusterFlags
 */
class PVECephClusterFlags {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }


  /**
   * Get ItemFlagsCephClusterFlag
   * @param flag
   * @returns {PVEItemFlagsCephClusterFlag}
   */
  get(flag) { return new PVEItemFlagsCephClusterFlag(this.#client, flag); }

  /**
  * get the status of all ceph flags
  * @returns {Result}
  */
  async getAllFlags() {
    return await this.#client.get(`/cluster/ceph/flags`);
  }
  /**
  * Set/Unset multiple ceph flags at once.
  * @param {bool} nobackfill Backfilling of PGs is suspended.
  * @param {bool} nodeep_scrub Deep Scrubbing is disabled.
  * @param {bool} nodown OSD failure reports are being ignored, such that the monitors will not mark OSDs down.
  * @param {bool} noin OSDs that were previously marked out will not be marked back in when they start.
  * @param {bool} noout OSDs will not automatically be marked out after the configured interval.
  * @param {bool} norebalance Rebalancing of PGs is suspended.
  * @param {bool} norecover Recovery of PGs is suspended.
  * @param {bool} noscrub Scrubbing is disabled.
  * @param {bool} notieragent Cache tiering activity is suspended.
  * @param {bool} noup OSDs are not allowed to start.
  * @param {bool} pause Pauses read and writes.
  * @returns {Result}
  */
  async setFlags(nobackfill, nodeep_scrub, nodown, noin, noout, norebalance, norecover, noscrub, notieragent, noup, pause) {
    const parameters = {
      'nobackfill': nobackfill,
      'nodeep-scrub': nodeep_scrub,
      'nodown': nodown,
      'noin': noin,
      'noout': noout,
      'norebalance': norebalance,
      'norecover': norecover,
      'noscrub': noscrub,
      'notieragent': notieragent,
      'noup': noup,
      'pause': pause
    };
    return await this.#client.set(`/cluster/ceph/flags`, parameters);
  }

}
/**
 * Class PVEItemFlagsCephClusterFlag
 */
class PVEItemFlagsCephClusterFlag {
  #flag;
  /** @type {PveClient} */
  #client;

  constructor(client, flag) {
    this.#client = client;
    this.#flag = flag;
  }



  /**
  * Get the status of a specific ceph flag.
  * @returns {Result}
  */
  async getFlag() {
    return await this.#client.get(`/cluster/ceph/flags/${this.#flag}`);
  }
  /**
  * Set or clear (unset) a specific ceph flag
  * @param {bool} value The new value of the flag
  * @returns {Result}
  */
  async updateFlag(value) {
    const parameters = { 'value': value };
    return await this.#client.set(`/cluster/ceph/flags/${this.#flag}`, parameters);
  }

}

/**
 * Class PVEClusterJobs
 */
class PVEClusterJobs {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }

  #scheduleAnalyze;
  /**
   * Get JobsClusterScheduleAnalyze
   * @returns {PVEJobsClusterScheduleAnalyze}
   */
  get scheduleAnalyze() { return this.#scheduleAnalyze == null ? (this.#scheduleAnalyze = new PVEJobsClusterScheduleAnalyze(this.#client)) : this.#scheduleAnalyze; }


  /**
  * Index for jobs related endpoints.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/cluster/jobs`);
  }

}
/**
 * Class PVEJobsClusterScheduleAnalyze
 */
class PVEJobsClusterScheduleAnalyze {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }



  /**
  * Returns a list of future schedule runtimes.
  * @param {string} schedule Job schedule. The format is a subset of `systemd` calendar events.
  * @param {int} iterations Number of event-iteration to simulate and return.
  * @param {int} starttime UNIX timestamp to start the calculation from. Defaults to the current time.
  * @returns {Result}
  */
  async scheduleAnalyze(schedule, iterations, starttime) {
    const parameters = {
      'schedule': schedule,
      'iterations': iterations,
      'starttime': starttime
    };
    return await this.#client.get(`/cluster/jobs/schedule-analyze`, parameters);
  }

}

/**
 * Class PVEClusterSdn
 */
class PVEClusterSdn {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }

  #vnets;
  /**
   * Get SdnClusterVnets
   * @returns {PVESdnClusterVnets}
   */
  get vnets() { return this.#vnets == null ? (this.#vnets = new PVESdnClusterVnets(this.#client)) : this.#vnets; }
  #zones;
  /**
   * Get SdnClusterZones
   * @returns {PVESdnClusterZones}
   */
  get zones() { return this.#zones == null ? (this.#zones = new PVESdnClusterZones(this.#client)) : this.#zones; }
  #controllers;
  /**
   * Get SdnClusterControllers
   * @returns {PVESdnClusterControllers}
   */
  get controllers() { return this.#controllers == null ? (this.#controllers = new PVESdnClusterControllers(this.#client)) : this.#controllers; }
  #ipams;
  /**
   * Get SdnClusterIpams
   * @returns {PVESdnClusterIpams}
   */
  get ipams() { return this.#ipams == null ? (this.#ipams = new PVESdnClusterIpams(this.#client)) : this.#ipams; }
  #dns;
  /**
   * Get SdnClusterDns
   * @returns {PVESdnClusterDns}
   */
  get dns() { return this.#dns == null ? (this.#dns = new PVESdnClusterDns(this.#client)) : this.#dns; }


  /**
  * Directory index.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/cluster/sdn`);
  }
  /**
  * Apply sdn controller changes &amp;&amp; reload.
  * @returns {Result}
  */
  async reload() {
    return await this.#client.set(`/cluster/sdn`);
  }

}
/**
 * Class PVESdnClusterVnets
 */
class PVESdnClusterVnets {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }


  /**
   * Get ItemVnetsSdnClusterVnet
   * @param vnet
   * @returns {PVEItemVnetsSdnClusterVnet}
   */
  get(vnet) { return new PVEItemVnetsSdnClusterVnet(this.#client, vnet); }

  /**
  * SDN vnets index.
  * @param {bool} pending Display pending config.
  * @param {bool} running Display running config.
  * @returns {Result}
  */
  async index(pending, running) {
    const parameters = {
      'pending': pending,
      'running': running
    };
    return await this.#client.get(`/cluster/sdn/vnets`, parameters);
  }
  /**
  * Create a new sdn vnet object.
  * @param {string} vnet The SDN vnet object identifier.
  * @param {string} zone zone id
  * @param {string} alias alias name of the vnet
  * @param {int} tag vlan or vxlan id
  * @param {string} type Type
  *   Enum: vnet
  * @param {bool} vlanaware Allow vm VLANs to pass through this vnet.
  * @returns {Result}
  */
  async create(vnet, zone, alias, tag, type, vlanaware) {
    const parameters = {
      'vnet': vnet,
      'zone': zone,
      'alias': alias,
      'tag': tag,
      'type': type,
      'vlanaware': vlanaware
    };
    return await this.#client.create(`/cluster/sdn/vnets`, parameters);
  }

}
/**
 * Class PVEItemVnetsSdnClusterVnet
 */
class PVEItemVnetsSdnClusterVnet {
  #vnet;
  /** @type {PveClient} */
  #client;

  constructor(client, vnet) {
    this.#client = client;
    this.#vnet = vnet;
  }

  #subnets;
  /**
   * Get VnetVnetsSdnClusterSubnets
   * @returns {PVEVnetVnetsSdnClusterSubnets}
   */
  get subnets() { return this.#subnets == null ? (this.#subnets = new PVEVnetVnetsSdnClusterSubnets(this.#client, this.#vnet)) : this.#subnets; }


  /**
  * Delete sdn vnet object configuration.
  * @returns {Result}
  */
  async delete_() {
    return await this.#client.delete(`/cluster/sdn/vnets/${this.#vnet}`);
  }
  /**
  * Read sdn vnet configuration.
  * @param {bool} pending Display pending config.
  * @param {bool} running Display running config.
  * @returns {Result}
  */
  async read(pending, running) {
    const parameters = {
      'pending': pending,
      'running': running
    };
    return await this.#client.get(`/cluster/sdn/vnets/${this.#vnet}`, parameters);
  }
  /**
  * Update sdn vnet object configuration.
  * @param {string} alias alias name of the vnet
  * @param {string} delete_ A list of settings you want to delete.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {int} tag vlan or vxlan id
  * @param {bool} vlanaware Allow vm VLANs to pass through this vnet.
  * @param {string} zone zone id
  * @returns {Result}
  */
  async update(alias, delete_, digest, tag, vlanaware, zone) {
    const parameters = {
      'alias': alias,
      'delete': delete_,
      'digest': digest,
      'tag': tag,
      'vlanaware': vlanaware,
      'zone': zone
    };
    return await this.#client.set(`/cluster/sdn/vnets/${this.#vnet}`, parameters);
  }

}
/**
 * Class PVEVnetVnetsSdnClusterSubnets
 */
class PVEVnetVnetsSdnClusterSubnets {
  #vnet;
  /** @type {PveClient} */
  #client;

  constructor(client, vnet) {
    this.#client = client;
    this.#vnet = vnet;
  }


  /**
   * Get ItemSubnetsVnetVnetsSdnClusterSubnet
   * @param subnet
   * @returns {PVEItemSubnetsVnetVnetsSdnClusterSubnet}
   */
  get(subnet) { return new PVEItemSubnetsVnetVnetsSdnClusterSubnet(this.#client, this.#vnet, subnet); }

  /**
  * SDN subnets index.
  * @param {bool} pending Display pending config.
  * @param {bool} running Display running config.
  * @returns {Result}
  */
  async index(pending, running) {
    const parameters = {
      'pending': pending,
      'running': running
    };
    return await this.#client.get(`/cluster/sdn/vnets/${this.#vnet}/subnets`, parameters);
  }
  /**
  * Create a new sdn subnet object.
  * @param {string} subnet The SDN subnet object identifier.
  * @param {string} type
  *   Enum: subnet
  * @param {string} dnszoneprefix dns domain zone prefix  ex: 'adm' -&amp;gt; &amp;lt;hostname&amp;gt;.adm.mydomain.com
  * @param {string} gateway Subnet Gateway: Will be assign on vnet for layer3 zones
  * @param {bool} snat enable masquerade for this subnet if pve-firewall
  * @returns {Result}
  */
  async create(subnet, type, dnszoneprefix, gateway, snat) {
    const parameters = {
      'subnet': subnet,
      'type': type,
      'dnszoneprefix': dnszoneprefix,
      'gateway': gateway,
      'snat': snat
    };
    return await this.#client.create(`/cluster/sdn/vnets/${this.#vnet}/subnets`, parameters);
  }

}
/**
 * Class PVEItemSubnetsVnetVnetsSdnClusterSubnet
 */
class PVEItemSubnetsVnetVnetsSdnClusterSubnet {
  #vnet;
  #subnet;
  /** @type {PveClient} */
  #client;

  constructor(client, vnet, subnet) {
    this.#client = client;
    this.#vnet = vnet;
    this.#subnet = subnet;
  }



  /**
  * Delete sdn subnet object configuration.
  * @returns {Result}
  */
  async delete_() {
    return await this.#client.delete(`/cluster/sdn/vnets/${this.#vnet}/subnets/${this.#subnet}`);
  }
  /**
  * Read sdn subnet configuration.
  * @param {bool} pending Display pending config.
  * @param {bool} running Display running config.
  * @returns {Result}
  */
  async read(pending, running) {
    const parameters = {
      'pending': pending,
      'running': running
    };
    return await this.#client.get(`/cluster/sdn/vnets/${this.#vnet}/subnets/${this.#subnet}`, parameters);
  }
  /**
  * Update sdn subnet object configuration.
  * @param {string} delete_ A list of settings you want to delete.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {string} dnszoneprefix dns domain zone prefix  ex: 'adm' -&amp;gt; &amp;lt;hostname&amp;gt;.adm.mydomain.com
  * @param {string} gateway Subnet Gateway: Will be assign on vnet for layer3 zones
  * @param {bool} snat enable masquerade for this subnet if pve-firewall
  * @returns {Result}
  */
  async update(delete_, digest, dnszoneprefix, gateway, snat) {
    const parameters = {
      'delete': delete_,
      'digest': digest,
      'dnszoneprefix': dnszoneprefix,
      'gateway': gateway,
      'snat': snat
    };
    return await this.#client.set(`/cluster/sdn/vnets/${this.#vnet}/subnets/${this.#subnet}`, parameters);
  }

}

/**
 * Class PVESdnClusterZones
 */
class PVESdnClusterZones {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }


  /**
   * Get ItemZonesSdnClusterZone
   * @param zone
   * @returns {PVEItemZonesSdnClusterZone}
   */
  get(zone) { return new PVEItemZonesSdnClusterZone(this.#client, zone); }

  /**
  * SDN zones index.
  * @param {bool} pending Display pending config.
  * @param {bool} running Display running config.
  * @param {string} type Only list SDN zones of specific type
  *   Enum: evpn,faucet,qinq,simple,vlan,vxlan
  * @returns {Result}
  */
  async index(pending, running, type) {
    const parameters = {
      'pending': pending,
      'running': running,
      'type': type
    };
    return await this.#client.get(`/cluster/sdn/zones`, parameters);
  }
  /**
  * Create a new sdn zone object.
  * @param {string} type Plugin type.
  *   Enum: evpn,faucet,qinq,simple,vlan,vxlan
  * @param {string} zone The SDN zone object identifier.
  * @param {bool} advertise_subnets Advertise evpn subnets if you have silent hosts
  * @param {string} bridge
  * @param {string} controller Frr router name
  * @param {bool} disable_arp_nd_suppression Disable ipv4 arp &amp;&amp; ipv6 neighbour discovery suppression
  * @param {string} dns dns api server
  * @param {string} dnszone dns domain zone  ex: mydomain.com
  * @param {int} dp_id Faucet dataplane id
  * @param {string} exitnodes List of cluster node names.
  * @param {bool} exitnodes_local_routing Allow exitnodes to connect to evpn guests
  * @param {string} ipam use a specific ipam
  * @param {string} mac Anycast logical router mac address
  * @param {int} mtu MTU
  * @param {string} nodes List of cluster node names.
  * @param {string} peers peers address list.
  * @param {string} reversedns reverse dns api server
  * @param {int} tag Service-VLAN Tag
  * @param {string} vlan_protocol
  *   Enum: 802.1q,802.1ad
  * @param {int} vrf_vxlan l3vni.
  * @returns {Result}
  */
  async create(type, zone, advertise_subnets, bridge, controller, disable_arp_nd_suppression, dns, dnszone, dp_id, exitnodes, exitnodes_local_routing, ipam, mac, mtu, nodes, peers, reversedns, tag, vlan_protocol, vrf_vxlan) {
    const parameters = {
      'type': type,
      'zone': zone,
      'advertise-subnets': advertise_subnets,
      'bridge': bridge,
      'controller': controller,
      'disable-arp-nd-suppression': disable_arp_nd_suppression,
      'dns': dns,
      'dnszone': dnszone,
      'dp-id': dp_id,
      'exitnodes': exitnodes,
      'exitnodes-local-routing': exitnodes_local_routing,
      'ipam': ipam,
      'mac': mac,
      'mtu': mtu,
      'nodes': nodes,
      'peers': peers,
      'reversedns': reversedns,
      'tag': tag,
      'vlan-protocol': vlan_protocol,
      'vrf-vxlan': vrf_vxlan
    };
    return await this.#client.create(`/cluster/sdn/zones`, parameters);
  }

}
/**
 * Class PVEItemZonesSdnClusterZone
 */
class PVEItemZonesSdnClusterZone {
  #zone;
  /** @type {PveClient} */
  #client;

  constructor(client, zone) {
    this.#client = client;
    this.#zone = zone;
  }



  /**
  * Delete sdn zone object configuration.
  * @returns {Result}
  */
  async delete_() {
    return await this.#client.delete(`/cluster/sdn/zones/${this.#zone}`);
  }
  /**
  * Read sdn zone configuration.
  * @param {bool} pending Display pending config.
  * @param {bool} running Display running config.
  * @returns {Result}
  */
  async read(pending, running) {
    const parameters = {
      'pending': pending,
      'running': running
    };
    return await this.#client.get(`/cluster/sdn/zones/${this.#zone}`, parameters);
  }
  /**
  * Update sdn zone object configuration.
  * @param {bool} advertise_subnets Advertise evpn subnets if you have silent hosts
  * @param {string} bridge
  * @param {string} controller Frr router name
  * @param {string} delete_ A list of settings you want to delete.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {bool} disable_arp_nd_suppression Disable ipv4 arp &amp;&amp; ipv6 neighbour discovery suppression
  * @param {string} dns dns api server
  * @param {string} dnszone dns domain zone  ex: mydomain.com
  * @param {int} dp_id Faucet dataplane id
  * @param {string} exitnodes List of cluster node names.
  * @param {bool} exitnodes_local_routing Allow exitnodes to connect to evpn guests
  * @param {string} ipam use a specific ipam
  * @param {string} mac Anycast logical router mac address
  * @param {int} mtu MTU
  * @param {string} nodes List of cluster node names.
  * @param {string} peers peers address list.
  * @param {string} reversedns reverse dns api server
  * @param {int} tag Service-VLAN Tag
  * @param {string} vlan_protocol
  *   Enum: 802.1q,802.1ad
  * @param {int} vrf_vxlan l3vni.
  * @returns {Result}
  */
  async update(advertise_subnets, bridge, controller, delete_, digest, disable_arp_nd_suppression, dns, dnszone, dp_id, exitnodes, exitnodes_local_routing, ipam, mac, mtu, nodes, peers, reversedns, tag, vlan_protocol, vrf_vxlan) {
    const parameters = {
      'advertise-subnets': advertise_subnets,
      'bridge': bridge,
      'controller': controller,
      'delete': delete_,
      'digest': digest,
      'disable-arp-nd-suppression': disable_arp_nd_suppression,
      'dns': dns,
      'dnszone': dnszone,
      'dp-id': dp_id,
      'exitnodes': exitnodes,
      'exitnodes-local-routing': exitnodes_local_routing,
      'ipam': ipam,
      'mac': mac,
      'mtu': mtu,
      'nodes': nodes,
      'peers': peers,
      'reversedns': reversedns,
      'tag': tag,
      'vlan-protocol': vlan_protocol,
      'vrf-vxlan': vrf_vxlan
    };
    return await this.#client.set(`/cluster/sdn/zones/${this.#zone}`, parameters);
  }

}

/**
 * Class PVESdnClusterControllers
 */
class PVESdnClusterControllers {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }


  /**
   * Get ItemControllersSdnClusterController
   * @param controller
   * @returns {PVEItemControllersSdnClusterController}
   */
  get(controller) { return new PVEItemControllersSdnClusterController(this.#client, controller); }

  /**
  * SDN controllers index.
  * @param {bool} pending Display pending config.
  * @param {bool} running Display running config.
  * @param {string} type Only list sdn controllers of specific type
  *   Enum: bgp,evpn,faucet
  * @returns {Result}
  */
  async index(pending, running, type) {
    const parameters = {
      'pending': pending,
      'running': running,
      'type': type
    };
    return await this.#client.get(`/cluster/sdn/controllers`, parameters);
  }
  /**
  * Create a new sdn controller object.
  * @param {string} controller The SDN controller object identifier.
  * @param {string} type Plugin type.
  *   Enum: bgp,evpn,faucet
  * @param {int} asn autonomous system number
  * @param {bool} ebgp Enable ebgp. (remote-as external)
  * @param {int} ebgp_multihop
  * @param {string} loopback source loopback interface.
  * @param {string} node The cluster node name.
  * @param {string} peers peers address list.
  * @returns {Result}
  */
  async create(controller, type, asn, ebgp, ebgp_multihop, loopback, node, peers) {
    const parameters = {
      'controller': controller,
      'type': type,
      'asn': asn,
      'ebgp': ebgp,
      'ebgp-multihop': ebgp_multihop,
      'loopback': loopback,
      'node': node,
      'peers': peers
    };
    return await this.#client.create(`/cluster/sdn/controllers`, parameters);
  }

}
/**
 * Class PVEItemControllersSdnClusterController
 */
class PVEItemControllersSdnClusterController {
  #controller;
  /** @type {PveClient} */
  #client;

  constructor(client, controller) {
    this.#client = client;
    this.#controller = controller;
  }



  /**
  * Delete sdn controller object configuration.
  * @returns {Result}
  */
  async delete_() {
    return await this.#client.delete(`/cluster/sdn/controllers/${this.#controller}`);
  }
  /**
  * Read sdn controller configuration.
  * @param {bool} pending Display pending config.
  * @param {bool} running Display running config.
  * @returns {Result}
  */
  async read(pending, running) {
    const parameters = {
      'pending': pending,
      'running': running
    };
    return await this.#client.get(`/cluster/sdn/controllers/${this.#controller}`, parameters);
  }
  /**
  * Update sdn controller object configuration.
  * @param {int} asn autonomous system number
  * @param {string} delete_ A list of settings you want to delete.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {bool} ebgp Enable ebgp. (remote-as external)
  * @param {int} ebgp_multihop
  * @param {string} loopback source loopback interface.
  * @param {string} node The cluster node name.
  * @param {string} peers peers address list.
  * @returns {Result}
  */
  async update(asn, delete_, digest, ebgp, ebgp_multihop, loopback, node, peers) {
    const parameters = {
      'asn': asn,
      'delete': delete_,
      'digest': digest,
      'ebgp': ebgp,
      'ebgp-multihop': ebgp_multihop,
      'loopback': loopback,
      'node': node,
      'peers': peers
    };
    return await this.#client.set(`/cluster/sdn/controllers/${this.#controller}`, parameters);
  }

}

/**
 * Class PVESdnClusterIpams
 */
class PVESdnClusterIpams {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }


  /**
   * Get ItemIpamsSdnClusterIpam
   * @param ipam
   * @returns {PVEItemIpamsSdnClusterIpam}
   */
  get(ipam) { return new PVEItemIpamsSdnClusterIpam(this.#client, ipam); }

  /**
  * SDN ipams index.
  * @param {string} type Only list sdn ipams of specific type
  *   Enum: netbox,phpipam,pve
  * @returns {Result}
  */
  async index(type) {
    const parameters = { 'type': type };
    return await this.#client.get(`/cluster/sdn/ipams`, parameters);
  }
  /**
  * Create a new sdn ipam object.
  * @param {string} ipam The SDN ipam object identifier.
  * @param {string} type Plugin type.
  *   Enum: netbox,phpipam,pve
  * @param {int} section
  * @param {string} token
  * @param {string} url
  * @returns {Result}
  */
  async create(ipam, type, section, token, url) {
    const parameters = {
      'ipam': ipam,
      'type': type,
      'section': section,
      'token': token,
      'url': url
    };
    return await this.#client.create(`/cluster/sdn/ipams`, parameters);
  }

}
/**
 * Class PVEItemIpamsSdnClusterIpam
 */
class PVEItemIpamsSdnClusterIpam {
  #ipam;
  /** @type {PveClient} */
  #client;

  constructor(client, ipam) {
    this.#client = client;
    this.#ipam = ipam;
  }



  /**
  * Delete sdn ipam object configuration.
  * @returns {Result}
  */
  async delete_() {
    return await this.#client.delete(`/cluster/sdn/ipams/${this.#ipam}`);
  }
  /**
  * Read sdn ipam configuration.
  * @returns {Result}
  */
  async read() {
    return await this.#client.get(`/cluster/sdn/ipams/${this.#ipam}`);
  }
  /**
  * Update sdn ipam object configuration.
  * @param {string} delete_ A list of settings you want to delete.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {int} section
  * @param {string} token
  * @param {string} url
  * @returns {Result}
  */
  async update(delete_, digest, section, token, url) {
    const parameters = {
      'delete': delete_,
      'digest': digest,
      'section': section,
      'token': token,
      'url': url
    };
    return await this.#client.set(`/cluster/sdn/ipams/${this.#ipam}`, parameters);
  }

}

/**
 * Class PVESdnClusterDns
 */
class PVESdnClusterDns {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }


  /**
   * Get ItemDnsSdnClusterDns
   * @param dns
   * @returns {PVEItemDnsSdnClusterDns}
   */
  get(dns) { return new PVEItemDnsSdnClusterDns(this.#client, dns); }

  /**
  * SDN dns index.
  * @param {string} type Only list sdn dns of specific type
  *   Enum: powerdns
  * @returns {Result}
  */
  async index(type) {
    const parameters = { 'type': type };
    return await this.#client.get(`/cluster/sdn/dns`, parameters);
  }
  /**
  * Create a new sdn dns object.
  * @param {string} dns The SDN dns object identifier.
  * @param {string} key
  * @param {string} type Plugin type.
  *   Enum: powerdns
  * @param {string} url
  * @param {int} reversemaskv6
  * @param {int} reversev6mask
  * @param {int} ttl
  * @returns {Result}
  */
  async create(dns, key, type, url, reversemaskv6, reversev6mask, ttl) {
    const parameters = {
      'dns': dns,
      'key': key,
      'type': type,
      'url': url,
      'reversemaskv6': reversemaskv6,
      'reversev6mask': reversev6mask,
      'ttl': ttl
    };
    return await this.#client.create(`/cluster/sdn/dns`, parameters);
  }

}
/**
 * Class PVEItemDnsSdnClusterDns
 */
class PVEItemDnsSdnClusterDns {
  #dns;
  /** @type {PveClient} */
  #client;

  constructor(client, dns) {
    this.#client = client;
    this.#dns = dns;
  }



  /**
  * Delete sdn dns object configuration.
  * @returns {Result}
  */
  async delete_() {
    return await this.#client.delete(`/cluster/sdn/dns/${this.#dns}`);
  }
  /**
  * Read sdn dns configuration.
  * @returns {Result}
  */
  async read() {
    return await this.#client.get(`/cluster/sdn/dns/${this.#dns}`);
  }
  /**
  * Update sdn dns object configuration.
  * @param {string} delete_ A list of settings you want to delete.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {string} key
  * @param {int} reversemaskv6
  * @param {int} ttl
  * @param {string} url
  * @returns {Result}
  */
  async update(delete_, digest, key, reversemaskv6, ttl, url) {
    const parameters = {
      'delete': delete_,
      'digest': digest,
      'key': key,
      'reversemaskv6': reversemaskv6,
      'ttl': ttl,
      'url': url
    };
    return await this.#client.set(`/cluster/sdn/dns/${this.#dns}`, parameters);
  }

}

/**
 * Class PVEClusterLog
 */
class PVEClusterLog {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }



  /**
  * Read cluster log
  * @param {int} max Maximum number of entries.
  * @returns {Result}
  */
  async log(max) {
    const parameters = { 'max': max };
    return await this.#client.get(`/cluster/log`, parameters);
  }

}

/**
 * Class PVEClusterResources
 */
class PVEClusterResources {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }



  /**
  * Resources index (cluster wide).
  * @param {string} type
  *   Enum: vm,storage,node,sdn
  * @returns {Result}
  */
  async resources(type) {
    const parameters = { 'type': type };
    return await this.#client.get(`/cluster/resources`, parameters);
  }

}

/**
 * Class PVEClusterTasks
 */
class PVEClusterTasks {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }



  /**
  * List recent tasks (cluster wide).
  * @returns {Result}
  */
  async tasks() {
    return await this.#client.get(`/cluster/tasks`);
  }

}

/**
 * Class PVEClusterOptions
 */
class PVEClusterOptions {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }



  /**
  * Get datacenter options.
  * @returns {Result}
  */
  async getOptions() {
    return await this.#client.get(`/cluster/options`);
  }
  /**
  * Set datacenter options.
  * @param {string} bwlimit Set bandwidth/io limits various operations.
  * @param {string} console Select the default Console viewer. You can either use the builtin java applet (VNC; deprecated and maps to html5), an external virt-viewer comtatible application (SPICE), an HTML5 based vnc viewer (noVNC), or an HTML5 based console client (xtermjs). If the selected viewer is not available (e.g. SPICE not activated for the VM), the fallback is noVNC.
  *   Enum: applet,vv,html5,xtermjs
  * @param {string} delete_ A list of settings you want to delete.
  * @param {string} description Datacenter description. Shown in the web-interface datacenter notes panel. This is saved as comment inside the configuration file.
  * @param {string} email_from Specify email address to send notification from (default is root@$hostname)
  * @param {string} fencing Set the fencing mode of the HA cluster. Hardware mode needs a valid configuration of fence devices in /etc/pve/ha/fence.cfg. With both all two modes are used.  WARNING: 'hardware' and 'both' are EXPERIMENTAL &amp; WIP
  *   Enum: watchdog,hardware,both
  * @param {string} ha Cluster wide HA settings.
  * @param {string} http_proxy Specify external http proxy which is used for downloads (example: 'http://username:password@host:port/')
  * @param {string} keyboard Default keybord layout for vnc server.
  *   Enum: de,de-ch,da,en-gb,en-us,es,fi,fr,fr-be,fr-ca,fr-ch,hu,is,it,ja,lt,mk,nl,no,pl,pt,pt-br,sv,sl,tr
  * @param {string} language Default GUI language.
  *   Enum: ca,da,de,en,es,eu,fa,fr,he,it,ja,nb,nn,pl,pt_BR,ru,sl,sv,tr,zh_CN,zh_TW
  * @param {string} mac_prefix Prefix for autogenerated MAC addresses.
  * @param {int} max_workers Defines how many workers (per node) are maximal started  on actions like 'stopall VMs' or task from the ha-manager.
  * @param {string} migration For cluster wide migration settings.
  * @param {bool} migration_unsecure Migration is secure using SSH tunnel by default. For secure private networks you can disable it to speed up migration. Deprecated, use the 'migration' property instead!
  * @param {string} u2f u2f
  * @param {string} webauthn webauthn configuration
  * @returns {Result}
  */
  async setOptions(bwlimit, console, delete_, description, email_from, fencing, ha, http_proxy, keyboard, language, mac_prefix, max_workers, migration, migration_unsecure, u2f, webauthn) {
    const parameters = {
      'bwlimit': bwlimit,
      'console': console,
      'delete': delete_,
      'description': description,
      'email_from': email_from,
      'fencing': fencing,
      'ha': ha,
      'http_proxy': http_proxy,
      'keyboard': keyboard,
      'language': language,
      'mac_prefix': mac_prefix,
      'max_workers': max_workers,
      'migration': migration,
      'migration_unsecure': migration_unsecure,
      'u2f': u2f,
      'webauthn': webauthn
    };
    return await this.#client.set(`/cluster/options`, parameters);
  }

}

/**
 * Class PVEClusterStatus
 */
class PVEClusterStatus {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }



  /**
  * Get cluster status information.
  * @returns {Result}
  */
  async getStatus() {
    return await this.#client.get(`/cluster/status`);
  }

}

/**
 * Class PVEClusterNextid
 */
class PVEClusterNextid {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }



  /**
  * Get next free VMID. If you pass an VMID it will raise an error if the ID is already used.
  * @param {int} vmid The (unique) ID of the VM.
  * @returns {Result}
  */
  async nextid(vmid) {
    const parameters = { 'vmid': vmid };
    return await this.#client.get(`/cluster/nextid`, parameters);
  }

}

/**
 * Class PVENodes
 */
class PVENodes {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }


  /**
   * Get ItemNodesNode
   * @param node
   * @returns {PVEItemNodesNode}
   */
  get(node) { return new PVEItemNodesNode(this.#client, node); }

  /**
  * Cluster node index.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/nodes`);
  }

}
/**
 * Class PVEItemNodesNode
 */
class PVEItemNodesNode {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }

  #qemu;
  /**
   * Get NodeNodesQemu
   * @returns {PVENodeNodesQemu}
   */
  get qemu() { return this.#qemu == null ? (this.#qemu = new PVENodeNodesQemu(this.#client, this.#node)) : this.#qemu; }
  #lxc;
  /**
   * Get NodeNodesLxc
   * @returns {PVENodeNodesLxc}
   */
  get lxc() { return this.#lxc == null ? (this.#lxc = new PVENodeNodesLxc(this.#client, this.#node)) : this.#lxc; }
  #ceph;
  /**
   * Get NodeNodesCeph
   * @returns {PVENodeNodesCeph}
   */
  get ceph() { return this.#ceph == null ? (this.#ceph = new PVENodeNodesCeph(this.#client, this.#node)) : this.#ceph; }
  #vzdump;
  /**
   * Get NodeNodesVzdump
   * @returns {PVENodeNodesVzdump}
   */
  get vzdump() { return this.#vzdump == null ? (this.#vzdump = new PVENodeNodesVzdump(this.#client, this.#node)) : this.#vzdump; }
  #services;
  /**
   * Get NodeNodesServices
   * @returns {PVENodeNodesServices}
   */
  get services() { return this.#services == null ? (this.#services = new PVENodeNodesServices(this.#client, this.#node)) : this.#services; }
  #subscription;
  /**
   * Get NodeNodesSubscription
   * @returns {PVENodeNodesSubscription}
   */
  get subscription() { return this.#subscription == null ? (this.#subscription = new PVENodeNodesSubscription(this.#client, this.#node)) : this.#subscription; }
  #network;
  /**
   * Get NodeNodesNetwork
   * @returns {PVENodeNodesNetwork}
   */
  get network() { return this.#network == null ? (this.#network = new PVENodeNodesNetwork(this.#client, this.#node)) : this.#network; }
  #tasks;
  /**
   * Get NodeNodesTasks
   * @returns {PVENodeNodesTasks}
   */
  get tasks() { return this.#tasks == null ? (this.#tasks = new PVENodeNodesTasks(this.#client, this.#node)) : this.#tasks; }
  #scan;
  /**
   * Get NodeNodesScan
   * @returns {PVENodeNodesScan}
   */
  get scan() { return this.#scan == null ? (this.#scan = new PVENodeNodesScan(this.#client, this.#node)) : this.#scan; }
  #hardware;
  /**
   * Get NodeNodesHardware
   * @returns {PVENodeNodesHardware}
   */
  get hardware() { return this.#hardware == null ? (this.#hardware = new PVENodeNodesHardware(this.#client, this.#node)) : this.#hardware; }
  #capabilities;
  /**
   * Get NodeNodesCapabilities
   * @returns {PVENodeNodesCapabilities}
   */
  get capabilities() { return this.#capabilities == null ? (this.#capabilities = new PVENodeNodesCapabilities(this.#client, this.#node)) : this.#capabilities; }
  #storage;
  /**
   * Get NodeNodesStorage
   * @returns {PVENodeNodesStorage}
   */
  get storage() { return this.#storage == null ? (this.#storage = new PVENodeNodesStorage(this.#client, this.#node)) : this.#storage; }
  #disks;
  /**
   * Get NodeNodesDisks
   * @returns {PVENodeNodesDisks}
   */
  get disks() { return this.#disks == null ? (this.#disks = new PVENodeNodesDisks(this.#client, this.#node)) : this.#disks; }
  #apt;
  /**
   * Get NodeNodesApt
   * @returns {PVENodeNodesApt}
   */
  get apt() { return this.#apt == null ? (this.#apt = new PVENodeNodesApt(this.#client, this.#node)) : this.#apt; }
  #firewall;
  /**
   * Get NodeNodesFirewall
   * @returns {PVENodeNodesFirewall}
   */
  get firewall() { return this.#firewall == null ? (this.#firewall = new PVENodeNodesFirewall(this.#client, this.#node)) : this.#firewall; }
  #replication;
  /**
   * Get NodeNodesReplication
   * @returns {PVENodeNodesReplication}
   */
  get replication() { return this.#replication == null ? (this.#replication = new PVENodeNodesReplication(this.#client, this.#node)) : this.#replication; }
  #certificates;
  /**
   * Get NodeNodesCertificates
   * @returns {PVENodeNodesCertificates}
   */
  get certificates() { return this.#certificates == null ? (this.#certificates = new PVENodeNodesCertificates(this.#client, this.#node)) : this.#certificates; }
  #config;
  /**
   * Get NodeNodesConfig
   * @returns {PVENodeNodesConfig}
   */
  get config() { return this.#config == null ? (this.#config = new PVENodeNodesConfig(this.#client, this.#node)) : this.#config; }
  #sdn;
  /**
   * Get NodeNodesSdn
   * @returns {PVENodeNodesSdn}
   */
  get sdn() { return this.#sdn == null ? (this.#sdn = new PVENodeNodesSdn(this.#client, this.#node)) : this.#sdn; }
  #version;
  /**
   * Get NodeNodesVersion
   * @returns {PVENodeNodesVersion}
   */
  get version() { return this.#version == null ? (this.#version = new PVENodeNodesVersion(this.#client, this.#node)) : this.#version; }
  #status;
  /**
   * Get NodeNodesStatus
   * @returns {PVENodeNodesStatus}
   */
  get status() { return this.#status == null ? (this.#status = new PVENodeNodesStatus(this.#client, this.#node)) : this.#status; }
  #netstat;
  /**
   * Get NodeNodesNetstat
   * @returns {PVENodeNodesNetstat}
   */
  get netstat() { return this.#netstat == null ? (this.#netstat = new PVENodeNodesNetstat(this.#client, this.#node)) : this.#netstat; }
  #execute;
  /**
   * Get NodeNodesExecute
   * @returns {PVENodeNodesExecute}
   */
  get execute() { return this.#execute == null ? (this.#execute = new PVENodeNodesExecute(this.#client, this.#node)) : this.#execute; }
  #wakeonlan;
  /**
   * Get NodeNodesWakeonlan
   * @returns {PVENodeNodesWakeonlan}
   */
  get wakeonlan() { return this.#wakeonlan == null ? (this.#wakeonlan = new PVENodeNodesWakeonlan(this.#client, this.#node)) : this.#wakeonlan; }
  #rrd;
  /**
   * Get NodeNodesRrd
   * @returns {PVENodeNodesRrd}
   */
  get rrd() { return this.#rrd == null ? (this.#rrd = new PVENodeNodesRrd(this.#client, this.#node)) : this.#rrd; }
  #rrddata;
  /**
   * Get NodeNodesRrddata
   * @returns {PVENodeNodesRrddata}
   */
  get rrddata() { return this.#rrddata == null ? (this.#rrddata = new PVENodeNodesRrddata(this.#client, this.#node)) : this.#rrddata; }
  #syslog;
  /**
   * Get NodeNodesSyslog
   * @returns {PVENodeNodesSyslog}
   */
  get syslog() { return this.#syslog == null ? (this.#syslog = new PVENodeNodesSyslog(this.#client, this.#node)) : this.#syslog; }
  #journal;
  /**
   * Get NodeNodesJournal
   * @returns {PVENodeNodesJournal}
   */
  get journal() { return this.#journal == null ? (this.#journal = new PVENodeNodesJournal(this.#client, this.#node)) : this.#journal; }
  #vncshell;
  /**
   * Get NodeNodesVncshell
   * @returns {PVENodeNodesVncshell}
   */
  get vncshell() { return this.#vncshell == null ? (this.#vncshell = new PVENodeNodesVncshell(this.#client, this.#node)) : this.#vncshell; }
  #termproxy;
  /**
   * Get NodeNodesTermproxy
   * @returns {PVENodeNodesTermproxy}
   */
  get termproxy() { return this.#termproxy == null ? (this.#termproxy = new PVENodeNodesTermproxy(this.#client, this.#node)) : this.#termproxy; }
  #vncwebsocket;
  /**
   * Get NodeNodesVncwebsocket
   * @returns {PVENodeNodesVncwebsocket}
   */
  get vncwebsocket() { return this.#vncwebsocket == null ? (this.#vncwebsocket = new PVENodeNodesVncwebsocket(this.#client, this.#node)) : this.#vncwebsocket; }
  #spiceshell;
  /**
   * Get NodeNodesSpiceshell
   * @returns {PVENodeNodesSpiceshell}
   */
  get spiceshell() { return this.#spiceshell == null ? (this.#spiceshell = new PVENodeNodesSpiceshell(this.#client, this.#node)) : this.#spiceshell; }
  #dns;
  /**
   * Get NodeNodesDns
   * @returns {PVENodeNodesDns}
   */
  get dns() { return this.#dns == null ? (this.#dns = new PVENodeNodesDns(this.#client, this.#node)) : this.#dns; }
  #time;
  /**
   * Get NodeNodesTime
   * @returns {PVENodeNodesTime}
   */
  get time() { return this.#time == null ? (this.#time = new PVENodeNodesTime(this.#client, this.#node)) : this.#time; }
  #aplinfo;
  /**
   * Get NodeNodesAplinfo
   * @returns {PVENodeNodesAplinfo}
   */
  get aplinfo() { return this.#aplinfo == null ? (this.#aplinfo = new PVENodeNodesAplinfo(this.#client, this.#node)) : this.#aplinfo; }
  #queryUrlMetadata;
  /**
   * Get NodeNodesQueryUrlMetadata
   * @returns {PVENodeNodesQueryUrlMetadata}
   */
  get queryUrlMetadata() { return this.#queryUrlMetadata == null ? (this.#queryUrlMetadata = new PVENodeNodesQueryUrlMetadata(this.#client, this.#node)) : this.#queryUrlMetadata; }
  #report;
  /**
   * Get NodeNodesReport
   * @returns {PVENodeNodesReport}
   */
  get report() { return this.#report == null ? (this.#report = new PVENodeNodesReport(this.#client, this.#node)) : this.#report; }
  #startall;
  /**
   * Get NodeNodesStartall
   * @returns {PVENodeNodesStartall}
   */
  get startall() { return this.#startall == null ? (this.#startall = new PVENodeNodesStartall(this.#client, this.#node)) : this.#startall; }
  #stopall;
  /**
   * Get NodeNodesStopall
   * @returns {PVENodeNodesStopall}
   */
  get stopall() { return this.#stopall == null ? (this.#stopall = new PVENodeNodesStopall(this.#client, this.#node)) : this.#stopall; }
  #migrateall;
  /**
   * Get NodeNodesMigrateall
   * @returns {PVENodeNodesMigrateall}
   */
  get migrateall() { return this.#migrateall == null ? (this.#migrateall = new PVENodeNodesMigrateall(this.#client, this.#node)) : this.#migrateall; }
  #hosts;
  /**
   * Get NodeNodesHosts
   * @returns {PVENodeNodesHosts}
   */
  get hosts() { return this.#hosts == null ? (this.#hosts = new PVENodeNodesHosts(this.#client, this.#node)) : this.#hosts; }


  /**
  * Node index.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/nodes/${this.#node}`);
  }

}
/**
 * Class PVENodeNodesQemu
 */
class PVENodeNodesQemu {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }


  /**
   * Get ItemQemuNodeNodesVmid
   * @param vmid
   * @returns {PVEItemQemuNodeNodesVmid}
   */
  get(vmid) { return new PVEItemQemuNodeNodesVmid(this.#client, this.#node, vmid); }

  /**
  * Virtual machine index (per node).
  * @param {bool} full Determine the full status of active VMs.
  * @returns {Result}
  */
  async vmlist(full) {
    const parameters = { 'full': full };
    return await this.#client.get(`/nodes/${this.#node}/qemu`, parameters);
  }
  /**
  * Create or restore a virtual machine.
  * @param {int} vmid The (unique) ID of the VM.
  * @param {bool} acpi Enable/disable ACPI.
  * @param {string} agent Enable/disable communication with the Qemu Guest Agent and its properties.
  * @param {string} arch Virtual processor architecture. Defaults to the host.
  *   Enum: x86_64,aarch64
  * @param {string} archive The backup archive. Either the file system path to a .tar or .vma file (use '-' to pipe data from stdin) or a proxmox storage backup volume identifier.
  * @param {string} args Arbitrary arguments passed to kvm.
  * @param {string} audio0 Configure a audio device, useful in combination with QXL/Spice.
  * @param {bool} autostart Automatic restart after crash (currently ignored).
  * @param {int} balloon Amount of target RAM for the VM in MB. Using zero disables the ballon driver.
  * @param {string} bios Select BIOS implementation.
  *   Enum: seabios,ovmf
  * @param {string} boot Specify guest boot order. Use the 'order=' sub-property as usage with no key or 'legacy=' is deprecated.
  * @param {string} bootdisk Enable booting from specified disk. Deprecated: Use 'boot: order=foo;bar' instead.
  * @param {int} bwlimit Override I/O bandwidth limit (in KiB/s).
  * @param {string} cdrom This is an alias for option -ide2
  * @param {string} cicustom cloud-init: Specify custom files to replace the automatically generated ones at start.
  * @param {string} cipassword cloud-init: Password to assign the user. Using this is generally not recommended. Use ssh keys instead. Also note that older cloud-init versions do not support hashed passwords.
  * @param {string} citype Specifies the cloud-init configuration format. The default depends on the configured operating system type (`ostype`. We use the `nocloud` format for Linux, and `configdrive2` for windows.
  *   Enum: configdrive2,nocloud,opennebula
  * @param {string} ciuser cloud-init: User name to change ssh keys and password for instead of the image's configured default user.
  * @param {int} cores The number of cores per socket.
  * @param {string} cpu Emulated CPU type.
  * @param {float} cpulimit Limit of CPU usage.
  * @param {int} cpuunits CPU weight for a VM, will be clamped to [1, 10000] in cgroup v2.
  * @param {string} description Description for the VM. Shown in the web-interface VM's summary. This is saved as comment inside the configuration file.
  * @param {string} efidisk0 Configure a Disk for storing EFI vars. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume. Note that SIZE_IN_GiB is ignored here and that the default EFI vars are copied to the volume instead.
  * @param {bool} force Allow to overwrite existing VM.
  * @param {bool} freeze Freeze CPU at startup (use 'c' monitor command to start execution).
  * @param {string} hookscript Script that will be executed during various steps in the vms lifetime.
  * @param {array} hostpciN Map host PCI devices into guest.
  * @param {string} hotplug Selectively enable hotplug features. This is a comma separated list of hotplug features: 'network', 'disk', 'cpu', 'memory' and 'usb'. Use '0' to disable hotplug completely. Using '1' as value is an alias for the default `network,disk,usb`.
  * @param {string} hugepages Enable/disable hugepages memory.
  *   Enum: any,2,1024
  * @param {array} ideN Use volume as IDE hard disk or CD-ROM (n is 0 to 3). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
  * @param {array} ipconfigN cloud-init: Specify IP addresses and gateways for the corresponding interface.  IP addresses use CIDR notation, gateways are optional but need an IP of the same type specified.  The special string 'dhcp' can be used for IP addresses to use DHCP, in which case no explicit gateway should be provided. For IPv6 the special string 'auto' can be used to use stateless autoconfiguration. This requires cloud-init 19.4 or newer.  If cloud-init is enabled and neither an IPv4 nor an IPv6 address is specified, it defaults to using dhcp on IPv4.
  * @param {string} ivshmem Inter-VM shared memory. Useful for direct communication between VMs, or to the host.
  * @param {bool} keephugepages Use together with hugepages. If enabled, hugepages will not not be deleted after VM shutdown and can be used for subsequent starts.
  * @param {string} keyboard Keyboard layout for VNC server. The default is read from the'/etc/pve/datacenter.cfg' configuration file. It should not be necessary to set it.
  *   Enum: de,de-ch,da,en-gb,en-us,es,fi,fr,fr-be,fr-ca,fr-ch,hu,is,it,ja,lt,mk,nl,no,pl,pt,pt-br,sv,sl,tr
  * @param {bool} kvm Enable/disable KVM hardware virtualization.
  * @param {bool} live_restore Start the VM immediately from the backup and restore in background. PBS only.
  * @param {bool} localtime Set the real time clock (RTC) to local time. This is enabled by default if the `ostype` indicates a Microsoft Windows OS.
  * @param {string} lock Lock/unlock the VM.
  *   Enum: backup,clone,create,migrate,rollback,snapshot,snapshot-delete,suspending,suspended
  * @param {string} machine Specifies the Qemu machine type.
  * @param {int} memory Amount of RAM for the VM in MB. This is the maximum available memory when you use the balloon device.
  * @param {float} migrate_downtime Set maximum tolerated downtime (in seconds) for migrations.
  * @param {int} migrate_speed Set maximum speed (in MB/s) for migrations. Value 0 is no limit.
  * @param {string} name Set a name for the VM. Only used on the configuration web interface.
  * @param {string} nameserver cloud-init: Sets DNS server IP address for a container. Create will' 	    .' automatically use the setting from the host if neither searchdomain nor nameserver' 	    .' are set.
  * @param {array} netN Specify network devices.
  * @param {bool} numa Enable/disable NUMA.
  * @param {array} numaN NUMA topology.
  * @param {bool} onboot Specifies whether a VM will be started during system bootup.
  * @param {string} ostype Specify guest operating system.
  *   Enum: other,wxp,w2k,w2k3,w2k8,wvista,win7,win8,win10,win11,l24,l26,solaris
  * @param {array} parallelN Map host parallel devices (n is 0 to 2).
  * @param {string} pool Add the VM to the specified pool.
  * @param {bool} protection Sets the protection flag of the VM. This will disable the remove VM and remove disk operations.
  * @param {bool} reboot Allow reboot. If set to '0' the VM exit on reboot.
  * @param {string} rng0 Configure a VirtIO-based Random Number Generator.
  * @param {array} sataN Use volume as SATA hard disk or CD-ROM (n is 0 to 5). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
  * @param {array} scsiN Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
  * @param {string} scsihw SCSI controller model
  *   Enum: lsi,lsi53c810,virtio-scsi-pci,virtio-scsi-single,megasas,pvscsi
  * @param {string} searchdomain cloud-init: Sets DNS search domains for a container. Create will' 	    .' automatically use the setting from the host if neither searchdomain nor nameserver' 	    .' are set.
  * @param {array} serialN Create a serial device inside the VM (n is 0 to 3)
  * @param {int} shares Amount of memory shares for auto-ballooning. The larger the number is, the more memory this VM gets. Number is relative to weights of all other running VMs. Using zero disables auto-ballooning. Auto-ballooning is done by pvestatd.
  * @param {string} smbios1 Specify SMBIOS type 1 fields.
  * @param {int} smp The number of CPUs. Please use option -sockets instead.
  * @param {int} sockets The number of CPU sockets.
  * @param {string} spice_enhancements Configure additional enhancements for SPICE.
  * @param {string} sshkeys cloud-init: Setup public SSH keys (one key per line, OpenSSH format).
  * @param {bool} start Start VM after it was created successfully.
  * @param {string} startdate Set the initial date of the real time clock. Valid format for date are:'now' or '2006-06-17T16:01:21' or '2006-06-17'.
  * @param {string} startup Startup and shutdown behavior. Order is a non-negative number defining the general startup order. Shutdown in done with reverse ordering. Additionally you can set the 'up' or 'down' delay in seconds, which specifies a delay to wait before the next VM is started or stopped.
  * @param {string} storage Default storage.
  * @param {bool} tablet Enable/disable the USB tablet device.
  * @param {string} tags Tags of the VM. This is only meta information.
  * @param {bool} tdf Enable/disable time drift fix.
  * @param {bool} template Enable/disable Template.
  * @param {string} tpmstate0 Configure a Disk for storing TPM state. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume. Note that SIZE_IN_GiB is ignored here and that the default size of 4 MiB will always be used instead. The format is also fixed to 'raw'.
  * @param {bool} unique Assign a unique random ethernet address.
  * @param {array} unusedN Reference to unused volumes. This is used internally, and should not be modified manually.
  * @param {array} usbN Configure an USB device (n is 0 to 4).
  * @param {int} vcpus Number of hotplugged vcpus.
  * @param {string} vga Configure the VGA hardware.
  * @param {array} virtioN Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
  * @param {string} vmgenid Set VM Generation ID. Use '1' to autogenerate on create or update, pass '0' to disable explicitly.
  * @param {string} vmstatestorage Default storage for VM state volumes/files.
  * @param {string} watchdog Create a virtual hardware watchdog device.
  * @returns {Result}
  */
  async createVm(vmid, acpi, agent, arch, archive, args, audio0, autostart, balloon, bios, boot, bootdisk, bwlimit, cdrom, cicustom, cipassword, citype, ciuser, cores, cpu, cpulimit, cpuunits, description, efidisk0, force, freeze, hookscript, hostpciN, hotplug, hugepages, ideN, ipconfigN, ivshmem, keephugepages, keyboard, kvm, live_restore, localtime, lock, machine, memory, migrate_downtime, migrate_speed, name, nameserver, netN, numa, numaN, onboot, ostype, parallelN, pool, protection, reboot, rng0, sataN, scsiN, scsihw, searchdomain, serialN, shares, smbios1, smp, sockets, spice_enhancements, sshkeys, start, startdate, startup, storage, tablet, tags, tdf, template, tpmstate0, unique, unusedN, usbN, vcpus, vga, virtioN, vmgenid, vmstatestorage, watchdog) {
    const parameters = {
      'vmid': vmid,
      'acpi': acpi,
      'agent': agent,
      'arch': arch,
      'archive': archive,
      'args': args,
      'audio0': audio0,
      'autostart': autostart,
      'balloon': balloon,
      'bios': bios,
      'boot': boot,
      'bootdisk': bootdisk,
      'bwlimit': bwlimit,
      'cdrom': cdrom,
      'cicustom': cicustom,
      'cipassword': cipassword,
      'citype': citype,
      'ciuser': ciuser,
      'cores': cores,
      'cpu': cpu,
      'cpulimit': cpulimit,
      'cpuunits': cpuunits,
      'description': description,
      'efidisk0': efidisk0,
      'force': force,
      'freeze': freeze,
      'hookscript': hookscript,
      'hotplug': hotplug,
      'hugepages': hugepages,
      'ivshmem': ivshmem,
      'keephugepages': keephugepages,
      'keyboard': keyboard,
      'kvm': kvm,
      'live-restore': live_restore,
      'localtime': localtime,
      'lock': lock,
      'machine': machine,
      'memory': memory,
      'migrate_downtime': migrate_downtime,
      'migrate_speed': migrate_speed,
      'name': name,
      'nameserver': nameserver,
      'numa': numa,
      'onboot': onboot,
      'ostype': ostype,
      'pool': pool,
      'protection': protection,
      'reboot': reboot,
      'rng0': rng0,
      'scsihw': scsihw,
      'searchdomain': searchdomain,
      'shares': shares,
      'smbios1': smbios1,
      'smp': smp,
      'sockets': sockets,
      'spice_enhancements': spice_enhancements,
      'sshkeys': sshkeys,
      'start': start,
      'startdate': startdate,
      'startup': startup,
      'storage': storage,
      'tablet': tablet,
      'tags': tags,
      'tdf': tdf,
      'template': template,
      'tpmstate0': tpmstate0,
      'unique': unique,
      'vcpus': vcpus,
      'vga': vga,
      'vmgenid': vmgenid,
      'vmstatestorage': vmstatestorage,
      'watchdog': watchdog
    };
    this.#client.addIndexedParameter(parameters, 'hostpci', hostpciN);
    this.#client.addIndexedParameter(parameters, 'ide', ideN);
    this.#client.addIndexedParameter(parameters, 'ipconfig', ipconfigN);
    this.#client.addIndexedParameter(parameters, 'net', netN);
    this.#client.addIndexedParameter(parameters, 'numa', numaN);
    this.#client.addIndexedParameter(parameters, 'parallel', parallelN);
    this.#client.addIndexedParameter(parameters, 'sata', sataN);
    this.#client.addIndexedParameter(parameters, 'scsi', scsiN);
    this.#client.addIndexedParameter(parameters, 'serial', serialN);
    this.#client.addIndexedParameter(parameters, 'unused', unusedN);
    this.#client.addIndexedParameter(parameters, 'usb', usbN);
    this.#client.addIndexedParameter(parameters, 'virtio', virtioN);
    return await this.#client.create(`/nodes/${this.#node}/qemu`, parameters);
  }

}
/**
 * Class PVEItemQemuNodeNodesVmid
 */
class PVEItemQemuNodeNodesVmid {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }

  #firewall;
  /**
   * Get VmidQemuNodeNodesFirewall
   * @returns {PVEVmidQemuNodeNodesFirewall}
   */
  get firewall() { return this.#firewall == null ? (this.#firewall = new PVEVmidQemuNodeNodesFirewall(this.#client, this.#node, this.#vmid)) : this.#firewall; }
  #agent;
  /**
   * Get VmidQemuNodeNodesAgent
   * @returns {PVEVmidQemuNodeNodesAgent}
   */
  get agent() { return this.#agent == null ? (this.#agent = new PVEVmidQemuNodeNodesAgent(this.#client, this.#node, this.#vmid)) : this.#agent; }
  #rrd;
  /**
   * Get VmidQemuNodeNodesRrd
   * @returns {PVEVmidQemuNodeNodesRrd}
   */
  get rrd() { return this.#rrd == null ? (this.#rrd = new PVEVmidQemuNodeNodesRrd(this.#client, this.#node, this.#vmid)) : this.#rrd; }
  #rrddata;
  /**
   * Get VmidQemuNodeNodesRrddata
   * @returns {PVEVmidQemuNodeNodesRrddata}
   */
  get rrddata() { return this.#rrddata == null ? (this.#rrddata = new PVEVmidQemuNodeNodesRrddata(this.#client, this.#node, this.#vmid)) : this.#rrddata; }
  #config;
  /**
   * Get VmidQemuNodeNodesConfig
   * @returns {PVEVmidQemuNodeNodesConfig}
   */
  get config() { return this.#config == null ? (this.#config = new PVEVmidQemuNodeNodesConfig(this.#client, this.#node, this.#vmid)) : this.#config; }
  #pending;
  /**
   * Get VmidQemuNodeNodesPending
   * @returns {PVEVmidQemuNodeNodesPending}
   */
  get pending() { return this.#pending == null ? (this.#pending = new PVEVmidQemuNodeNodesPending(this.#client, this.#node, this.#vmid)) : this.#pending; }
  #unlink;
  /**
   * Get VmidQemuNodeNodesUnlink
   * @returns {PVEVmidQemuNodeNodesUnlink}
   */
  get unlink() { return this.#unlink == null ? (this.#unlink = new PVEVmidQemuNodeNodesUnlink(this.#client, this.#node, this.#vmid)) : this.#unlink; }
  #vncproxy;
  /**
   * Get VmidQemuNodeNodesVncproxy
   * @returns {PVEVmidQemuNodeNodesVncproxy}
   */
  get vncproxy() { return this.#vncproxy == null ? (this.#vncproxy = new PVEVmidQemuNodeNodesVncproxy(this.#client, this.#node, this.#vmid)) : this.#vncproxy; }
  #termproxy;
  /**
   * Get VmidQemuNodeNodesTermproxy
   * @returns {PVEVmidQemuNodeNodesTermproxy}
   */
  get termproxy() { return this.#termproxy == null ? (this.#termproxy = new PVEVmidQemuNodeNodesTermproxy(this.#client, this.#node, this.#vmid)) : this.#termproxy; }
  #vncwebsocket;
  /**
   * Get VmidQemuNodeNodesVncwebsocket
   * @returns {PVEVmidQemuNodeNodesVncwebsocket}
   */
  get vncwebsocket() { return this.#vncwebsocket == null ? (this.#vncwebsocket = new PVEVmidQemuNodeNodesVncwebsocket(this.#client, this.#node, this.#vmid)) : this.#vncwebsocket; }
  #spiceproxy;
  /**
   * Get VmidQemuNodeNodesSpiceproxy
   * @returns {PVEVmidQemuNodeNodesSpiceproxy}
   */
  get spiceproxy() { return this.#spiceproxy == null ? (this.#spiceproxy = new PVEVmidQemuNodeNodesSpiceproxy(this.#client, this.#node, this.#vmid)) : this.#spiceproxy; }
  #status;
  /**
   * Get VmidQemuNodeNodesStatus
   * @returns {PVEVmidQemuNodeNodesStatus}
   */
  get status() { return this.#status == null ? (this.#status = new PVEVmidQemuNodeNodesStatus(this.#client, this.#node, this.#vmid)) : this.#status; }
  #sendkey;
  /**
   * Get VmidQemuNodeNodesSendkey
   * @returns {PVEVmidQemuNodeNodesSendkey}
   */
  get sendkey() { return this.#sendkey == null ? (this.#sendkey = new PVEVmidQemuNodeNodesSendkey(this.#client, this.#node, this.#vmid)) : this.#sendkey; }
  #feature;
  /**
   * Get VmidQemuNodeNodesFeature
   * @returns {PVEVmidQemuNodeNodesFeature}
   */
  get feature() { return this.#feature == null ? (this.#feature = new PVEVmidQemuNodeNodesFeature(this.#client, this.#node, this.#vmid)) : this.#feature; }
  #clone;
  /**
   * Get VmidQemuNodeNodesClone
   * @returns {PVEVmidQemuNodeNodesClone}
   */
  get clone() { return this.#clone == null ? (this.#clone = new PVEVmidQemuNodeNodesClone(this.#client, this.#node, this.#vmid)) : this.#clone; }
  #moveDisk;
  /**
   * Get VmidQemuNodeNodesMoveDisk
   * @returns {PVEVmidQemuNodeNodesMoveDisk}
   */
  get moveDisk() { return this.#moveDisk == null ? (this.#moveDisk = new PVEVmidQemuNodeNodesMoveDisk(this.#client, this.#node, this.#vmid)) : this.#moveDisk; }
  #migrate;
  /**
   * Get VmidQemuNodeNodesMigrate
   * @returns {PVEVmidQemuNodeNodesMigrate}
   */
  get migrate() { return this.#migrate == null ? (this.#migrate = new PVEVmidQemuNodeNodesMigrate(this.#client, this.#node, this.#vmid)) : this.#migrate; }
  #monitor;
  /**
   * Get VmidQemuNodeNodesMonitor
   * @returns {PVEVmidQemuNodeNodesMonitor}
   */
  get monitor() { return this.#monitor == null ? (this.#monitor = new PVEVmidQemuNodeNodesMonitor(this.#client, this.#node, this.#vmid)) : this.#monitor; }
  #resize;
  /**
   * Get VmidQemuNodeNodesResize
   * @returns {PVEVmidQemuNodeNodesResize}
   */
  get resize() { return this.#resize == null ? (this.#resize = new PVEVmidQemuNodeNodesResize(this.#client, this.#node, this.#vmid)) : this.#resize; }
  #snapshot;
  /**
   * Get VmidQemuNodeNodesSnapshot
   * @returns {PVEVmidQemuNodeNodesSnapshot}
   */
  get snapshot() { return this.#snapshot == null ? (this.#snapshot = new PVEVmidQemuNodeNodesSnapshot(this.#client, this.#node, this.#vmid)) : this.#snapshot; }
  #template;
  /**
   * Get VmidQemuNodeNodesTemplate
   * @returns {PVEVmidQemuNodeNodesTemplate}
   */
  get template() { return this.#template == null ? (this.#template = new PVEVmidQemuNodeNodesTemplate(this.#client, this.#node, this.#vmid)) : this.#template; }
  #cloudinit;
  /**
   * Get VmidQemuNodeNodesCloudinit
   * @returns {PVEVmidQemuNodeNodesCloudinit}
   */
  get cloudinit() { return this.#cloudinit == null ? (this.#cloudinit = new PVEVmidQemuNodeNodesCloudinit(this.#client, this.#node, this.#vmid)) : this.#cloudinit; }


  /**
  * Destroy the VM and  all used/owned volumes. Removes any VM specific permissions and firewall rules
  * @param {bool} destroy_unreferenced_disks If set, destroy additionally all disks not referenced in the config but with a matching VMID from all enabled storages.
  * @param {bool} purge Remove VMID from configurations, like backup &amp; replication jobs and HA.
  * @param {bool} skiplock Ignore locks - only root is allowed to use this option.
  * @returns {Result}
  */
  async destroyVm(destroy_unreferenced_disks, purge, skiplock) {
    const parameters = {
      'destroy-unreferenced-disks': destroy_unreferenced_disks,
      'purge': purge,
      'skiplock': skiplock
    };
    return await this.#client.delete(`/nodes/${this.#node}/qemu/${this.#vmid}`, parameters);
  }
  /**
  * Directory index
  * @returns {Result}
  */
  async vmdiridx() {
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}`);
  }

}
/**
 * Class PVEVmidQemuNodeNodesFirewall
 */
class PVEVmidQemuNodeNodesFirewall {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }

  #rules;
  /**
   * Get FirewallVmidQemuNodeNodesRules
   * @returns {PVEFirewallVmidQemuNodeNodesRules}
   */
  get rules() { return this.#rules == null ? (this.#rules = new PVEFirewallVmidQemuNodeNodesRules(this.#client, this.#node, this.#vmid)) : this.#rules; }
  #aliases;
  /**
   * Get FirewallVmidQemuNodeNodesAliases
   * @returns {PVEFirewallVmidQemuNodeNodesAliases}
   */
  get aliases() { return this.#aliases == null ? (this.#aliases = new PVEFirewallVmidQemuNodeNodesAliases(this.#client, this.#node, this.#vmid)) : this.#aliases; }
  #ipset;
  /**
   * Get FirewallVmidQemuNodeNodesIpset
   * @returns {PVEFirewallVmidQemuNodeNodesIpset}
   */
  get ipset() { return this.#ipset == null ? (this.#ipset = new PVEFirewallVmidQemuNodeNodesIpset(this.#client, this.#node, this.#vmid)) : this.#ipset; }
  #options;
  /**
   * Get FirewallVmidQemuNodeNodesOptions
   * @returns {PVEFirewallVmidQemuNodeNodesOptions}
   */
  get options() { return this.#options == null ? (this.#options = new PVEFirewallVmidQemuNodeNodesOptions(this.#client, this.#node, this.#vmid)) : this.#options; }
  #log;
  /**
   * Get FirewallVmidQemuNodeNodesLog
   * @returns {PVEFirewallVmidQemuNodeNodesLog}
   */
  get log() { return this.#log == null ? (this.#log = new PVEFirewallVmidQemuNodeNodesLog(this.#client, this.#node, this.#vmid)) : this.#log; }
  #refs;
  /**
   * Get FirewallVmidQemuNodeNodesRefs
   * @returns {PVEFirewallVmidQemuNodeNodesRefs}
   */
  get refs() { return this.#refs == null ? (this.#refs = new PVEFirewallVmidQemuNodeNodesRefs(this.#client, this.#node, this.#vmid)) : this.#refs; }


  /**
  * Directory index.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/firewall`);
  }

}
/**
 * Class PVEFirewallVmidQemuNodeNodesRules
 */
class PVEFirewallVmidQemuNodeNodesRules {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }


  /**
   * Get ItemRulesFirewallVmidQemuNodeNodesPos
   * @param pos
   * @returns {PVEItemRulesFirewallVmidQemuNodeNodesPos}
   */
  get(pos) { return new PVEItemRulesFirewallVmidQemuNodeNodesPos(this.#client, this.#node, this.#vmid, pos); }

  /**
  * List rules.
  * @returns {Result}
  */
  async getRules() {
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/firewall/rules`);
  }
  /**
  * Create new rule.
  * @param {string} action Rule action ('ACCEPT', 'DROP', 'REJECT') or security group name.
  * @param {string} type Rule type.
  *   Enum: in,out,group
  * @param {string} comment Descriptive comment.
  * @param {string} dest Restrict packet destination address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {string} dport Restrict TCP/UDP destination port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
  * @param {int} enable Flag to enable/disable a rule.
  * @param {string} icmp_type Specify icmp-type. Only valid if proto equals 'icmp'.
  * @param {string} iface Network interface name. You have to use network configuration key names for VMs and containers ('net\d+'). Host related rules can use arbitrary strings.
  * @param {string} log Log level for firewall rule.
  *   Enum: emerg,alert,crit,err,warning,notice,info,debug,nolog
  * @param {string} macro Use predefined standard macro.
  * @param {int} pos Update rule at position &amp;lt;pos&amp;gt;.
  * @param {string} proto IP protocol. You can use protocol names ('tcp'/'udp') or simple numbers, as defined in '/etc/protocols'.
  * @param {string} source Restrict packet source address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
  * @param {string} sport Restrict TCP/UDP source port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
  * @returns {Result}
  */
  async createRule(action, type, comment, dest, digest, dport, enable, icmp_type, iface, log, macro, pos, proto, source, sport) {
    const parameters = {
      'action': action,
      'type': type,
      'comment': comment,
      'dest': dest,
      'digest': digest,
      'dport': dport,
      'enable': enable,
      'icmp-type': icmp_type,
      'iface': iface,
      'log': log,
      'macro': macro,
      'pos': pos,
      'proto': proto,
      'source': source,
      'sport': sport
    };
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/firewall/rules`, parameters);
  }

}
/**
 * Class PVEItemRulesFirewallVmidQemuNodeNodesPos
 */
class PVEItemRulesFirewallVmidQemuNodeNodesPos {
  #node;
  #vmid;
  #pos;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid, pos) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
    this.#pos = pos;
  }



  /**
  * Delete rule.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @returns {Result}
  */
  async deleteRule(digest) {
    const parameters = { 'digest': digest };
    return await this.#client.delete(`/nodes/${this.#node}/qemu/${this.#vmid}/firewall/rules/${this.#pos}`, parameters);
  }
  /**
  * Get single rule data.
  * @returns {Result}
  */
  async getRule() {
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/firewall/rules/${this.#pos}`);
  }
  /**
  * Modify rule data.
  * @param {string} action Rule action ('ACCEPT', 'DROP', 'REJECT') or security group name.
  * @param {string} comment Descriptive comment.
  * @param {string} delete_ A list of settings you want to delete.
  * @param {string} dest Restrict packet destination address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {string} dport Restrict TCP/UDP destination port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
  * @param {int} enable Flag to enable/disable a rule.
  * @param {string} icmp_type Specify icmp-type. Only valid if proto equals 'icmp'.
  * @param {string} iface Network interface name. You have to use network configuration key names for VMs and containers ('net\d+'). Host related rules can use arbitrary strings.
  * @param {string} log Log level for firewall rule.
  *   Enum: emerg,alert,crit,err,warning,notice,info,debug,nolog
  * @param {string} macro Use predefined standard macro.
  * @param {int} moveto Move rule to new position &amp;lt;moveto&amp;gt;. Other arguments are ignored.
  * @param {string} proto IP protocol. You can use protocol names ('tcp'/'udp') or simple numbers, as defined in '/etc/protocols'.
  * @param {string} source Restrict packet source address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
  * @param {string} sport Restrict TCP/UDP source port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
  * @param {string} type Rule type.
  *   Enum: in,out,group
  * @returns {Result}
  */
  async updateRule(action, comment, delete_, dest, digest, dport, enable, icmp_type, iface, log, macro, moveto, proto, source, sport, type) {
    const parameters = {
      'action': action,
      'comment': comment,
      'delete': delete_,
      'dest': dest,
      'digest': digest,
      'dport': dport,
      'enable': enable,
      'icmp-type': icmp_type,
      'iface': iface,
      'log': log,
      'macro': macro,
      'moveto': moveto,
      'proto': proto,
      'source': source,
      'sport': sport,
      'type': type
    };
    return await this.#client.set(`/nodes/${this.#node}/qemu/${this.#vmid}/firewall/rules/${this.#pos}`, parameters);
  }

}

/**
 * Class PVEFirewallVmidQemuNodeNodesAliases
 */
class PVEFirewallVmidQemuNodeNodesAliases {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }


  /**
   * Get ItemAliasesFirewallVmidQemuNodeNodesName
   * @param name
   * @returns {PVEItemAliasesFirewallVmidQemuNodeNodesName}
   */
  get(name) { return new PVEItemAliasesFirewallVmidQemuNodeNodesName(this.#client, this.#node, this.#vmid, name); }

  /**
  * List aliases
  * @returns {Result}
  */
  async getAliases() {
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/firewall/aliases`);
  }
  /**
  * Create IP or Network Alias.
  * @param {string} cidr Network/IP specification in CIDR format.
  * @param {string} name Alias name.
  * @param {string} comment
  * @returns {Result}
  */
  async createAlias(cidr, name, comment) {
    const parameters = {
      'cidr': cidr,
      'name': name,
      'comment': comment
    };
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/firewall/aliases`, parameters);
  }

}
/**
 * Class PVEItemAliasesFirewallVmidQemuNodeNodesName
 */
class PVEItemAliasesFirewallVmidQemuNodeNodesName {
  #node;
  #vmid;
  #name;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid, name) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
    this.#name = name;
  }



  /**
  * Remove IP or Network alias.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @returns {Result}
  */
  async removeAlias(digest) {
    const parameters = { 'digest': digest };
    return await this.#client.delete(`/nodes/${this.#node}/qemu/${this.#vmid}/firewall/aliases/${this.#name}`, parameters);
  }
  /**
  * Read alias.
  * @returns {Result}
  */
  async readAlias() {
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/firewall/aliases/${this.#name}`);
  }
  /**
  * Update IP or Network alias.
  * @param {string} cidr Network/IP specification in CIDR format.
  * @param {string} comment
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {string} rename Rename an existing alias.
  * @returns {Result}
  */
  async updateAlias(cidr, comment, digest, rename) {
    const parameters = {
      'cidr': cidr,
      'comment': comment,
      'digest': digest,
      'rename': rename
    };
    return await this.#client.set(`/nodes/${this.#node}/qemu/${this.#vmid}/firewall/aliases/${this.#name}`, parameters);
  }

}

/**
 * Class PVEFirewallVmidQemuNodeNodesIpset
 */
class PVEFirewallVmidQemuNodeNodesIpset {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }


  /**
   * Get ItemIpsetFirewallVmidQemuNodeNodesName
   * @param name
   * @returns {PVEItemIpsetFirewallVmidQemuNodeNodesName}
   */
  get(name) { return new PVEItemIpsetFirewallVmidQemuNodeNodesName(this.#client, this.#node, this.#vmid, name); }

  /**
  * List IPSets
  * @returns {Result}
  */
  async ipsetIndex() {
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/firewall/ipset`);
  }
  /**
  * Create new IPSet
  * @param {string} name IP set name.
  * @param {string} comment
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {string} rename Rename an existing IPSet. You can set 'rename' to the same value as 'name' to update the 'comment' of an existing IPSet.
  * @returns {Result}
  */
  async createIpset(name, comment, digest, rename) {
    const parameters = {
      'name': name,
      'comment': comment,
      'digest': digest,
      'rename': rename
    };
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/firewall/ipset`, parameters);
  }

}
/**
 * Class PVEItemIpsetFirewallVmidQemuNodeNodesName
 */
class PVEItemIpsetFirewallVmidQemuNodeNodesName {
  #node;
  #vmid;
  #name;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid, name) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
    this.#name = name;
  }


  /**
   * Get ItemNameIpsetFirewallVmidQemuNodeNodesCidr
   * @param cidr
   * @returns {PVEItemNameIpsetFirewallVmidQemuNodeNodesCidr}
   */
  get(cidr) { return new PVEItemNameIpsetFirewallVmidQemuNodeNodesCidr(this.#client, this.#node, this.#vmid, this.#name, cidr); }

  /**
  * Delete IPSet
  * @returns {Result}
  */
  async deleteIpset() {
    return await this.#client.delete(`/nodes/${this.#node}/qemu/${this.#vmid}/firewall/ipset/${this.#name}`);
  }
  /**
  * List IPSet content
  * @returns {Result}
  */
  async getIpset() {
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/firewall/ipset/${this.#name}`);
  }
  /**
  * Add IP or Network to IPSet.
  * @param {string} cidr Network/IP specification in CIDR format.
  * @param {string} comment
  * @param {bool} nomatch
  * @returns {Result}
  */
  async createIp(cidr, comment, nomatch) {
    const parameters = {
      'cidr': cidr,
      'comment': comment,
      'nomatch': nomatch
    };
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/firewall/ipset/${this.#name}`, parameters);
  }

}
/**
 * Class PVEItemNameIpsetFirewallVmidQemuNodeNodesCidr
 */
class PVEItemNameIpsetFirewallVmidQemuNodeNodesCidr {
  #node;
  #vmid;
  #name;
  #cidr;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid, name, cidr) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
    this.#name = name;
    this.#cidr = cidr;
  }



  /**
  * Remove IP or Network from IPSet.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @returns {Result}
  */
  async removeIp(digest) {
    const parameters = { 'digest': digest };
    return await this.#client.delete(`/nodes/${this.#node}/qemu/${this.#vmid}/firewall/ipset/${this.#name}/${this.#cidr}`, parameters);
  }
  /**
  * Read IP or Network settings from IPSet.
  * @returns {Result}
  */
  async readIp() {
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/firewall/ipset/${this.#name}/${this.#cidr}`);
  }
  /**
  * Update IP or Network settings
  * @param {string} comment
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {bool} nomatch
  * @returns {Result}
  */
  async updateIp(comment, digest, nomatch) {
    const parameters = {
      'comment': comment,
      'digest': digest,
      'nomatch': nomatch
    };
    return await this.#client.set(`/nodes/${this.#node}/qemu/${this.#vmid}/firewall/ipset/${this.#name}/${this.#cidr}`, parameters);
  }

}

/**
 * Class PVEFirewallVmidQemuNodeNodesOptions
 */
class PVEFirewallVmidQemuNodeNodesOptions {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Get VM firewall options.
  * @returns {Result}
  */
  async getOptions() {
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/firewall/options`);
  }
  /**
  * Set Firewall options.
  * @param {string} delete_ A list of settings you want to delete.
  * @param {bool} dhcp Enable DHCP.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {bool} enable Enable/disable firewall rules.
  * @param {bool} ipfilter Enable default IP filters. This is equivalent to adding an empty ipfilter-net&amp;lt;id&amp;gt; ipset for every interface. Such ipsets implicitly contain sane default restrictions such as restricting IPv6 link local addresses to the one derived from the interface's MAC address. For containers the configured IP addresses will be implicitly added.
  * @param {string} log_level_in Log level for incoming traffic.
  *   Enum: emerg,alert,crit,err,warning,notice,info,debug,nolog
  * @param {string} log_level_out Log level for outgoing traffic.
  *   Enum: emerg,alert,crit,err,warning,notice,info,debug,nolog
  * @param {bool} macfilter Enable/disable MAC address filter.
  * @param {bool} ndp Enable NDP (Neighbor Discovery Protocol).
  * @param {string} policy_in Input policy.
  *   Enum: ACCEPT,REJECT,DROP
  * @param {string} policy_out Output policy.
  *   Enum: ACCEPT,REJECT,DROP
  * @param {bool} radv Allow sending Router Advertisement.
  * @returns {Result}
  */
  async setOptions(delete_, dhcp, digest, enable, ipfilter, log_level_in, log_level_out, macfilter, ndp, policy_in, policy_out, radv) {
    const parameters = {
      'delete': delete_,
      'dhcp': dhcp,
      'digest': digest,
      'enable': enable,
      'ipfilter': ipfilter,
      'log_level_in': log_level_in,
      'log_level_out': log_level_out,
      'macfilter': macfilter,
      'ndp': ndp,
      'policy_in': policy_in,
      'policy_out': policy_out,
      'radv': radv
    };
    return await this.#client.set(`/nodes/${this.#node}/qemu/${this.#vmid}/firewall/options`, parameters);
  }

}

/**
 * Class PVEFirewallVmidQemuNodeNodesLog
 */
class PVEFirewallVmidQemuNodeNodesLog {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Read firewall log
  * @param {int} limit
  * @param {int} start
  * @returns {Result}
  */
  async log(limit, start) {
    const parameters = {
      'limit': limit,
      'start': start
    };
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/firewall/log`, parameters);
  }

}

/**
 * Class PVEFirewallVmidQemuNodeNodesRefs
 */
class PVEFirewallVmidQemuNodeNodesRefs {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Lists possible IPSet/Alias reference which are allowed in source/dest properties.
  * @param {string} type Only list references of specified type.
  *   Enum: alias,ipset
  * @returns {Result}
  */
  async refs(type) {
    const parameters = { 'type': type };
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/firewall/refs`, parameters);
  }

}

/**
 * Class PVEVmidQemuNodeNodesAgent
 */
class PVEVmidQemuNodeNodesAgent {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }

  #fsfreezeFreeze;
  /**
   * Get AgentVmidQemuNodeNodesFsfreezeFreeze
   * @returns {PVEAgentVmidQemuNodeNodesFsfreezeFreeze}
   */
  get fsfreezeFreeze() { return this.#fsfreezeFreeze == null ? (this.#fsfreezeFreeze = new PVEAgentVmidQemuNodeNodesFsfreezeFreeze(this.#client, this.#node, this.#vmid)) : this.#fsfreezeFreeze; }
  #fsfreezeStatus;
  /**
   * Get AgentVmidQemuNodeNodesFsfreezeStatus
   * @returns {PVEAgentVmidQemuNodeNodesFsfreezeStatus}
   */
  get fsfreezeStatus() { return this.#fsfreezeStatus == null ? (this.#fsfreezeStatus = new PVEAgentVmidQemuNodeNodesFsfreezeStatus(this.#client, this.#node, this.#vmid)) : this.#fsfreezeStatus; }
  #fsfreezeThaw;
  /**
   * Get AgentVmidQemuNodeNodesFsfreezeThaw
   * @returns {PVEAgentVmidQemuNodeNodesFsfreezeThaw}
   */
  get fsfreezeThaw() { return this.#fsfreezeThaw == null ? (this.#fsfreezeThaw = new PVEAgentVmidQemuNodeNodesFsfreezeThaw(this.#client, this.#node, this.#vmid)) : this.#fsfreezeThaw; }
  #fstrim;
  /**
   * Get AgentVmidQemuNodeNodesFstrim
   * @returns {PVEAgentVmidQemuNodeNodesFstrim}
   */
  get fstrim() { return this.#fstrim == null ? (this.#fstrim = new PVEAgentVmidQemuNodeNodesFstrim(this.#client, this.#node, this.#vmid)) : this.#fstrim; }
  #getFsinfo;
  /**
   * Get AgentVmidQemuNodeNodesGetFsinfo
   * @returns {PVEAgentVmidQemuNodeNodesGetFsinfo}
   */
  get getFsinfo() { return this.#getFsinfo == null ? (this.#getFsinfo = new PVEAgentVmidQemuNodeNodesGetFsinfo(this.#client, this.#node, this.#vmid)) : this.#getFsinfo; }
  #getHostName;
  /**
   * Get AgentVmidQemuNodeNodesGetHostName
   * @returns {PVEAgentVmidQemuNodeNodesGetHostName}
   */
  get getHostName() { return this.#getHostName == null ? (this.#getHostName = new PVEAgentVmidQemuNodeNodesGetHostName(this.#client, this.#node, this.#vmid)) : this.#getHostName; }
  #getMemoryBlockInfo;
  /**
   * Get AgentVmidQemuNodeNodesGetMemoryBlockInfo
   * @returns {PVEAgentVmidQemuNodeNodesGetMemoryBlockInfo}
   */
  get getMemoryBlockInfo() { return this.#getMemoryBlockInfo == null ? (this.#getMemoryBlockInfo = new PVEAgentVmidQemuNodeNodesGetMemoryBlockInfo(this.#client, this.#node, this.#vmid)) : this.#getMemoryBlockInfo; }
  #getMemoryBlocks;
  /**
   * Get AgentVmidQemuNodeNodesGetMemoryBlocks
   * @returns {PVEAgentVmidQemuNodeNodesGetMemoryBlocks}
   */
  get getMemoryBlocks() { return this.#getMemoryBlocks == null ? (this.#getMemoryBlocks = new PVEAgentVmidQemuNodeNodesGetMemoryBlocks(this.#client, this.#node, this.#vmid)) : this.#getMemoryBlocks; }
  #getOsinfo;
  /**
   * Get AgentVmidQemuNodeNodesGetOsinfo
   * @returns {PVEAgentVmidQemuNodeNodesGetOsinfo}
   */
  get getOsinfo() { return this.#getOsinfo == null ? (this.#getOsinfo = new PVEAgentVmidQemuNodeNodesGetOsinfo(this.#client, this.#node, this.#vmid)) : this.#getOsinfo; }
  #getTime;
  /**
   * Get AgentVmidQemuNodeNodesGetTime
   * @returns {PVEAgentVmidQemuNodeNodesGetTime}
   */
  get getTime() { return this.#getTime == null ? (this.#getTime = new PVEAgentVmidQemuNodeNodesGetTime(this.#client, this.#node, this.#vmid)) : this.#getTime; }
  #getTimezone;
  /**
   * Get AgentVmidQemuNodeNodesGetTimezone
   * @returns {PVEAgentVmidQemuNodeNodesGetTimezone}
   */
  get getTimezone() { return this.#getTimezone == null ? (this.#getTimezone = new PVEAgentVmidQemuNodeNodesGetTimezone(this.#client, this.#node, this.#vmid)) : this.#getTimezone; }
  #getUsers;
  /**
   * Get AgentVmidQemuNodeNodesGetUsers
   * @returns {PVEAgentVmidQemuNodeNodesGetUsers}
   */
  get getUsers() { return this.#getUsers == null ? (this.#getUsers = new PVEAgentVmidQemuNodeNodesGetUsers(this.#client, this.#node, this.#vmid)) : this.#getUsers; }
  #getVcpus;
  /**
   * Get AgentVmidQemuNodeNodesGetVcpus
   * @returns {PVEAgentVmidQemuNodeNodesGetVcpus}
   */
  get getVcpus() { return this.#getVcpus == null ? (this.#getVcpus = new PVEAgentVmidQemuNodeNodesGetVcpus(this.#client, this.#node, this.#vmid)) : this.#getVcpus; }
  #info;
  /**
   * Get AgentVmidQemuNodeNodesInfo
   * @returns {PVEAgentVmidQemuNodeNodesInfo}
   */
  get info() { return this.#info == null ? (this.#info = new PVEAgentVmidQemuNodeNodesInfo(this.#client, this.#node, this.#vmid)) : this.#info; }
  #networkGetInterfaces;
  /**
   * Get AgentVmidQemuNodeNodesNetworkGetInterfaces
   * @returns {PVEAgentVmidQemuNodeNodesNetworkGetInterfaces}
   */
  get networkGetInterfaces() { return this.#networkGetInterfaces == null ? (this.#networkGetInterfaces = new PVEAgentVmidQemuNodeNodesNetworkGetInterfaces(this.#client, this.#node, this.#vmid)) : this.#networkGetInterfaces; }
  #ping;
  /**
   * Get AgentVmidQemuNodeNodesPing
   * @returns {PVEAgentVmidQemuNodeNodesPing}
   */
  get ping() { return this.#ping == null ? (this.#ping = new PVEAgentVmidQemuNodeNodesPing(this.#client, this.#node, this.#vmid)) : this.#ping; }
  #shutdown;
  /**
   * Get AgentVmidQemuNodeNodesShutdown
   * @returns {PVEAgentVmidQemuNodeNodesShutdown}
   */
  get shutdown() { return this.#shutdown == null ? (this.#shutdown = new PVEAgentVmidQemuNodeNodesShutdown(this.#client, this.#node, this.#vmid)) : this.#shutdown; }
  #suspendDisk;
  /**
   * Get AgentVmidQemuNodeNodesSuspendDisk
   * @returns {PVEAgentVmidQemuNodeNodesSuspendDisk}
   */
  get suspendDisk() { return this.#suspendDisk == null ? (this.#suspendDisk = new PVEAgentVmidQemuNodeNodesSuspendDisk(this.#client, this.#node, this.#vmid)) : this.#suspendDisk; }
  #suspendHybrid;
  /**
   * Get AgentVmidQemuNodeNodesSuspendHybrid
   * @returns {PVEAgentVmidQemuNodeNodesSuspendHybrid}
   */
  get suspendHybrid() { return this.#suspendHybrid == null ? (this.#suspendHybrid = new PVEAgentVmidQemuNodeNodesSuspendHybrid(this.#client, this.#node, this.#vmid)) : this.#suspendHybrid; }
  #suspendRam;
  /**
   * Get AgentVmidQemuNodeNodesSuspendRam
   * @returns {PVEAgentVmidQemuNodeNodesSuspendRam}
   */
  get suspendRam() { return this.#suspendRam == null ? (this.#suspendRam = new PVEAgentVmidQemuNodeNodesSuspendRam(this.#client, this.#node, this.#vmid)) : this.#suspendRam; }
  #setUserPassword;
  /**
   * Get AgentVmidQemuNodeNodesSetUserPassword
   * @returns {PVEAgentVmidQemuNodeNodesSetUserPassword}
   */
  get setUserPassword() { return this.#setUserPassword == null ? (this.#setUserPassword = new PVEAgentVmidQemuNodeNodesSetUserPassword(this.#client, this.#node, this.#vmid)) : this.#setUserPassword; }
  #exec;
  /**
   * Get AgentVmidQemuNodeNodesExec
   * @returns {PVEAgentVmidQemuNodeNodesExec}
   */
  get exec() { return this.#exec == null ? (this.#exec = new PVEAgentVmidQemuNodeNodesExec(this.#client, this.#node, this.#vmid)) : this.#exec; }
  #execStatus;
  /**
   * Get AgentVmidQemuNodeNodesExecStatus
   * @returns {PVEAgentVmidQemuNodeNodesExecStatus}
   */
  get execStatus() { return this.#execStatus == null ? (this.#execStatus = new PVEAgentVmidQemuNodeNodesExecStatus(this.#client, this.#node, this.#vmid)) : this.#execStatus; }
  #fileRead;
  /**
   * Get AgentVmidQemuNodeNodesFileRead
   * @returns {PVEAgentVmidQemuNodeNodesFileRead}
   */
  get fileRead() { return this.#fileRead == null ? (this.#fileRead = new PVEAgentVmidQemuNodeNodesFileRead(this.#client, this.#node, this.#vmid)) : this.#fileRead; }
  #fileWrite;
  /**
   * Get AgentVmidQemuNodeNodesFileWrite
   * @returns {PVEAgentVmidQemuNodeNodesFileWrite}
   */
  get fileWrite() { return this.#fileWrite == null ? (this.#fileWrite = new PVEAgentVmidQemuNodeNodesFileWrite(this.#client, this.#node, this.#vmid)) : this.#fileWrite; }


  /**
  * Qemu Agent command index.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/agent`);
  }
  /**
  * Execute Qemu Guest Agent commands.
  * @param {string} command The QGA command.
  *   Enum: fsfreeze-freeze,fsfreeze-status,fsfreeze-thaw,fstrim,get-fsinfo,get-host-name,get-memory-block-info,get-memory-blocks,get-osinfo,get-time,get-timezone,get-users,get-vcpus,info,network-get-interfaces,ping,shutdown,suspend-disk,suspend-hybrid,suspend-ram
  * @returns {Result}
  */
  async agent(command) {
    const parameters = { 'command': command };
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/agent`, parameters);
  }

}
/**
 * Class PVEAgentVmidQemuNodeNodesFsfreezeFreeze
 */
class PVEAgentVmidQemuNodeNodesFsfreezeFreeze {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Execute fsfreeze-freeze.
  * @returns {Result}
  */
  async fsfreezeFreeze() {
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/agent/fsfreeze-freeze`);
  }

}

/**
 * Class PVEAgentVmidQemuNodeNodesFsfreezeStatus
 */
class PVEAgentVmidQemuNodeNodesFsfreezeStatus {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Execute fsfreeze-status.
  * @returns {Result}
  */
  async fsfreezeStatus() {
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/agent/fsfreeze-status`);
  }

}

/**
 * Class PVEAgentVmidQemuNodeNodesFsfreezeThaw
 */
class PVEAgentVmidQemuNodeNodesFsfreezeThaw {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Execute fsfreeze-thaw.
  * @returns {Result}
  */
  async fsfreezeThaw() {
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/agent/fsfreeze-thaw`);
  }

}

/**
 * Class PVEAgentVmidQemuNodeNodesFstrim
 */
class PVEAgentVmidQemuNodeNodesFstrim {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Execute fstrim.
  * @returns {Result}
  */
  async fstrim() {
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/agent/fstrim`);
  }

}

/**
 * Class PVEAgentVmidQemuNodeNodesGetFsinfo
 */
class PVEAgentVmidQemuNodeNodesGetFsinfo {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Execute get-fsinfo.
  * @returns {Result}
  */
  async getFsinfo() {
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/agent/get-fsinfo`);
  }

}

/**
 * Class PVEAgentVmidQemuNodeNodesGetHostName
 */
class PVEAgentVmidQemuNodeNodesGetHostName {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Execute get-host-name.
  * @returns {Result}
  */
  async getHostName() {
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/agent/get-host-name`);
  }

}

/**
 * Class PVEAgentVmidQemuNodeNodesGetMemoryBlockInfo
 */
class PVEAgentVmidQemuNodeNodesGetMemoryBlockInfo {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Execute get-memory-block-info.
  * @returns {Result}
  */
  async getMemoryBlockInfo() {
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/agent/get-memory-block-info`);
  }

}

/**
 * Class PVEAgentVmidQemuNodeNodesGetMemoryBlocks
 */
class PVEAgentVmidQemuNodeNodesGetMemoryBlocks {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Execute get-memory-blocks.
  * @returns {Result}
  */
  async getMemoryBlocks() {
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/agent/get-memory-blocks`);
  }

}

/**
 * Class PVEAgentVmidQemuNodeNodesGetOsinfo
 */
class PVEAgentVmidQemuNodeNodesGetOsinfo {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Execute get-osinfo.
  * @returns {Result}
  */
  async getOsinfo() {
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/agent/get-osinfo`);
  }

}

/**
 * Class PVEAgentVmidQemuNodeNodesGetTime
 */
class PVEAgentVmidQemuNodeNodesGetTime {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Execute get-time.
  * @returns {Result}
  */
  async getTime() {
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/agent/get-time`);
  }

}

/**
 * Class PVEAgentVmidQemuNodeNodesGetTimezone
 */
class PVEAgentVmidQemuNodeNodesGetTimezone {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Execute get-timezone.
  * @returns {Result}
  */
  async getTimezone() {
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/agent/get-timezone`);
  }

}

/**
 * Class PVEAgentVmidQemuNodeNodesGetUsers
 */
class PVEAgentVmidQemuNodeNodesGetUsers {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Execute get-users.
  * @returns {Result}
  */
  async getUsers() {
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/agent/get-users`);
  }

}

/**
 * Class PVEAgentVmidQemuNodeNodesGetVcpus
 */
class PVEAgentVmidQemuNodeNodesGetVcpus {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Execute get-vcpus.
  * @returns {Result}
  */
  async getVcpus() {
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/agent/get-vcpus`);
  }

}

/**
 * Class PVEAgentVmidQemuNodeNodesInfo
 */
class PVEAgentVmidQemuNodeNodesInfo {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Execute info.
  * @returns {Result}
  */
  async info() {
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/agent/info`);
  }

}

/**
 * Class PVEAgentVmidQemuNodeNodesNetworkGetInterfaces
 */
class PVEAgentVmidQemuNodeNodesNetworkGetInterfaces {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Execute network-get-interfaces.
  * @returns {Result}
  */
  async networkGetInterfaces() {
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/agent/network-get-interfaces`);
  }

}

/**
 * Class PVEAgentVmidQemuNodeNodesPing
 */
class PVEAgentVmidQemuNodeNodesPing {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Execute ping.
  * @returns {Result}
  */
  async ping() {
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/agent/ping`);
  }

}

/**
 * Class PVEAgentVmidQemuNodeNodesShutdown
 */
class PVEAgentVmidQemuNodeNodesShutdown {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Execute shutdown.
  * @returns {Result}
  */
  async shutdown() {
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/agent/shutdown`);
  }

}

/**
 * Class PVEAgentVmidQemuNodeNodesSuspendDisk
 */
class PVEAgentVmidQemuNodeNodesSuspendDisk {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Execute suspend-disk.
  * @returns {Result}
  */
  async suspendDisk() {
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/agent/suspend-disk`);
  }

}

/**
 * Class PVEAgentVmidQemuNodeNodesSuspendHybrid
 */
class PVEAgentVmidQemuNodeNodesSuspendHybrid {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Execute suspend-hybrid.
  * @returns {Result}
  */
  async suspendHybrid() {
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/agent/suspend-hybrid`);
  }

}

/**
 * Class PVEAgentVmidQemuNodeNodesSuspendRam
 */
class PVEAgentVmidQemuNodeNodesSuspendRam {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Execute suspend-ram.
  * @returns {Result}
  */
  async suspendRam() {
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/agent/suspend-ram`);
  }

}

/**
 * Class PVEAgentVmidQemuNodeNodesSetUserPassword
 */
class PVEAgentVmidQemuNodeNodesSetUserPassword {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Sets the password for the given user to the given password
  * @param {string} password The new password.
  * @param {string} username The user to set the password for.
  * @param {bool} crypted set to 1 if the password has already been passed through crypt()
  * @returns {Result}
  */
  async setUserPassword(password, username, crypted) {
    const parameters = {
      'password': password,
      'username': username,
      'crypted': crypted
    };
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/agent/set-user-password`, parameters);
  }

}

/**
 * Class PVEAgentVmidQemuNodeNodesExec
 */
class PVEAgentVmidQemuNodeNodesExec {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Executes the given command in the vm via the guest-agent and returns an object with the pid.
  * @param {string} command The command as a list of program + arguments
  * @param {string} input_data Data to pass as 'input-data' to the guest. Usually treated as STDIN to 'command'.
  * @returns {Result}
  */
  async exec(command, input_data) {
    const parameters = {
      'command': command,
      'input-data': input_data
    };
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/agent/exec`, parameters);
  }

}

/**
 * Class PVEAgentVmidQemuNodeNodesExecStatus
 */
class PVEAgentVmidQemuNodeNodesExecStatus {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Gets the status of the given pid started by the guest-agent
  * @param {int} pid The PID to query
  * @returns {Result}
  */
  async execStatus(pid) {
    const parameters = { 'pid': pid };
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/agent/exec-status`, parameters);
  }

}

/**
 * Class PVEAgentVmidQemuNodeNodesFileRead
 */
class PVEAgentVmidQemuNodeNodesFileRead {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Reads the given file via guest agent. Is limited to 16777216 bytes.
  * @param {string} file The path to the file
  * @returns {Result}
  */
  async fileRead(file) {
    const parameters = { 'file': file };
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/agent/file-read`, parameters);
  }

}

/**
 * Class PVEAgentVmidQemuNodeNodesFileWrite
 */
class PVEAgentVmidQemuNodeNodesFileWrite {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Writes the given file via guest agent.
  * @param {string} content The content to write into the file.
  * @param {string} file The path to the file.
  * @returns {Result}
  */
  async fileWrite(content, file) {
    const parameters = {
      'content': content,
      'file': file
    };
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/agent/file-write`, parameters);
  }

}

/**
 * Class PVEVmidQemuNodeNodesRrd
 */
class PVEVmidQemuNodeNodesRrd {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Read VM RRD statistics (returns PNG)
  * @param {string} ds The list of datasources you want to display.
  * @param {string} timeframe Specify the time frame you are interested in.
  *   Enum: hour,day,week,month,year
  * @param {string} cf The RRD consolidation function
  *   Enum: AVERAGE,MAX
  * @returns {Result}
  */
  async rrd(ds, timeframe, cf) {
    const parameters = {
      'ds': ds,
      'timeframe': timeframe,
      'cf': cf
    };
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/rrd`, parameters);
  }

}

/**
 * Class PVEVmidQemuNodeNodesRrddata
 */
class PVEVmidQemuNodeNodesRrddata {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Read VM RRD statistics
  * @param {string} timeframe Specify the time frame you are interested in.
  *   Enum: hour,day,week,month,year
  * @param {string} cf The RRD consolidation function
  *   Enum: AVERAGE,MAX
  * @returns {Result}
  */
  async rrddata(timeframe, cf) {
    const parameters = {
      'timeframe': timeframe,
      'cf': cf
    };
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/rrddata`, parameters);
  }

}

/**
 * Class PVEVmidQemuNodeNodesConfig
 */
class PVEVmidQemuNodeNodesConfig {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Get the virtual machine configuration with pending configuration changes applied. Set the 'current' parameter to get the current configuration instead.
  * @param {bool} current Get current values (instead of pending values).
  * @param {string} snapshot Fetch config values from given snapshot.
  * @returns {Result}
  */
  async vmConfig(current, snapshot) {
    const parameters = {
      'current': current,
      'snapshot': snapshot
    };
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/config`, parameters);
  }
  /**
  * Set virtual machine options (asynchrounous API).
  * @param {bool} acpi Enable/disable ACPI.
  * @param {string} agent Enable/disable communication with the Qemu Guest Agent and its properties.
  * @param {string} arch Virtual processor architecture. Defaults to the host.
  *   Enum: x86_64,aarch64
  * @param {string} args Arbitrary arguments passed to kvm.
  * @param {string} audio0 Configure a audio device, useful in combination with QXL/Spice.
  * @param {bool} autostart Automatic restart after crash (currently ignored).
  * @param {int} background_delay Time to wait for the task to finish. We return 'null' if the task finish within that time.
  * @param {int} balloon Amount of target RAM for the VM in MB. Using zero disables the ballon driver.
  * @param {string} bios Select BIOS implementation.
  *   Enum: seabios,ovmf
  * @param {string} boot Specify guest boot order. Use the 'order=' sub-property as usage with no key or 'legacy=' is deprecated.
  * @param {string} bootdisk Enable booting from specified disk. Deprecated: Use 'boot: order=foo;bar' instead.
  * @param {string} cdrom This is an alias for option -ide2
  * @param {string} cicustom cloud-init: Specify custom files to replace the automatically generated ones at start.
  * @param {string} cipassword cloud-init: Password to assign the user. Using this is generally not recommended. Use ssh keys instead. Also note that older cloud-init versions do not support hashed passwords.
  * @param {string} citype Specifies the cloud-init configuration format. The default depends on the configured operating system type (`ostype`. We use the `nocloud` format for Linux, and `configdrive2` for windows.
  *   Enum: configdrive2,nocloud,opennebula
  * @param {string} ciuser cloud-init: User name to change ssh keys and password for instead of the image's configured default user.
  * @param {int} cores The number of cores per socket.
  * @param {string} cpu Emulated CPU type.
  * @param {float} cpulimit Limit of CPU usage.
  * @param {int} cpuunits CPU weight for a VM, will be clamped to [1, 10000] in cgroup v2.
  * @param {string} delete_ A list of settings you want to delete.
  * @param {string} description Description for the VM. Shown in the web-interface VM's summary. This is saved as comment inside the configuration file.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {string} efidisk0 Configure a Disk for storing EFI vars. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume. Note that SIZE_IN_GiB is ignored here and that the default EFI vars are copied to the volume instead.
  * @param {bool} force Force physical removal. Without this, we simple remove the disk from the config file and create an additional configuration entry called 'unused[n]', which contains the volume ID. Unlink of unused[n] always cause physical removal.
  * @param {bool} freeze Freeze CPU at startup (use 'c' monitor command to start execution).
  * @param {string} hookscript Script that will be executed during various steps in the vms lifetime.
  * @param {array} hostpciN Map host PCI devices into guest.
  * @param {string} hotplug Selectively enable hotplug features. This is a comma separated list of hotplug features: 'network', 'disk', 'cpu', 'memory' and 'usb'. Use '0' to disable hotplug completely. Using '1' as value is an alias for the default `network,disk,usb`.
  * @param {string} hugepages Enable/disable hugepages memory.
  *   Enum: any,2,1024
  * @param {array} ideN Use volume as IDE hard disk or CD-ROM (n is 0 to 3). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
  * @param {array} ipconfigN cloud-init: Specify IP addresses and gateways for the corresponding interface.  IP addresses use CIDR notation, gateways are optional but need an IP of the same type specified.  The special string 'dhcp' can be used for IP addresses to use DHCP, in which case no explicit gateway should be provided. For IPv6 the special string 'auto' can be used to use stateless autoconfiguration. This requires cloud-init 19.4 or newer.  If cloud-init is enabled and neither an IPv4 nor an IPv6 address is specified, it defaults to using dhcp on IPv4.
  * @param {string} ivshmem Inter-VM shared memory. Useful for direct communication between VMs, or to the host.
  * @param {bool} keephugepages Use together with hugepages. If enabled, hugepages will not not be deleted after VM shutdown and can be used for subsequent starts.
  * @param {string} keyboard Keyboard layout for VNC server. The default is read from the'/etc/pve/datacenter.cfg' configuration file. It should not be necessary to set it.
  *   Enum: de,de-ch,da,en-gb,en-us,es,fi,fr,fr-be,fr-ca,fr-ch,hu,is,it,ja,lt,mk,nl,no,pl,pt,pt-br,sv,sl,tr
  * @param {bool} kvm Enable/disable KVM hardware virtualization.
  * @param {bool} localtime Set the real time clock (RTC) to local time. This is enabled by default if the `ostype` indicates a Microsoft Windows OS.
  * @param {string} lock Lock/unlock the VM.
  *   Enum: backup,clone,create,migrate,rollback,snapshot,snapshot-delete,suspending,suspended
  * @param {string} machine Specifies the Qemu machine type.
  * @param {int} memory Amount of RAM for the VM in MB. This is the maximum available memory when you use the balloon device.
  * @param {float} migrate_downtime Set maximum tolerated downtime (in seconds) for migrations.
  * @param {int} migrate_speed Set maximum speed (in MB/s) for migrations. Value 0 is no limit.
  * @param {string} name Set a name for the VM. Only used on the configuration web interface.
  * @param {string} nameserver cloud-init: Sets DNS server IP address for a container. Create will' 	    .' automatically use the setting from the host if neither searchdomain nor nameserver' 	    .' are set.
  * @param {array} netN Specify network devices.
  * @param {bool} numa Enable/disable NUMA.
  * @param {array} numaN NUMA topology.
  * @param {bool} onboot Specifies whether a VM will be started during system bootup.
  * @param {string} ostype Specify guest operating system.
  *   Enum: other,wxp,w2k,w2k3,w2k8,wvista,win7,win8,win10,win11,l24,l26,solaris
  * @param {array} parallelN Map host parallel devices (n is 0 to 2).
  * @param {bool} protection Sets the protection flag of the VM. This will disable the remove VM and remove disk operations.
  * @param {bool} reboot Allow reboot. If set to '0' the VM exit on reboot.
  * @param {string} revert Revert a pending change.
  * @param {string} rng0 Configure a VirtIO-based Random Number Generator.
  * @param {array} sataN Use volume as SATA hard disk or CD-ROM (n is 0 to 5). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
  * @param {array} scsiN Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
  * @param {string} scsihw SCSI controller model
  *   Enum: lsi,lsi53c810,virtio-scsi-pci,virtio-scsi-single,megasas,pvscsi
  * @param {string} searchdomain cloud-init: Sets DNS search domains for a container. Create will' 	    .' automatically use the setting from the host if neither searchdomain nor nameserver' 	    .' are set.
  * @param {array} serialN Create a serial device inside the VM (n is 0 to 3)
  * @param {int} shares Amount of memory shares for auto-ballooning. The larger the number is, the more memory this VM gets. Number is relative to weights of all other running VMs. Using zero disables auto-ballooning. Auto-ballooning is done by pvestatd.
  * @param {bool} skiplock Ignore locks - only root is allowed to use this option.
  * @param {string} smbios1 Specify SMBIOS type 1 fields.
  * @param {int} smp The number of CPUs. Please use option -sockets instead.
  * @param {int} sockets The number of CPU sockets.
  * @param {string} spice_enhancements Configure additional enhancements for SPICE.
  * @param {string} sshkeys cloud-init: Setup public SSH keys (one key per line, OpenSSH format).
  * @param {string} startdate Set the initial date of the real time clock. Valid format for date are:'now' or '2006-06-17T16:01:21' or '2006-06-17'.
  * @param {string} startup Startup and shutdown behavior. Order is a non-negative number defining the general startup order. Shutdown in done with reverse ordering. Additionally you can set the 'up' or 'down' delay in seconds, which specifies a delay to wait before the next VM is started or stopped.
  * @param {bool} tablet Enable/disable the USB tablet device.
  * @param {string} tags Tags of the VM. This is only meta information.
  * @param {bool} tdf Enable/disable time drift fix.
  * @param {bool} template Enable/disable Template.
  * @param {string} tpmstate0 Configure a Disk for storing TPM state. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume. Note that SIZE_IN_GiB is ignored here and that the default size of 4 MiB will always be used instead. The format is also fixed to 'raw'.
  * @param {array} unusedN Reference to unused volumes. This is used internally, and should not be modified manually.
  * @param {array} usbN Configure an USB device (n is 0 to 4).
  * @param {int} vcpus Number of hotplugged vcpus.
  * @param {string} vga Configure the VGA hardware.
  * @param {array} virtioN Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
  * @param {string} vmgenid Set VM Generation ID. Use '1' to autogenerate on create or update, pass '0' to disable explicitly.
  * @param {string} vmstatestorage Default storage for VM state volumes/files.
  * @param {string} watchdog Create a virtual hardware watchdog device.
  * @returns {Result}
  */
  async updateVmAsync(acpi, agent, arch, args, audio0, autostart, background_delay, balloon, bios, boot, bootdisk, cdrom, cicustom, cipassword, citype, ciuser, cores, cpu, cpulimit, cpuunits, delete_, description, digest, efidisk0, force, freeze, hookscript, hostpciN, hotplug, hugepages, ideN, ipconfigN, ivshmem, keephugepages, keyboard, kvm, localtime, lock, machine, memory, migrate_downtime, migrate_speed, name, nameserver, netN, numa, numaN, onboot, ostype, parallelN, protection, reboot, revert, rng0, sataN, scsiN, scsihw, searchdomain, serialN, shares, skiplock, smbios1, smp, sockets, spice_enhancements, sshkeys, startdate, startup, tablet, tags, tdf, template, tpmstate0, unusedN, usbN, vcpus, vga, virtioN, vmgenid, vmstatestorage, watchdog) {
    const parameters = {
      'acpi': acpi,
      'agent': agent,
      'arch': arch,
      'args': args,
      'audio0': audio0,
      'autostart': autostart,
      'background_delay': background_delay,
      'balloon': balloon,
      'bios': bios,
      'boot': boot,
      'bootdisk': bootdisk,
      'cdrom': cdrom,
      'cicustom': cicustom,
      'cipassword': cipassword,
      'citype': citype,
      'ciuser': ciuser,
      'cores': cores,
      'cpu': cpu,
      'cpulimit': cpulimit,
      'cpuunits': cpuunits,
      'delete': delete_,
      'description': description,
      'digest': digest,
      'efidisk0': efidisk0,
      'force': force,
      'freeze': freeze,
      'hookscript': hookscript,
      'hotplug': hotplug,
      'hugepages': hugepages,
      'ivshmem': ivshmem,
      'keephugepages': keephugepages,
      'keyboard': keyboard,
      'kvm': kvm,
      'localtime': localtime,
      'lock': lock,
      'machine': machine,
      'memory': memory,
      'migrate_downtime': migrate_downtime,
      'migrate_speed': migrate_speed,
      'name': name,
      'nameserver': nameserver,
      'numa': numa,
      'onboot': onboot,
      'ostype': ostype,
      'protection': protection,
      'reboot': reboot,
      'revert': revert,
      'rng0': rng0,
      'scsihw': scsihw,
      'searchdomain': searchdomain,
      'shares': shares,
      'skiplock': skiplock,
      'smbios1': smbios1,
      'smp': smp,
      'sockets': sockets,
      'spice_enhancements': spice_enhancements,
      'sshkeys': sshkeys,
      'startdate': startdate,
      'startup': startup,
      'tablet': tablet,
      'tags': tags,
      'tdf': tdf,
      'template': template,
      'tpmstate0': tpmstate0,
      'vcpus': vcpus,
      'vga': vga,
      'vmgenid': vmgenid,
      'vmstatestorage': vmstatestorage,
      'watchdog': watchdog
    };
    this.#client.addIndexedParameter(parameters, 'hostpci', hostpciN);
    this.#client.addIndexedParameter(parameters, 'ide', ideN);
    this.#client.addIndexedParameter(parameters, 'ipconfig', ipconfigN);
    this.#client.addIndexedParameter(parameters, 'net', netN);
    this.#client.addIndexedParameter(parameters, 'numa', numaN);
    this.#client.addIndexedParameter(parameters, 'parallel', parallelN);
    this.#client.addIndexedParameter(parameters, 'sata', sataN);
    this.#client.addIndexedParameter(parameters, 'scsi', scsiN);
    this.#client.addIndexedParameter(parameters, 'serial', serialN);
    this.#client.addIndexedParameter(parameters, 'unused', unusedN);
    this.#client.addIndexedParameter(parameters, 'usb', usbN);
    this.#client.addIndexedParameter(parameters, 'virtio', virtioN);
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/config`, parameters);
  }
  /**
  * Set virtual machine options (synchrounous API) - You should consider using the POST method instead for any actions involving hotplug or storage allocation.
  * @param {bool} acpi Enable/disable ACPI.
  * @param {string} agent Enable/disable communication with the Qemu Guest Agent and its properties.
  * @param {string} arch Virtual processor architecture. Defaults to the host.
  *   Enum: x86_64,aarch64
  * @param {string} args Arbitrary arguments passed to kvm.
  * @param {string} audio0 Configure a audio device, useful in combination with QXL/Spice.
  * @param {bool} autostart Automatic restart after crash (currently ignored).
  * @param {int} balloon Amount of target RAM for the VM in MB. Using zero disables the ballon driver.
  * @param {string} bios Select BIOS implementation.
  *   Enum: seabios,ovmf
  * @param {string} boot Specify guest boot order. Use the 'order=' sub-property as usage with no key or 'legacy=' is deprecated.
  * @param {string} bootdisk Enable booting from specified disk. Deprecated: Use 'boot: order=foo;bar' instead.
  * @param {string} cdrom This is an alias for option -ide2
  * @param {string} cicustom cloud-init: Specify custom files to replace the automatically generated ones at start.
  * @param {string} cipassword cloud-init: Password to assign the user. Using this is generally not recommended. Use ssh keys instead. Also note that older cloud-init versions do not support hashed passwords.
  * @param {string} citype Specifies the cloud-init configuration format. The default depends on the configured operating system type (`ostype`. We use the `nocloud` format for Linux, and `configdrive2` for windows.
  *   Enum: configdrive2,nocloud,opennebula
  * @param {string} ciuser cloud-init: User name to change ssh keys and password for instead of the image's configured default user.
  * @param {int} cores The number of cores per socket.
  * @param {string} cpu Emulated CPU type.
  * @param {float} cpulimit Limit of CPU usage.
  * @param {int} cpuunits CPU weight for a VM, will be clamped to [1, 10000] in cgroup v2.
  * @param {string} delete_ A list of settings you want to delete.
  * @param {string} description Description for the VM. Shown in the web-interface VM's summary. This is saved as comment inside the configuration file.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {string} efidisk0 Configure a Disk for storing EFI vars. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume. Note that SIZE_IN_GiB is ignored here and that the default EFI vars are copied to the volume instead.
  * @param {bool} force Force physical removal. Without this, we simple remove the disk from the config file and create an additional configuration entry called 'unused[n]', which contains the volume ID. Unlink of unused[n] always cause physical removal.
  * @param {bool} freeze Freeze CPU at startup (use 'c' monitor command to start execution).
  * @param {string} hookscript Script that will be executed during various steps in the vms lifetime.
  * @param {array} hostpciN Map host PCI devices into guest.
  * @param {string} hotplug Selectively enable hotplug features. This is a comma separated list of hotplug features: 'network', 'disk', 'cpu', 'memory' and 'usb'. Use '0' to disable hotplug completely. Using '1' as value is an alias for the default `network,disk,usb`.
  * @param {string} hugepages Enable/disable hugepages memory.
  *   Enum: any,2,1024
  * @param {array} ideN Use volume as IDE hard disk or CD-ROM (n is 0 to 3). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
  * @param {array} ipconfigN cloud-init: Specify IP addresses and gateways for the corresponding interface.  IP addresses use CIDR notation, gateways are optional but need an IP of the same type specified.  The special string 'dhcp' can be used for IP addresses to use DHCP, in which case no explicit gateway should be provided. For IPv6 the special string 'auto' can be used to use stateless autoconfiguration. This requires cloud-init 19.4 or newer.  If cloud-init is enabled and neither an IPv4 nor an IPv6 address is specified, it defaults to using dhcp on IPv4.
  * @param {string} ivshmem Inter-VM shared memory. Useful for direct communication between VMs, or to the host.
  * @param {bool} keephugepages Use together with hugepages. If enabled, hugepages will not not be deleted after VM shutdown and can be used for subsequent starts.
  * @param {string} keyboard Keyboard layout for VNC server. The default is read from the'/etc/pve/datacenter.cfg' configuration file. It should not be necessary to set it.
  *   Enum: de,de-ch,da,en-gb,en-us,es,fi,fr,fr-be,fr-ca,fr-ch,hu,is,it,ja,lt,mk,nl,no,pl,pt,pt-br,sv,sl,tr
  * @param {bool} kvm Enable/disable KVM hardware virtualization.
  * @param {bool} localtime Set the real time clock (RTC) to local time. This is enabled by default if the `ostype` indicates a Microsoft Windows OS.
  * @param {string} lock Lock/unlock the VM.
  *   Enum: backup,clone,create,migrate,rollback,snapshot,snapshot-delete,suspending,suspended
  * @param {string} machine Specifies the Qemu machine type.
  * @param {int} memory Amount of RAM for the VM in MB. This is the maximum available memory when you use the balloon device.
  * @param {float} migrate_downtime Set maximum tolerated downtime (in seconds) for migrations.
  * @param {int} migrate_speed Set maximum speed (in MB/s) for migrations. Value 0 is no limit.
  * @param {string} name Set a name for the VM. Only used on the configuration web interface.
  * @param {string} nameserver cloud-init: Sets DNS server IP address for a container. Create will' 	    .' automatically use the setting from the host if neither searchdomain nor nameserver' 	    .' are set.
  * @param {array} netN Specify network devices.
  * @param {bool} numa Enable/disable NUMA.
  * @param {array} numaN NUMA topology.
  * @param {bool} onboot Specifies whether a VM will be started during system bootup.
  * @param {string} ostype Specify guest operating system.
  *   Enum: other,wxp,w2k,w2k3,w2k8,wvista,win7,win8,win10,win11,l24,l26,solaris
  * @param {array} parallelN Map host parallel devices (n is 0 to 2).
  * @param {bool} protection Sets the protection flag of the VM. This will disable the remove VM and remove disk operations.
  * @param {bool} reboot Allow reboot. If set to '0' the VM exit on reboot.
  * @param {string} revert Revert a pending change.
  * @param {string} rng0 Configure a VirtIO-based Random Number Generator.
  * @param {array} sataN Use volume as SATA hard disk or CD-ROM (n is 0 to 5). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
  * @param {array} scsiN Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
  * @param {string} scsihw SCSI controller model
  *   Enum: lsi,lsi53c810,virtio-scsi-pci,virtio-scsi-single,megasas,pvscsi
  * @param {string} searchdomain cloud-init: Sets DNS search domains for a container. Create will' 	    .' automatically use the setting from the host if neither searchdomain nor nameserver' 	    .' are set.
  * @param {array} serialN Create a serial device inside the VM (n is 0 to 3)
  * @param {int} shares Amount of memory shares for auto-ballooning. The larger the number is, the more memory this VM gets. Number is relative to weights of all other running VMs. Using zero disables auto-ballooning. Auto-ballooning is done by pvestatd.
  * @param {bool} skiplock Ignore locks - only root is allowed to use this option.
  * @param {string} smbios1 Specify SMBIOS type 1 fields.
  * @param {int} smp The number of CPUs. Please use option -sockets instead.
  * @param {int} sockets The number of CPU sockets.
  * @param {string} spice_enhancements Configure additional enhancements for SPICE.
  * @param {string} sshkeys cloud-init: Setup public SSH keys (one key per line, OpenSSH format).
  * @param {string} startdate Set the initial date of the real time clock. Valid format for date are:'now' or '2006-06-17T16:01:21' or '2006-06-17'.
  * @param {string} startup Startup and shutdown behavior. Order is a non-negative number defining the general startup order. Shutdown in done with reverse ordering. Additionally you can set the 'up' or 'down' delay in seconds, which specifies a delay to wait before the next VM is started or stopped.
  * @param {bool} tablet Enable/disable the USB tablet device.
  * @param {string} tags Tags of the VM. This is only meta information.
  * @param {bool} tdf Enable/disable time drift fix.
  * @param {bool} template Enable/disable Template.
  * @param {string} tpmstate0 Configure a Disk for storing TPM state. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume. Note that SIZE_IN_GiB is ignored here and that the default size of 4 MiB will always be used instead. The format is also fixed to 'raw'.
  * @param {array} unusedN Reference to unused volumes. This is used internally, and should not be modified manually.
  * @param {array} usbN Configure an USB device (n is 0 to 4).
  * @param {int} vcpus Number of hotplugged vcpus.
  * @param {string} vga Configure the VGA hardware.
  * @param {array} virtioN Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
  * @param {string} vmgenid Set VM Generation ID. Use '1' to autogenerate on create or update, pass '0' to disable explicitly.
  * @param {string} vmstatestorage Default storage for VM state volumes/files.
  * @param {string} watchdog Create a virtual hardware watchdog device.
  * @returns {Result}
  */
  async updateVm(acpi, agent, arch, args, audio0, autostart, balloon, bios, boot, bootdisk, cdrom, cicustom, cipassword, citype, ciuser, cores, cpu, cpulimit, cpuunits, delete_, description, digest, efidisk0, force, freeze, hookscript, hostpciN, hotplug, hugepages, ideN, ipconfigN, ivshmem, keephugepages, keyboard, kvm, localtime, lock, machine, memory, migrate_downtime, migrate_speed, name, nameserver, netN, numa, numaN, onboot, ostype, parallelN, protection, reboot, revert, rng0, sataN, scsiN, scsihw, searchdomain, serialN, shares, skiplock, smbios1, smp, sockets, spice_enhancements, sshkeys, startdate, startup, tablet, tags, tdf, template, tpmstate0, unusedN, usbN, vcpus, vga, virtioN, vmgenid, vmstatestorage, watchdog) {
    const parameters = {
      'acpi': acpi,
      'agent': agent,
      'arch': arch,
      'args': args,
      'audio0': audio0,
      'autostart': autostart,
      'balloon': balloon,
      'bios': bios,
      'boot': boot,
      'bootdisk': bootdisk,
      'cdrom': cdrom,
      'cicustom': cicustom,
      'cipassword': cipassword,
      'citype': citype,
      'ciuser': ciuser,
      'cores': cores,
      'cpu': cpu,
      'cpulimit': cpulimit,
      'cpuunits': cpuunits,
      'delete': delete_,
      'description': description,
      'digest': digest,
      'efidisk0': efidisk0,
      'force': force,
      'freeze': freeze,
      'hookscript': hookscript,
      'hotplug': hotplug,
      'hugepages': hugepages,
      'ivshmem': ivshmem,
      'keephugepages': keephugepages,
      'keyboard': keyboard,
      'kvm': kvm,
      'localtime': localtime,
      'lock': lock,
      'machine': machine,
      'memory': memory,
      'migrate_downtime': migrate_downtime,
      'migrate_speed': migrate_speed,
      'name': name,
      'nameserver': nameserver,
      'numa': numa,
      'onboot': onboot,
      'ostype': ostype,
      'protection': protection,
      'reboot': reboot,
      'revert': revert,
      'rng0': rng0,
      'scsihw': scsihw,
      'searchdomain': searchdomain,
      'shares': shares,
      'skiplock': skiplock,
      'smbios1': smbios1,
      'smp': smp,
      'sockets': sockets,
      'spice_enhancements': spice_enhancements,
      'sshkeys': sshkeys,
      'startdate': startdate,
      'startup': startup,
      'tablet': tablet,
      'tags': tags,
      'tdf': tdf,
      'template': template,
      'tpmstate0': tpmstate0,
      'vcpus': vcpus,
      'vga': vga,
      'vmgenid': vmgenid,
      'vmstatestorage': vmstatestorage,
      'watchdog': watchdog
    };
    this.#client.addIndexedParameter(parameters, 'hostpci', hostpciN);
    this.#client.addIndexedParameter(parameters, 'ide', ideN);
    this.#client.addIndexedParameter(parameters, 'ipconfig', ipconfigN);
    this.#client.addIndexedParameter(parameters, 'net', netN);
    this.#client.addIndexedParameter(parameters, 'numa', numaN);
    this.#client.addIndexedParameter(parameters, 'parallel', parallelN);
    this.#client.addIndexedParameter(parameters, 'sata', sataN);
    this.#client.addIndexedParameter(parameters, 'scsi', scsiN);
    this.#client.addIndexedParameter(parameters, 'serial', serialN);
    this.#client.addIndexedParameter(parameters, 'unused', unusedN);
    this.#client.addIndexedParameter(parameters, 'usb', usbN);
    this.#client.addIndexedParameter(parameters, 'virtio', virtioN);
    return await this.#client.set(`/nodes/${this.#node}/qemu/${this.#vmid}/config`, parameters);
  }

}

/**
 * Class PVEVmidQemuNodeNodesPending
 */
class PVEVmidQemuNodeNodesPending {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Get the virtual machine configuration with both current and pending values.
  * @returns {Result}
  */
  async vmPending() {
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/pending`);
  }

}

/**
 * Class PVEVmidQemuNodeNodesUnlink
 */
class PVEVmidQemuNodeNodesUnlink {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Unlink/delete disk images.
  * @param {string} idlist A list of disk IDs you want to delete.
  * @param {bool} force Force physical removal. Without this, we simple remove the disk from the config file and create an additional configuration entry called 'unused[n]', which contains the volume ID. Unlink of unused[n] always cause physical removal.
  * @returns {Result}
  */
  async unlink(idlist, force) {
    const parameters = {
      'idlist': idlist,
      'force': force
    };
    return await this.#client.set(`/nodes/${this.#node}/qemu/${this.#vmid}/unlink`, parameters);
  }

}

/**
 * Class PVEVmidQemuNodeNodesVncproxy
 */
class PVEVmidQemuNodeNodesVncproxy {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Creates a TCP VNC proxy connections.
  * @param {bool} generate_password Generates a random password to be used as ticket instead of the API ticket.
  * @param {bool} websocket starts websockify instead of vncproxy
  * @returns {Result}
  */
  async vncproxy(generate_password, websocket) {
    const parameters = {
      'generate-password': generate_password,
      'websocket': websocket
    };
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/vncproxy`, parameters);
  }

}

/**
 * Class PVEVmidQemuNodeNodesTermproxy
 */
class PVEVmidQemuNodeNodesTermproxy {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Creates a TCP proxy connections.
  * @param {string} serial opens a serial terminal (defaults to display)
  *   Enum: serial0,serial1,serial2,serial3
  * @returns {Result}
  */
  async termproxy(serial) {
    const parameters = { 'serial': serial };
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/termproxy`, parameters);
  }

}

/**
 * Class PVEVmidQemuNodeNodesVncwebsocket
 */
class PVEVmidQemuNodeNodesVncwebsocket {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Opens a weksocket for VNC traffic.
  * @param {int} port Port number returned by previous vncproxy call.
  * @param {string} vncticket Ticket from previous call to vncproxy.
  * @returns {Result}
  */
  async vncwebsocket(port, vncticket) {
    const parameters = {
      'port': port,
      'vncticket': vncticket
    };
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/vncwebsocket`, parameters);
  }

}

/**
 * Class PVEVmidQemuNodeNodesSpiceproxy
 */
class PVEVmidQemuNodeNodesSpiceproxy {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Returns a SPICE configuration to connect to the VM.
  * @param {string} proxy SPICE proxy server. This can be used by the client to specify the proxy server. All nodes in a cluster runs 'spiceproxy', so it is up to the client to choose one. By default, we return the node where the VM is currently running. As reasonable setting is to use same node you use to connect to the API (This is window.location.hostname for the JS GUI).
  * @returns {Result}
  */
  async spiceproxy(proxy) {
    const parameters = { 'proxy': proxy };
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/spiceproxy`, parameters);
  }

}

/**
 * Class PVEVmidQemuNodeNodesStatus
 */
class PVEVmidQemuNodeNodesStatus {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }

  #current;
  /**
   * Get StatusVmidQemuNodeNodesCurrent
   * @returns {PVEStatusVmidQemuNodeNodesCurrent}
   */
  get current() { return this.#current == null ? (this.#current = new PVEStatusVmidQemuNodeNodesCurrent(this.#client, this.#node, this.#vmid)) : this.#current; }
  #start;
  /**
   * Get StatusVmidQemuNodeNodesStart
   * @returns {PVEStatusVmidQemuNodeNodesStart}
   */
  get start() { return this.#start == null ? (this.#start = new PVEStatusVmidQemuNodeNodesStart(this.#client, this.#node, this.#vmid)) : this.#start; }
  #stop;
  /**
   * Get StatusVmidQemuNodeNodesStop
   * @returns {PVEStatusVmidQemuNodeNodesStop}
   */
  get stop() { return this.#stop == null ? (this.#stop = new PVEStatusVmidQemuNodeNodesStop(this.#client, this.#node, this.#vmid)) : this.#stop; }
  #reset;
  /**
   * Get StatusVmidQemuNodeNodesReset
   * @returns {PVEStatusVmidQemuNodeNodesReset}
   */
  get reset() { return this.#reset == null ? (this.#reset = new PVEStatusVmidQemuNodeNodesReset(this.#client, this.#node, this.#vmid)) : this.#reset; }
  #shutdown;
  /**
   * Get StatusVmidQemuNodeNodesShutdown
   * @returns {PVEStatusVmidQemuNodeNodesShutdown}
   */
  get shutdown() { return this.#shutdown == null ? (this.#shutdown = new PVEStatusVmidQemuNodeNodesShutdown(this.#client, this.#node, this.#vmid)) : this.#shutdown; }
  #reboot;
  /**
   * Get StatusVmidQemuNodeNodesReboot
   * @returns {PVEStatusVmidQemuNodeNodesReboot}
   */
  get reboot() { return this.#reboot == null ? (this.#reboot = new PVEStatusVmidQemuNodeNodesReboot(this.#client, this.#node, this.#vmid)) : this.#reboot; }
  #suspend;
  /**
   * Get StatusVmidQemuNodeNodesSuspend
   * @returns {PVEStatusVmidQemuNodeNodesSuspend}
   */
  get suspend() { return this.#suspend == null ? (this.#suspend = new PVEStatusVmidQemuNodeNodesSuspend(this.#client, this.#node, this.#vmid)) : this.#suspend; }
  #resume;
  /**
   * Get StatusVmidQemuNodeNodesResume
   * @returns {PVEStatusVmidQemuNodeNodesResume}
   */
  get resume() { return this.#resume == null ? (this.#resume = new PVEStatusVmidQemuNodeNodesResume(this.#client, this.#node, this.#vmid)) : this.#resume; }


  /**
  * Directory index
  * @returns {Result}
  */
  async vmcmdidx() {
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/status`);
  }

}
/**
 * Class PVEStatusVmidQemuNodeNodesCurrent
 */
class PVEStatusVmidQemuNodeNodesCurrent {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Get virtual machine status.
  * @returns {Result}
  */
  async vmStatus() {
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/status/current`);
  }

}

/**
 * Class PVEStatusVmidQemuNodeNodesStart
 */
class PVEStatusVmidQemuNodeNodesStart {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Start virtual machine.
  * @param {string} force_cpu Override QEMU's -cpu argument with the given string.
  * @param {string} machine Specifies the Qemu machine type.
  * @param {string} migratedfrom The cluster node name.
  * @param {string} migration_network CIDR of the (sub) network that is used for migration.
  * @param {string} migration_type Migration traffic is encrypted using an SSH tunnel by default. On secure, completely private networks this can be disabled to increase performance.
  *   Enum: secure,insecure
  * @param {bool} skiplock Ignore locks - only root is allowed to use this option.
  * @param {string} stateuri Some command save/restore state from this location.
  * @param {string} targetstorage Mapping from source to target storages. Providing only a single storage ID maps all source storages to that storage. Providing the special value '1' will map each source storage to itself.
  * @param {int} timeout Wait maximal timeout seconds.
  * @returns {Result}
  */
  async vmStart(force_cpu, machine, migratedfrom, migration_network, migration_type, skiplock, stateuri, targetstorage, timeout) {
    const parameters = {
      'force-cpu': force_cpu,
      'machine': machine,
      'migratedfrom': migratedfrom,
      'migration_network': migration_network,
      'migration_type': migration_type,
      'skiplock': skiplock,
      'stateuri': stateuri,
      'targetstorage': targetstorage,
      'timeout': timeout
    };
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/status/start`, parameters);
  }

}

/**
 * Class PVEStatusVmidQemuNodeNodesStop
 */
class PVEStatusVmidQemuNodeNodesStop {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Stop virtual machine. The qemu process will exit immediately. Thisis akin to pulling the power plug of a running computer and may damage the VM data
  * @param {bool} keepActive Do not deactivate storage volumes.
  * @param {string} migratedfrom The cluster node name.
  * @param {bool} skiplock Ignore locks - only root is allowed to use this option.
  * @param {int} timeout Wait maximal timeout seconds.
  * @returns {Result}
  */
  async vmStop(keepActive, migratedfrom, skiplock, timeout) {
    const parameters = {
      'keepActive': keepActive,
      'migratedfrom': migratedfrom,
      'skiplock': skiplock,
      'timeout': timeout
    };
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/status/stop`, parameters);
  }

}

/**
 * Class PVEStatusVmidQemuNodeNodesReset
 */
class PVEStatusVmidQemuNodeNodesReset {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Reset virtual machine.
  * @param {bool} skiplock Ignore locks - only root is allowed to use this option.
  * @returns {Result}
  */
  async vmReset(skiplock) {
    const parameters = { 'skiplock': skiplock };
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/status/reset`, parameters);
  }

}

/**
 * Class PVEStatusVmidQemuNodeNodesShutdown
 */
class PVEStatusVmidQemuNodeNodesShutdown {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Shutdown virtual machine. This is similar to pressing the power button on a physical machine.This will send an ACPI event for the guest OS, which should then proceed to a clean shutdown.
  * @param {bool} forceStop Make sure the VM stops.
  * @param {bool} keepActive Do not deactivate storage volumes.
  * @param {bool} skiplock Ignore locks - only root is allowed to use this option.
  * @param {int} timeout Wait maximal timeout seconds.
  * @returns {Result}
  */
  async vmShutdown(forceStop, keepActive, skiplock, timeout) {
    const parameters = {
      'forceStop': forceStop,
      'keepActive': keepActive,
      'skiplock': skiplock,
      'timeout': timeout
    };
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/status/shutdown`, parameters);
  }

}

/**
 * Class PVEStatusVmidQemuNodeNodesReboot
 */
class PVEStatusVmidQemuNodeNodesReboot {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Reboot the VM by shutting it down, and starting it again. Applies pending changes.
  * @param {int} timeout Wait maximal timeout seconds for the shutdown.
  * @returns {Result}
  */
  async vmReboot(timeout) {
    const parameters = { 'timeout': timeout };
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/status/reboot`, parameters);
  }

}

/**
 * Class PVEStatusVmidQemuNodeNodesSuspend
 */
class PVEStatusVmidQemuNodeNodesSuspend {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Suspend virtual machine.
  * @param {bool} skiplock Ignore locks - only root is allowed to use this option.
  * @param {string} statestorage The storage for the VM state
  * @param {bool} todisk If set, suspends the VM to disk. Will be resumed on next VM start.
  * @returns {Result}
  */
  async vmSuspend(skiplock, statestorage, todisk) {
    const parameters = {
      'skiplock': skiplock,
      'statestorage': statestorage,
      'todisk': todisk
    };
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/status/suspend`, parameters);
  }

}

/**
 * Class PVEStatusVmidQemuNodeNodesResume
 */
class PVEStatusVmidQemuNodeNodesResume {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Resume virtual machine.
  * @param {bool} nocheck
  * @param {bool} skiplock Ignore locks - only root is allowed to use this option.
  * @returns {Result}
  */
  async vmResume(nocheck, skiplock) {
    const parameters = {
      'nocheck': nocheck,
      'skiplock': skiplock
    };
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/status/resume`, parameters);
  }

}

/**
 * Class PVEVmidQemuNodeNodesSendkey
 */
class PVEVmidQemuNodeNodesSendkey {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Send key event to virtual machine.
  * @param {string} key The key (qemu monitor encoding).
  * @param {bool} skiplock Ignore locks - only root is allowed to use this option.
  * @returns {Result}
  */
  async vmSendkey(key, skiplock) {
    const parameters = {
      'key': key,
      'skiplock': skiplock
    };
    return await this.#client.set(`/nodes/${this.#node}/qemu/${this.#vmid}/sendkey`, parameters);
  }

}

/**
 * Class PVEVmidQemuNodeNodesFeature
 */
class PVEVmidQemuNodeNodesFeature {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Check if feature for virtual machine is available.
  * @param {string} feature Feature to check.
  *   Enum: snapshot,clone,copy
  * @param {string} snapname The name of the snapshot.
  * @returns {Result}
  */
  async vmFeature(feature, snapname) {
    const parameters = {
      'feature': feature,
      'snapname': snapname
    };
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/feature`, parameters);
  }

}

/**
 * Class PVEVmidQemuNodeNodesClone
 */
class PVEVmidQemuNodeNodesClone {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Create a copy of virtual machine/template.
  * @param {int} newid VMID for the clone.
  * @param {int} bwlimit Override I/O bandwidth limit (in KiB/s).
  * @param {string} description Description for the new VM.
  * @param {string} format Target format for file storage. Only valid for full clone.
  *   Enum: raw,qcow2,vmdk
  * @param {bool} full Create a full copy of all disks. This is always done when you clone a normal VM. For VM templates, we try to create a linked clone by default.
  * @param {string} name Set a name for the new VM.
  * @param {string} pool Add the new VM to the specified pool.
  * @param {string} snapname The name of the snapshot.
  * @param {string} storage Target storage for full clone.
  * @param {string} target Target node. Only allowed if the original VM is on shared storage.
  * @returns {Result}
  */
  async cloneVm(newid, bwlimit, description, format, full, name, pool, snapname, storage, target) {
    const parameters = {
      'newid': newid,
      'bwlimit': bwlimit,
      'description': description,
      'format': format,
      'full': full,
      'name': name,
      'pool': pool,
      'snapname': snapname,
      'storage': storage,
      'target': target
    };
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/clone`, parameters);
  }

}

/**
 * Class PVEVmidQemuNodeNodesMoveDisk
 */
class PVEVmidQemuNodeNodesMoveDisk {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Move volume to different storage or to a different VM.
  * @param {string} disk The disk you want to move.
  *   Enum: ide0,ide1,ide2,ide3,scsi0,scsi1,scsi2,scsi3,scsi4,scsi5,scsi6,scsi7,scsi8,scsi9,scsi10,scsi11,scsi12,scsi13,scsi14,scsi15,scsi16,scsi17,scsi18,scsi19,scsi20,scsi21,scsi22,scsi23,scsi24,scsi25,scsi26,scsi27,scsi28,scsi29,scsi30,virtio0,virtio1,virtio2,virtio3,virtio4,virtio5,virtio6,virtio7,virtio8,virtio9,virtio10,virtio11,virtio12,virtio13,virtio14,virtio15,sata0,sata1,sata2,sata3,sata4,sata5,efidisk0,tpmstate0,unused0,unused1,unused2,unused3,unused4,unused5,unused6,unused7,unused8,unused9,unused10,unused11,unused12,unused13,unused14,unused15,unused16,unused17,unused18,unused19,unused20,unused21,unused22,unused23,unused24,unused25,unused26,unused27,unused28,unused29,unused30,unused31,unused32,unused33,unused34,unused35,unused36,unused37,unused38,unused39,unused40,unused41,unused42,unused43,unused44,unused45,unused46,unused47,unused48,unused49,unused50,unused51,unused52,unused53,unused54,unused55,unused56,unused57,unused58,unused59,unused60,unused61,unused62,unused63,unused64,unused65,unused66,unused67,unused68,unused69,unused70,unused71,unused72,unused73,unused74,unused75,unused76,unused77,unused78,unused79,unused80,unused81,unused82,unused83,unused84,unused85,unused86,unused87,unused88,unused89,unused90,unused91,unused92,unused93,unused94,unused95,unused96,unused97,unused98,unused99,unused100,unused101,unused102,unused103,unused104,unused105,unused106,unused107,unused108,unused109,unused110,unused111,unused112,unused113,unused114,unused115,unused116,unused117,unused118,unused119,unused120,unused121,unused122,unused123,unused124,unused125,unused126,unused127,unused128,unused129,unused130,unused131,unused132,unused133,unused134,unused135,unused136,unused137,unused138,unused139,unused140,unused141,unused142,unused143,unused144,unused145,unused146,unused147,unused148,unused149,unused150,unused151,unused152,unused153,unused154,unused155,unused156,unused157,unused158,unused159,unused160,unused161,unused162,unused163,unused164,unused165,unused166,unused167,unused168,unused169,unused170,unused171,unused172,unused173,unused174,unused175,unused176,unused177,unused178,unused179,unused180,unused181,unused182,unused183,unused184,unused185,unused186,unused187,unused188,unused189,unused190,unused191,unused192,unused193,unused194,unused195,unused196,unused197,unused198,unused199,unused200,unused201,unused202,unused203,unused204,unused205,unused206,unused207,unused208,unused209,unused210,unused211,unused212,unused213,unused214,unused215,unused216,unused217,unused218,unused219,unused220,unused221,unused222,unused223,unused224,unused225,unused226,unused227,unused228,unused229,unused230,unused231,unused232,unused233,unused234,unused235,unused236,unused237,unused238,unused239,unused240,unused241,unused242,unused243,unused244,unused245,unused246,unused247,unused248,unused249,unused250,unused251,unused252,unused253,unused254,unused255
  * @param {int} bwlimit Override I/O bandwidth limit (in KiB/s).
  * @param {bool} delete_ Delete the original disk after successful copy. By default the original disk is kept as unused disk.
  * @param {string} digest Prevent changes if current configuration file has different SHA1" 		    ." digest. This can be used to prevent concurrent modifications.
  * @param {string} format Target Format.
  *   Enum: raw,qcow2,vmdk
  * @param {string} storage Target storage.
  * @param {string} target_digest Prevent changes if the current config file of the target VM has a" 		    ." different SHA1 digest. This can be used to detect concurrent modifications.
  * @param {string} target_disk The config key the disk will be moved to on the target VM (for example, ide0 or scsi1). Default is the source disk key.
  *   Enum: ide0,ide1,ide2,ide3,scsi0,scsi1,scsi2,scsi3,scsi4,scsi5,scsi6,scsi7,scsi8,scsi9,scsi10,scsi11,scsi12,scsi13,scsi14,scsi15,scsi16,scsi17,scsi18,scsi19,scsi20,scsi21,scsi22,scsi23,scsi24,scsi25,scsi26,scsi27,scsi28,scsi29,scsi30,virtio0,virtio1,virtio2,virtio3,virtio4,virtio5,virtio6,virtio7,virtio8,virtio9,virtio10,virtio11,virtio12,virtio13,virtio14,virtio15,sata0,sata1,sata2,sata3,sata4,sata5,efidisk0,tpmstate0,unused0,unused1,unused2,unused3,unused4,unused5,unused6,unused7,unused8,unused9,unused10,unused11,unused12,unused13,unused14,unused15,unused16,unused17,unused18,unused19,unused20,unused21,unused22,unused23,unused24,unused25,unused26,unused27,unused28,unused29,unused30,unused31,unused32,unused33,unused34,unused35,unused36,unused37,unused38,unused39,unused40,unused41,unused42,unused43,unused44,unused45,unused46,unused47,unused48,unused49,unused50,unused51,unused52,unused53,unused54,unused55,unused56,unused57,unused58,unused59,unused60,unused61,unused62,unused63,unused64,unused65,unused66,unused67,unused68,unused69,unused70,unused71,unused72,unused73,unused74,unused75,unused76,unused77,unused78,unused79,unused80,unused81,unused82,unused83,unused84,unused85,unused86,unused87,unused88,unused89,unused90,unused91,unused92,unused93,unused94,unused95,unused96,unused97,unused98,unused99,unused100,unused101,unused102,unused103,unused104,unused105,unused106,unused107,unused108,unused109,unused110,unused111,unused112,unused113,unused114,unused115,unused116,unused117,unused118,unused119,unused120,unused121,unused122,unused123,unused124,unused125,unused126,unused127,unused128,unused129,unused130,unused131,unused132,unused133,unused134,unused135,unused136,unused137,unused138,unused139,unused140,unused141,unused142,unused143,unused144,unused145,unused146,unused147,unused148,unused149,unused150,unused151,unused152,unused153,unused154,unused155,unused156,unused157,unused158,unused159,unused160,unused161,unused162,unused163,unused164,unused165,unused166,unused167,unused168,unused169,unused170,unused171,unused172,unused173,unused174,unused175,unused176,unused177,unused178,unused179,unused180,unused181,unused182,unused183,unused184,unused185,unused186,unused187,unused188,unused189,unused190,unused191,unused192,unused193,unused194,unused195,unused196,unused197,unused198,unused199,unused200,unused201,unused202,unused203,unused204,unused205,unused206,unused207,unused208,unused209,unused210,unused211,unused212,unused213,unused214,unused215,unused216,unused217,unused218,unused219,unused220,unused221,unused222,unused223,unused224,unused225,unused226,unused227,unused228,unused229,unused230,unused231,unused232,unused233,unused234,unused235,unused236,unused237,unused238,unused239,unused240,unused241,unused242,unused243,unused244,unused245,unused246,unused247,unused248,unused249,unused250,unused251,unused252,unused253,unused254,unused255
  * @param {int} target_vmid The (unique) ID of the VM.
  * @returns {Result}
  */
  async moveVmDisk(disk, bwlimit, delete_, digest, format, storage, target_digest, target_disk, target_vmid) {
    const parameters = {
      'disk': disk,
      'bwlimit': bwlimit,
      'delete': delete_,
      'digest': digest,
      'format': format,
      'storage': storage,
      'target-digest': target_digest,
      'target-disk': target_disk,
      'target-vmid': target_vmid
    };
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/move_disk`, parameters);
  }

}

/**
 * Class PVEVmidQemuNodeNodesMigrate
 */
class PVEVmidQemuNodeNodesMigrate {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Get preconditions for migration.
  * @param {string} target Target node.
  * @returns {Result}
  */
  async migrateVmPrecondition(target) {
    const parameters = { 'target': target };
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/migrate`, parameters);
  }
  /**
  * Migrate virtual machine. Creates a new migration task.
  * @param {string} target Target node.
  * @param {int} bwlimit Override I/O bandwidth limit (in KiB/s).
  * @param {bool} force Allow to migrate VMs which use local devices. Only root may use this option.
  * @param {string} migration_network CIDR of the (sub) network that is used for migration.
  * @param {string} migration_type Migration traffic is encrypted using an SSH tunnel by default. On secure, completely private networks this can be disabled to increase performance.
  *   Enum: secure,insecure
  * @param {bool} online Use online/live migration if VM is running. Ignored if VM is stopped.
  * @param {string} targetstorage Mapping from source to target storages. Providing only a single storage ID maps all source storages to that storage. Providing the special value '1' will map each source storage to itself.
  * @param {bool} with_local_disks Enable live storage migration for local disk
  * @returns {Result}
  */
  async migrateVm(target, bwlimit, force, migration_network, migration_type, online, targetstorage, with_local_disks) {
    const parameters = {
      'target': target,
      'bwlimit': bwlimit,
      'force': force,
      'migration_network': migration_network,
      'migration_type': migration_type,
      'online': online,
      'targetstorage': targetstorage,
      'with-local-disks': with_local_disks
    };
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/migrate`, parameters);
  }

}

/**
 * Class PVEVmidQemuNodeNodesMonitor
 */
class PVEVmidQemuNodeNodesMonitor {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Execute Qemu monitor commands.
  * @param {string} command The monitor command.
  * @returns {Result}
  */
  async monitor(command) {
    const parameters = { 'command': command };
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/monitor`, parameters);
  }

}

/**
 * Class PVEVmidQemuNodeNodesResize
 */
class PVEVmidQemuNodeNodesResize {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Extend volume size.
  * @param {string} disk The disk you want to resize.
  *   Enum: ide0,ide1,ide2,ide3,scsi0,scsi1,scsi2,scsi3,scsi4,scsi5,scsi6,scsi7,scsi8,scsi9,scsi10,scsi11,scsi12,scsi13,scsi14,scsi15,scsi16,scsi17,scsi18,scsi19,scsi20,scsi21,scsi22,scsi23,scsi24,scsi25,scsi26,scsi27,scsi28,scsi29,scsi30,virtio0,virtio1,virtio2,virtio3,virtio4,virtio5,virtio6,virtio7,virtio8,virtio9,virtio10,virtio11,virtio12,virtio13,virtio14,virtio15,sata0,sata1,sata2,sata3,sata4,sata5,efidisk0,tpmstate0
  * @param {string} size The new size. With the `+` sign the value is added to the actual size of the volume and without it, the value is taken as an absolute one. Shrinking disk size is not supported.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {bool} skiplock Ignore locks - only root is allowed to use this option.
  * @returns {Result}
  */
  async resizeVm(disk, size, digest, skiplock) {
    const parameters = {
      'disk': disk,
      'size': size,
      'digest': digest,
      'skiplock': skiplock
    };
    return await this.#client.set(`/nodes/${this.#node}/qemu/${this.#vmid}/resize`, parameters);
  }

}

/**
 * Class PVEVmidQemuNodeNodesSnapshot
 */
class PVEVmidQemuNodeNodesSnapshot {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }


  /**
   * Get ItemSnapshotVmidQemuNodeNodesSnapname
   * @param snapname
   * @returns {PVEItemSnapshotVmidQemuNodeNodesSnapname}
   */
  get(snapname) { return new PVEItemSnapshotVmidQemuNodeNodesSnapname(this.#client, this.#node, this.#vmid, snapname); }

  /**
  * List all snapshots.
  * @returns {Result}
  */
  async snapshotList() {
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/snapshot`);
  }
  /**
  * Snapshot a VM.
  * @param {string} snapname The name of the snapshot.
  * @param {string} description A textual description or comment.
  * @param {bool} vmstate Save the vmstate
  * @returns {Result}
  */
  async snapshot(snapname, description, vmstate) {
    const parameters = {
      'snapname': snapname,
      'description': description,
      'vmstate': vmstate
    };
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/snapshot`, parameters);
  }

}
/**
 * Class PVEItemSnapshotVmidQemuNodeNodesSnapname
 */
class PVEItemSnapshotVmidQemuNodeNodesSnapname {
  #node;
  #vmid;
  #snapname;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid, snapname) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
    this.#snapname = snapname;
  }

  #config;
  /**
   * Get SnapnameSnapshotVmidQemuNodeNodesConfig
   * @returns {PVESnapnameSnapshotVmidQemuNodeNodesConfig}
   */
  get config() { return this.#config == null ? (this.#config = new PVESnapnameSnapshotVmidQemuNodeNodesConfig(this.#client, this.#node, this.#vmid, this.#snapname)) : this.#config; }
  #rollback;
  /**
   * Get SnapnameSnapshotVmidQemuNodeNodesRollback
   * @returns {PVESnapnameSnapshotVmidQemuNodeNodesRollback}
   */
  get rollback() { return this.#rollback == null ? (this.#rollback = new PVESnapnameSnapshotVmidQemuNodeNodesRollback(this.#client, this.#node, this.#vmid, this.#snapname)) : this.#rollback; }


  /**
  * Delete a VM snapshot.
  * @param {bool} force For removal from config file, even if removing disk snapshots fails.
  * @returns {Result}
  */
  async delsnapshot(force) {
    const parameters = { 'force': force };
    return await this.#client.delete(`/nodes/${this.#node}/qemu/${this.#vmid}/snapshot/${this.#snapname}`, parameters);
  }
  /**
  *
  * @returns {Result}
  */
  async snapshotCmdIdx() {
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/snapshot/${this.#snapname}`);
  }

}
/**
 * Class PVESnapnameSnapshotVmidQemuNodeNodesConfig
 */
class PVESnapnameSnapshotVmidQemuNodeNodesConfig {
  #node;
  #vmid;
  #snapname;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid, snapname) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
    this.#snapname = snapname;
  }



  /**
  * Get snapshot configuration
  * @returns {Result}
  */
  async getSnapshotConfig() {
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/snapshot/${this.#snapname}/config`);
  }
  /**
  * Update snapshot metadata.
  * @param {string} description A textual description or comment.
  * @returns {Result}
  */
  async updateSnapshotConfig(description) {
    const parameters = { 'description': description };
    return await this.#client.set(`/nodes/${this.#node}/qemu/${this.#vmid}/snapshot/${this.#snapname}/config`, parameters);
  }

}

/**
 * Class PVESnapnameSnapshotVmidQemuNodeNodesRollback
 */
class PVESnapnameSnapshotVmidQemuNodeNodesRollback {
  #node;
  #vmid;
  #snapname;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid, snapname) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
    this.#snapname = snapname;
  }



  /**
  * Rollback VM state to specified snapshot.
  * @returns {Result}
  */
  async rollback() {
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/snapshot/${this.#snapname}/rollback`);
  }

}

/**
 * Class PVEVmidQemuNodeNodesTemplate
 */
class PVEVmidQemuNodeNodesTemplate {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Create a Template.
  * @param {string} disk If you want to convert only 1 disk to base image.
  *   Enum: ide0,ide1,ide2,ide3,scsi0,scsi1,scsi2,scsi3,scsi4,scsi5,scsi6,scsi7,scsi8,scsi9,scsi10,scsi11,scsi12,scsi13,scsi14,scsi15,scsi16,scsi17,scsi18,scsi19,scsi20,scsi21,scsi22,scsi23,scsi24,scsi25,scsi26,scsi27,scsi28,scsi29,scsi30,virtio0,virtio1,virtio2,virtio3,virtio4,virtio5,virtio6,virtio7,virtio8,virtio9,virtio10,virtio11,virtio12,virtio13,virtio14,virtio15,sata0,sata1,sata2,sata3,sata4,sata5,efidisk0,tpmstate0
  * @returns {Result}
  */
  async template(disk) {
    const parameters = { 'disk': disk };
    return await this.#client.create(`/nodes/${this.#node}/qemu/${this.#vmid}/template`, parameters);
  }

}

/**
 * Class PVEVmidQemuNodeNodesCloudinit
 */
class PVEVmidQemuNodeNodesCloudinit {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }

  #dump;
  /**
   * Get CloudinitVmidQemuNodeNodesDump
   * @returns {PVECloudinitVmidQemuNodeNodesDump}
   */
  get dump() { return this.#dump == null ? (this.#dump = new PVECloudinitVmidQemuNodeNodesDump(this.#client, this.#node, this.#vmid)) : this.#dump; }



}
/**
 * Class PVECloudinitVmidQemuNodeNodesDump
 */
class PVECloudinitVmidQemuNodeNodesDump {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Get automatically generated cloudinit config.
  * @param {string} type Config type.
  *   Enum: user,network,meta
  * @returns {Result}
  */
  async cloudinitGeneratedConfigDump(type) {
    const parameters = { 'type': type };
    return await this.#client.get(`/nodes/${this.#node}/qemu/${this.#vmid}/cloudinit/dump`, parameters);
  }

}

/**
 * Class PVENodeNodesLxc
 */
class PVENodeNodesLxc {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }


  /**
   * Get ItemLxcNodeNodesVmid
   * @param vmid
   * @returns {PVEItemLxcNodeNodesVmid}
   */
  get(vmid) { return new PVEItemLxcNodeNodesVmid(this.#client, this.#node, vmid); }

  /**
  * LXC container index (per node).
  * @returns {Result}
  */
  async vmlist() {
    return await this.#client.get(`/nodes/${this.#node}/lxc`);
  }
  /**
  * Create or restore a container.
  * @param {string} ostemplate The OS template or backup file.
  * @param {int} vmid The (unique) ID of the VM.
  * @param {string} arch OS architecture type.
  *   Enum: amd64,i386,arm64,armhf
  * @param {float} bwlimit Override I/O bandwidth limit (in KiB/s).
  * @param {string} cmode Console mode. By default, the console command tries to open a connection to one of the available tty devices. By setting cmode to 'console' it tries to attach to /dev/console instead. If you set cmode to 'shell', it simply invokes a shell inside the container (no login).
  *   Enum: shell,console,tty
  * @param {bool} console Attach a console device (/dev/console) to the container.
  * @param {int} cores The number of cores assigned to the container. A container can use all available cores by default.
  * @param {float} cpulimit Limit of CPU usage.  NOTE: If the computer has 2 CPUs, it has a total of '2' CPU time. Value '0' indicates no CPU limit.
  * @param {int} cpuunits CPU weight for a VM. Argument is used in the kernel fair scheduler. The larger the number is, the more CPU time this VM gets. Number is relative to the weights of all the other running VMs.  NOTE: You can disable fair-scheduler configuration by setting this to 0.
  * @param {bool} debug Try to be more verbose. For now this only enables debug log-level on start.
  * @param {string} description Description for the Container. Shown in the web-interface CT's summary. This is saved as comment inside the configuration file.
  * @param {string} features Allow containers access to advanced features.
  * @param {bool} force Allow to overwrite existing container.
  * @param {string} hookscript Script that will be exectued during various steps in the containers lifetime.
  * @param {string} hostname Set a host name for the container.
  * @param {bool} ignore_unpack_errors Ignore errors when extracting the template.
  * @param {string} lock Lock/unlock the VM.
  *   Enum: backup,create,destroyed,disk,fstrim,migrate,mounted,rollback,snapshot,snapshot-delete
  * @param {int} memory Amount of RAM for the VM in MB.
  * @param {array} mpN Use volume as container mount point. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
  * @param {string} nameserver Sets DNS server IP address for a container. Create will automatically use the setting from the host if you neither set searchdomain nor nameserver.
  * @param {array} netN Specifies network interfaces for the container.
  * @param {bool} onboot Specifies whether a VM will be started during system bootup.
  * @param {string} ostype OS type. This is used to setup configuration inside the container, and corresponds to lxc setup scripts in /usr/share/lxc/config/&amp;lt;ostype&amp;gt;.common.conf. Value 'unmanaged' can be used to skip and OS specific setup.
  *   Enum: debian,devuan,ubuntu,centos,fedora,opensuse,archlinux,alpine,gentoo,unmanaged
  * @param {string} password Sets root password inside container.
  * @param {string} pool Add the VM to the specified pool.
  * @param {bool} protection Sets the protection flag of the container. This will prevent the CT or CT's disk remove/update operation.
  * @param {bool} restore Mark this as restore task.
  * @param {string} rootfs Use volume as container root.
  * @param {string} searchdomain Sets DNS search domains for a container. Create will automatically use the setting from the host if you neither set searchdomain nor nameserver.
  * @param {string} ssh_public_keys Setup public SSH keys (one key per line, OpenSSH format).
  * @param {bool} start Start the CT after its creation finished successfully.
  * @param {string} startup Startup and shutdown behavior. Order is a non-negative number defining the general startup order. Shutdown in done with reverse ordering. Additionally you can set the 'up' or 'down' delay in seconds, which specifies a delay to wait before the next VM is started or stopped.
  * @param {string} storage Default Storage.
  * @param {int} swap Amount of SWAP for the VM in MB.
  * @param {string} tags Tags of the Container. This is only meta information.
  * @param {bool} template Enable/disable Template.
  * @param {string} timezone Time zone to use in the container. If option isn't set, then nothing will be done. Can be set to 'host' to match the host time zone, or an arbitrary time zone option from /usr/share/zoneinfo/zone.tab
  * @param {int} tty Specify the number of tty available to the container
  * @param {bool} unique Assign a unique random ethernet address.
  * @param {bool} unprivileged Makes the container run as unprivileged user. (Should not be modified manually.)
  * @param {array} unusedN Reference to unused volumes. This is used internally, and should not be modified manually.
  * @returns {Result}
  */
  async createVm(ostemplate, vmid, arch, bwlimit, cmode, console, cores, cpulimit, cpuunits, debug, description, features, force, hookscript, hostname, ignore_unpack_errors, lock, memory, mpN, nameserver, netN, onboot, ostype, password, pool, protection, restore, rootfs, searchdomain, ssh_public_keys, start, startup, storage, swap, tags, template, timezone, tty, unique, unprivileged, unusedN) {
    const parameters = {
      'ostemplate': ostemplate,
      'vmid': vmid,
      'arch': arch,
      'bwlimit': bwlimit,
      'cmode': cmode,
      'console': console,
      'cores': cores,
      'cpulimit': cpulimit,
      'cpuunits': cpuunits,
      'debug': debug,
      'description': description,
      'features': features,
      'force': force,
      'hookscript': hookscript,
      'hostname': hostname,
      'ignore-unpack-errors': ignore_unpack_errors,
      'lock': lock,
      'memory': memory,
      'nameserver': nameserver,
      'onboot': onboot,
      'ostype': ostype,
      'password': password,
      'pool': pool,
      'protection': protection,
      'restore': restore,
      'rootfs': rootfs,
      'searchdomain': searchdomain,
      'ssh-public-keys': ssh_public_keys,
      'start': start,
      'startup': startup,
      'storage': storage,
      'swap': swap,
      'tags': tags,
      'template': template,
      'timezone': timezone,
      'tty': tty,
      'unique': unique,
      'unprivileged': unprivileged
    };
    this.#client.addIndexedParameter(parameters, 'mp', mpN);
    this.#client.addIndexedParameter(parameters, 'net', netN);
    this.#client.addIndexedParameter(parameters, 'unused', unusedN);
    return await this.#client.create(`/nodes/${this.#node}/lxc`, parameters);
  }

}
/**
 * Class PVEItemLxcNodeNodesVmid
 */
class PVEItemLxcNodeNodesVmid {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }

  #config;
  /**
   * Get VmidLxcNodeNodesConfig
   * @returns {PVEVmidLxcNodeNodesConfig}
   */
  get config() { return this.#config == null ? (this.#config = new PVEVmidLxcNodeNodesConfig(this.#client, this.#node, this.#vmid)) : this.#config; }
  #status;
  /**
   * Get VmidLxcNodeNodesStatus
   * @returns {PVEVmidLxcNodeNodesStatus}
   */
  get status() { return this.#status == null ? (this.#status = new PVEVmidLxcNodeNodesStatus(this.#client, this.#node, this.#vmid)) : this.#status; }
  #snapshot;
  /**
   * Get VmidLxcNodeNodesSnapshot
   * @returns {PVEVmidLxcNodeNodesSnapshot}
   */
  get snapshot() { return this.#snapshot == null ? (this.#snapshot = new PVEVmidLxcNodeNodesSnapshot(this.#client, this.#node, this.#vmid)) : this.#snapshot; }
  #firewall;
  /**
   * Get VmidLxcNodeNodesFirewall
   * @returns {PVEVmidLxcNodeNodesFirewall}
   */
  get firewall() { return this.#firewall == null ? (this.#firewall = new PVEVmidLxcNodeNodesFirewall(this.#client, this.#node, this.#vmid)) : this.#firewall; }
  #rrd;
  /**
   * Get VmidLxcNodeNodesRrd
   * @returns {PVEVmidLxcNodeNodesRrd}
   */
  get rrd() { return this.#rrd == null ? (this.#rrd = new PVEVmidLxcNodeNodesRrd(this.#client, this.#node, this.#vmid)) : this.#rrd; }
  #rrddata;
  /**
   * Get VmidLxcNodeNodesRrddata
   * @returns {PVEVmidLxcNodeNodesRrddata}
   */
  get rrddata() { return this.#rrddata == null ? (this.#rrddata = new PVEVmidLxcNodeNodesRrddata(this.#client, this.#node, this.#vmid)) : this.#rrddata; }
  #vncproxy;
  /**
   * Get VmidLxcNodeNodesVncproxy
   * @returns {PVEVmidLxcNodeNodesVncproxy}
   */
  get vncproxy() { return this.#vncproxy == null ? (this.#vncproxy = new PVEVmidLxcNodeNodesVncproxy(this.#client, this.#node, this.#vmid)) : this.#vncproxy; }
  #termproxy;
  /**
   * Get VmidLxcNodeNodesTermproxy
   * @returns {PVEVmidLxcNodeNodesTermproxy}
   */
  get termproxy() { return this.#termproxy == null ? (this.#termproxy = new PVEVmidLxcNodeNodesTermproxy(this.#client, this.#node, this.#vmid)) : this.#termproxy; }
  #vncwebsocket;
  /**
   * Get VmidLxcNodeNodesVncwebsocket
   * @returns {PVEVmidLxcNodeNodesVncwebsocket}
   */
  get vncwebsocket() { return this.#vncwebsocket == null ? (this.#vncwebsocket = new PVEVmidLxcNodeNodesVncwebsocket(this.#client, this.#node, this.#vmid)) : this.#vncwebsocket; }
  #spiceproxy;
  /**
   * Get VmidLxcNodeNodesSpiceproxy
   * @returns {PVEVmidLxcNodeNodesSpiceproxy}
   */
  get spiceproxy() { return this.#spiceproxy == null ? (this.#spiceproxy = new PVEVmidLxcNodeNodesSpiceproxy(this.#client, this.#node, this.#vmid)) : this.#spiceproxy; }
  #migrate;
  /**
   * Get VmidLxcNodeNodesMigrate
   * @returns {PVEVmidLxcNodeNodesMigrate}
   */
  get migrate() { return this.#migrate == null ? (this.#migrate = new PVEVmidLxcNodeNodesMigrate(this.#client, this.#node, this.#vmid)) : this.#migrate; }
  #feature;
  /**
   * Get VmidLxcNodeNodesFeature
   * @returns {PVEVmidLxcNodeNodesFeature}
   */
  get feature() { return this.#feature == null ? (this.#feature = new PVEVmidLxcNodeNodesFeature(this.#client, this.#node, this.#vmid)) : this.#feature; }
  #template;
  /**
   * Get VmidLxcNodeNodesTemplate
   * @returns {PVEVmidLxcNodeNodesTemplate}
   */
  get template() { return this.#template == null ? (this.#template = new PVEVmidLxcNodeNodesTemplate(this.#client, this.#node, this.#vmid)) : this.#template; }
  #clone;
  /**
   * Get VmidLxcNodeNodesClone
   * @returns {PVEVmidLxcNodeNodesClone}
   */
  get clone() { return this.#clone == null ? (this.#clone = new PVEVmidLxcNodeNodesClone(this.#client, this.#node, this.#vmid)) : this.#clone; }
  #resize;
  /**
   * Get VmidLxcNodeNodesResize
   * @returns {PVEVmidLxcNodeNodesResize}
   */
  get resize() { return this.#resize == null ? (this.#resize = new PVEVmidLxcNodeNodesResize(this.#client, this.#node, this.#vmid)) : this.#resize; }
  #moveVolume;
  /**
   * Get VmidLxcNodeNodesMoveVolume
   * @returns {PVEVmidLxcNodeNodesMoveVolume}
   */
  get moveVolume() { return this.#moveVolume == null ? (this.#moveVolume = new PVEVmidLxcNodeNodesMoveVolume(this.#client, this.#node, this.#vmid)) : this.#moveVolume; }
  #pending;
  /**
   * Get VmidLxcNodeNodesPending
   * @returns {PVEVmidLxcNodeNodesPending}
   */
  get pending() { return this.#pending == null ? (this.#pending = new PVEVmidLxcNodeNodesPending(this.#client, this.#node, this.#vmid)) : this.#pending; }


  /**
  * Destroy the container (also delete all uses files).
  * @param {bool} destroy_unreferenced_disks If set, destroy additionally all disks with the VMID from all enabled storages which are not referenced in the config.
  * @param {bool} force Force destroy, even if running.
  * @param {bool} purge Remove container from all related configurations. For example, backup jobs, replication jobs or HA. Related ACLs and Firewall entries will *always* be removed.
  * @returns {Result}
  */
  async destroyVm(destroy_unreferenced_disks, force, purge) {
    const parameters = {
      'destroy-unreferenced-disks': destroy_unreferenced_disks,
      'force': force,
      'purge': purge
    };
    return await this.#client.delete(`/nodes/${this.#node}/lxc/${this.#vmid}`, parameters);
  }
  /**
  * Directory index
  * @returns {Result}
  */
  async vmdiridx() {
    return await this.#client.get(`/nodes/${this.#node}/lxc/${this.#vmid}`);
  }

}
/**
 * Class PVEVmidLxcNodeNodesConfig
 */
class PVEVmidLxcNodeNodesConfig {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Get container configuration.
  * @param {bool} current Get current values (instead of pending values).
  * @param {string} snapshot Fetch config values from given snapshot.
  * @returns {Result}
  */
  async vmConfig(current, snapshot) {
    const parameters = {
      'current': current,
      'snapshot': snapshot
    };
    return await this.#client.get(`/nodes/${this.#node}/lxc/${this.#vmid}/config`, parameters);
  }
  /**
  * Set container options.
  * @param {string} arch OS architecture type.
  *   Enum: amd64,i386,arm64,armhf
  * @param {string} cmode Console mode. By default, the console command tries to open a connection to one of the available tty devices. By setting cmode to 'console' it tries to attach to /dev/console instead. If you set cmode to 'shell', it simply invokes a shell inside the container (no login).
  *   Enum: shell,console,tty
  * @param {bool} console Attach a console device (/dev/console) to the container.
  * @param {int} cores The number of cores assigned to the container. A container can use all available cores by default.
  * @param {float} cpulimit Limit of CPU usage.  NOTE: If the computer has 2 CPUs, it has a total of '2' CPU time. Value '0' indicates no CPU limit.
  * @param {int} cpuunits CPU weight for a VM. Argument is used in the kernel fair scheduler. The larger the number is, the more CPU time this VM gets. Number is relative to the weights of all the other running VMs.  NOTE: You can disable fair-scheduler configuration by setting this to 0.
  * @param {bool} debug Try to be more verbose. For now this only enables debug log-level on start.
  * @param {string} delete_ A list of settings you want to delete.
  * @param {string} description Description for the Container. Shown in the web-interface CT's summary. This is saved as comment inside the configuration file.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {string} features Allow containers access to advanced features.
  * @param {string} hookscript Script that will be exectued during various steps in the containers lifetime.
  * @param {string} hostname Set a host name for the container.
  * @param {string} lock Lock/unlock the VM.
  *   Enum: backup,create,destroyed,disk,fstrim,migrate,mounted,rollback,snapshot,snapshot-delete
  * @param {int} memory Amount of RAM for the VM in MB.
  * @param {array} mpN Use volume as container mount point. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
  * @param {string} nameserver Sets DNS server IP address for a container. Create will automatically use the setting from the host if you neither set searchdomain nor nameserver.
  * @param {array} netN Specifies network interfaces for the container.
  * @param {bool} onboot Specifies whether a VM will be started during system bootup.
  * @param {string} ostype OS type. This is used to setup configuration inside the container, and corresponds to lxc setup scripts in /usr/share/lxc/config/&amp;lt;ostype&amp;gt;.common.conf. Value 'unmanaged' can be used to skip and OS specific setup.
  *   Enum: debian,devuan,ubuntu,centos,fedora,opensuse,archlinux,alpine,gentoo,unmanaged
  * @param {bool} protection Sets the protection flag of the container. This will prevent the CT or CT's disk remove/update operation.
  * @param {string} revert Revert a pending change.
  * @param {string} rootfs Use volume as container root.
  * @param {string} searchdomain Sets DNS search domains for a container. Create will automatically use the setting from the host if you neither set searchdomain nor nameserver.
  * @param {string} startup Startup and shutdown behavior. Order is a non-negative number defining the general startup order. Shutdown in done with reverse ordering. Additionally you can set the 'up' or 'down' delay in seconds, which specifies a delay to wait before the next VM is started or stopped.
  * @param {int} swap Amount of SWAP for the VM in MB.
  * @param {string} tags Tags of the Container. This is only meta information.
  * @param {bool} template Enable/disable Template.
  * @param {string} timezone Time zone to use in the container. If option isn't set, then nothing will be done. Can be set to 'host' to match the host time zone, or an arbitrary time zone option from /usr/share/zoneinfo/zone.tab
  * @param {int} tty Specify the number of tty available to the container
  * @param {bool} unprivileged Makes the container run as unprivileged user. (Should not be modified manually.)
  * @param {array} unusedN Reference to unused volumes. This is used internally, and should not be modified manually.
  * @returns {Result}
  */
  async updateVm(arch, cmode, console, cores, cpulimit, cpuunits, debug, delete_, description, digest, features, hookscript, hostname, lock, memory, mpN, nameserver, netN, onboot, ostype, protection, revert, rootfs, searchdomain, startup, swap, tags, template, timezone, tty, unprivileged, unusedN) {
    const parameters = {
      'arch': arch,
      'cmode': cmode,
      'console': console,
      'cores': cores,
      'cpulimit': cpulimit,
      'cpuunits': cpuunits,
      'debug': debug,
      'delete': delete_,
      'description': description,
      'digest': digest,
      'features': features,
      'hookscript': hookscript,
      'hostname': hostname,
      'lock': lock,
      'memory': memory,
      'nameserver': nameserver,
      'onboot': onboot,
      'ostype': ostype,
      'protection': protection,
      'revert': revert,
      'rootfs': rootfs,
      'searchdomain': searchdomain,
      'startup': startup,
      'swap': swap,
      'tags': tags,
      'template': template,
      'timezone': timezone,
      'tty': tty,
      'unprivileged': unprivileged
    };
    this.#client.addIndexedParameter(parameters, 'mp', mpN);
    this.#client.addIndexedParameter(parameters, 'net', netN);
    this.#client.addIndexedParameter(parameters, 'unused', unusedN);
    return await this.#client.set(`/nodes/${this.#node}/lxc/${this.#vmid}/config`, parameters);
  }

}

/**
 * Class PVEVmidLxcNodeNodesStatus
 */
class PVEVmidLxcNodeNodesStatus {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }

  #current;
  /**
   * Get StatusVmidLxcNodeNodesCurrent
   * @returns {PVEStatusVmidLxcNodeNodesCurrent}
   */
  get current() { return this.#current == null ? (this.#current = new PVEStatusVmidLxcNodeNodesCurrent(this.#client, this.#node, this.#vmid)) : this.#current; }
  #start;
  /**
   * Get StatusVmidLxcNodeNodesStart
   * @returns {PVEStatusVmidLxcNodeNodesStart}
   */
  get start() { return this.#start == null ? (this.#start = new PVEStatusVmidLxcNodeNodesStart(this.#client, this.#node, this.#vmid)) : this.#start; }
  #stop;
  /**
   * Get StatusVmidLxcNodeNodesStop
   * @returns {PVEStatusVmidLxcNodeNodesStop}
   */
  get stop() { return this.#stop == null ? (this.#stop = new PVEStatusVmidLxcNodeNodesStop(this.#client, this.#node, this.#vmid)) : this.#stop; }
  #shutdown;
  /**
   * Get StatusVmidLxcNodeNodesShutdown
   * @returns {PVEStatusVmidLxcNodeNodesShutdown}
   */
  get shutdown() { return this.#shutdown == null ? (this.#shutdown = new PVEStatusVmidLxcNodeNodesShutdown(this.#client, this.#node, this.#vmid)) : this.#shutdown; }
  #suspend;
  /**
   * Get StatusVmidLxcNodeNodesSuspend
   * @returns {PVEStatusVmidLxcNodeNodesSuspend}
   */
  get suspend() { return this.#suspend == null ? (this.#suspend = new PVEStatusVmidLxcNodeNodesSuspend(this.#client, this.#node, this.#vmid)) : this.#suspend; }
  #resume;
  /**
   * Get StatusVmidLxcNodeNodesResume
   * @returns {PVEStatusVmidLxcNodeNodesResume}
   */
  get resume() { return this.#resume == null ? (this.#resume = new PVEStatusVmidLxcNodeNodesResume(this.#client, this.#node, this.#vmid)) : this.#resume; }
  #reboot;
  /**
   * Get StatusVmidLxcNodeNodesReboot
   * @returns {PVEStatusVmidLxcNodeNodesReboot}
   */
  get reboot() { return this.#reboot == null ? (this.#reboot = new PVEStatusVmidLxcNodeNodesReboot(this.#client, this.#node, this.#vmid)) : this.#reboot; }


  /**
  * Directory index
  * @returns {Result}
  */
  async vmcmdidx() {
    return await this.#client.get(`/nodes/${this.#node}/lxc/${this.#vmid}/status`);
  }

}
/**
 * Class PVEStatusVmidLxcNodeNodesCurrent
 */
class PVEStatusVmidLxcNodeNodesCurrent {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Get virtual machine status.
  * @returns {Result}
  */
  async vmStatus() {
    return await this.#client.get(`/nodes/${this.#node}/lxc/${this.#vmid}/status/current`);
  }

}

/**
 * Class PVEStatusVmidLxcNodeNodesStart
 */
class PVEStatusVmidLxcNodeNodesStart {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Start the container.
  * @param {bool} debug If set, enables very verbose debug log-level on start.
  * @param {bool} skiplock Ignore locks - only root is allowed to use this option.
  * @returns {Result}
  */
  async vmStart(debug, skiplock) {
    const parameters = {
      'debug': debug,
      'skiplock': skiplock
    };
    return await this.#client.create(`/nodes/${this.#node}/lxc/${this.#vmid}/status/start`, parameters);
  }

}

/**
 * Class PVEStatusVmidLxcNodeNodesStop
 */
class PVEStatusVmidLxcNodeNodesStop {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Stop the container. This will abruptly stop all processes running in the container.
  * @param {bool} skiplock Ignore locks - only root is allowed to use this option.
  * @returns {Result}
  */
  async vmStop(skiplock) {
    const parameters = { 'skiplock': skiplock };
    return await this.#client.create(`/nodes/${this.#node}/lxc/${this.#vmid}/status/stop`, parameters);
  }

}

/**
 * Class PVEStatusVmidLxcNodeNodesShutdown
 */
class PVEStatusVmidLxcNodeNodesShutdown {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Shutdown the container. This will trigger a clean shutdown of the container, see lxc-stop(1) for details.
  * @param {bool} forceStop Make sure the Container stops.
  * @param {int} timeout Wait maximal timeout seconds.
  * @returns {Result}
  */
  async vmShutdown(forceStop, timeout) {
    const parameters = {
      'forceStop': forceStop,
      'timeout': timeout
    };
    return await this.#client.create(`/nodes/${this.#node}/lxc/${this.#vmid}/status/shutdown`, parameters);
  }

}

/**
 * Class PVEStatusVmidLxcNodeNodesSuspend
 */
class PVEStatusVmidLxcNodeNodesSuspend {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Suspend the container. This is experimental.
  * @returns {Result}
  */
  async vmSuspend() {
    return await this.#client.create(`/nodes/${this.#node}/lxc/${this.#vmid}/status/suspend`);
  }

}

/**
 * Class PVEStatusVmidLxcNodeNodesResume
 */
class PVEStatusVmidLxcNodeNodesResume {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Resume the container.
  * @returns {Result}
  */
  async vmResume() {
    return await this.#client.create(`/nodes/${this.#node}/lxc/${this.#vmid}/status/resume`);
  }

}

/**
 * Class PVEStatusVmidLxcNodeNodesReboot
 */
class PVEStatusVmidLxcNodeNodesReboot {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Reboot the container by shutting it down, and starting it again. Applies pending changes.
  * @param {int} timeout Wait maximal timeout seconds for the shutdown.
  * @returns {Result}
  */
  async vmReboot(timeout) {
    const parameters = { 'timeout': timeout };
    return await this.#client.create(`/nodes/${this.#node}/lxc/${this.#vmid}/status/reboot`, parameters);
  }

}

/**
 * Class PVEVmidLxcNodeNodesSnapshot
 */
class PVEVmidLxcNodeNodesSnapshot {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }


  /**
   * Get ItemSnapshotVmidLxcNodeNodesSnapname
   * @param snapname
   * @returns {PVEItemSnapshotVmidLxcNodeNodesSnapname}
   */
  get(snapname) { return new PVEItemSnapshotVmidLxcNodeNodesSnapname(this.#client, this.#node, this.#vmid, snapname); }

  /**
  * List all snapshots.
  * @returns {Result}
  */
  async list() {
    return await this.#client.get(`/nodes/${this.#node}/lxc/${this.#vmid}/snapshot`);
  }
  /**
  * Snapshot a container.
  * @param {string} snapname The name of the snapshot.
  * @param {string} description A textual description or comment.
  * @returns {Result}
  */
  async snapshot(snapname, description) {
    const parameters = {
      'snapname': snapname,
      'description': description
    };
    return await this.#client.create(`/nodes/${this.#node}/lxc/${this.#vmid}/snapshot`, parameters);
  }

}
/**
 * Class PVEItemSnapshotVmidLxcNodeNodesSnapname
 */
class PVEItemSnapshotVmidLxcNodeNodesSnapname {
  #node;
  #vmid;
  #snapname;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid, snapname) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
    this.#snapname = snapname;
  }

  #rollback;
  /**
   * Get SnapnameSnapshotVmidLxcNodeNodesRollback
   * @returns {PVESnapnameSnapshotVmidLxcNodeNodesRollback}
   */
  get rollback() { return this.#rollback == null ? (this.#rollback = new PVESnapnameSnapshotVmidLxcNodeNodesRollback(this.#client, this.#node, this.#vmid, this.#snapname)) : this.#rollback; }
  #config;
  /**
   * Get SnapnameSnapshotVmidLxcNodeNodesConfig
   * @returns {PVESnapnameSnapshotVmidLxcNodeNodesConfig}
   */
  get config() { return this.#config == null ? (this.#config = new PVESnapnameSnapshotVmidLxcNodeNodesConfig(this.#client, this.#node, this.#vmid, this.#snapname)) : this.#config; }


  /**
  * Delete a LXC snapshot.
  * @param {bool} force For removal from config file, even if removing disk snapshots fails.
  * @returns {Result}
  */
  async delsnapshot(force) {
    const parameters = { 'force': force };
    return await this.#client.delete(`/nodes/${this.#node}/lxc/${this.#vmid}/snapshot/${this.#snapname}`, parameters);
  }
  /**
  *
  * @returns {Result}
  */
  async snapshotCmdIdx() {
    return await this.#client.get(`/nodes/${this.#node}/lxc/${this.#vmid}/snapshot/${this.#snapname}`);
  }

}
/**
 * Class PVESnapnameSnapshotVmidLxcNodeNodesRollback
 */
class PVESnapnameSnapshotVmidLxcNodeNodesRollback {
  #node;
  #vmid;
  #snapname;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid, snapname) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
    this.#snapname = snapname;
  }



  /**
  * Rollback LXC state to specified snapshot.
  * @returns {Result}
  */
  async rollback() {
    return await this.#client.create(`/nodes/${this.#node}/lxc/${this.#vmid}/snapshot/${this.#snapname}/rollback`);
  }

}

/**
 * Class PVESnapnameSnapshotVmidLxcNodeNodesConfig
 */
class PVESnapnameSnapshotVmidLxcNodeNodesConfig {
  #node;
  #vmid;
  #snapname;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid, snapname) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
    this.#snapname = snapname;
  }



  /**
  * Get snapshot configuration
  * @returns {Result}
  */
  async getSnapshotConfig() {
    return await this.#client.get(`/nodes/${this.#node}/lxc/${this.#vmid}/snapshot/${this.#snapname}/config`);
  }
  /**
  * Update snapshot metadata.
  * @param {string} description A textual description or comment.
  * @returns {Result}
  */
  async updateSnapshotConfig(description) {
    const parameters = { 'description': description };
    return await this.#client.set(`/nodes/${this.#node}/lxc/${this.#vmid}/snapshot/${this.#snapname}/config`, parameters);
  }

}

/**
 * Class PVEVmidLxcNodeNodesFirewall
 */
class PVEVmidLxcNodeNodesFirewall {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }

  #rules;
  /**
   * Get FirewallVmidLxcNodeNodesRules
   * @returns {PVEFirewallVmidLxcNodeNodesRules}
   */
  get rules() { return this.#rules == null ? (this.#rules = new PVEFirewallVmidLxcNodeNodesRules(this.#client, this.#node, this.#vmid)) : this.#rules; }
  #aliases;
  /**
   * Get FirewallVmidLxcNodeNodesAliases
   * @returns {PVEFirewallVmidLxcNodeNodesAliases}
   */
  get aliases() { return this.#aliases == null ? (this.#aliases = new PVEFirewallVmidLxcNodeNodesAliases(this.#client, this.#node, this.#vmid)) : this.#aliases; }
  #ipset;
  /**
   * Get FirewallVmidLxcNodeNodesIpset
   * @returns {PVEFirewallVmidLxcNodeNodesIpset}
   */
  get ipset() { return this.#ipset == null ? (this.#ipset = new PVEFirewallVmidLxcNodeNodesIpset(this.#client, this.#node, this.#vmid)) : this.#ipset; }
  #options;
  /**
   * Get FirewallVmidLxcNodeNodesOptions
   * @returns {PVEFirewallVmidLxcNodeNodesOptions}
   */
  get options() { return this.#options == null ? (this.#options = new PVEFirewallVmidLxcNodeNodesOptions(this.#client, this.#node, this.#vmid)) : this.#options; }
  #log;
  /**
   * Get FirewallVmidLxcNodeNodesLog
   * @returns {PVEFirewallVmidLxcNodeNodesLog}
   */
  get log() { return this.#log == null ? (this.#log = new PVEFirewallVmidLxcNodeNodesLog(this.#client, this.#node, this.#vmid)) : this.#log; }
  #refs;
  /**
   * Get FirewallVmidLxcNodeNodesRefs
   * @returns {PVEFirewallVmidLxcNodeNodesRefs}
   */
  get refs() { return this.#refs == null ? (this.#refs = new PVEFirewallVmidLxcNodeNodesRefs(this.#client, this.#node, this.#vmid)) : this.#refs; }


  /**
  * Directory index.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/nodes/${this.#node}/lxc/${this.#vmid}/firewall`);
  }

}
/**
 * Class PVEFirewallVmidLxcNodeNodesRules
 */
class PVEFirewallVmidLxcNodeNodesRules {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }


  /**
   * Get ItemRulesFirewallVmidLxcNodeNodesPos
   * @param pos
   * @returns {PVEItemRulesFirewallVmidLxcNodeNodesPos}
   */
  get(pos) { return new PVEItemRulesFirewallVmidLxcNodeNodesPos(this.#client, this.#node, this.#vmid, pos); }

  /**
  * List rules.
  * @returns {Result}
  */
  async getRules() {
    return await this.#client.get(`/nodes/${this.#node}/lxc/${this.#vmid}/firewall/rules`);
  }
  /**
  * Create new rule.
  * @param {string} action Rule action ('ACCEPT', 'DROP', 'REJECT') or security group name.
  * @param {string} type Rule type.
  *   Enum: in,out,group
  * @param {string} comment Descriptive comment.
  * @param {string} dest Restrict packet destination address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {string} dport Restrict TCP/UDP destination port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
  * @param {int} enable Flag to enable/disable a rule.
  * @param {string} icmp_type Specify icmp-type. Only valid if proto equals 'icmp'.
  * @param {string} iface Network interface name. You have to use network configuration key names for VMs and containers ('net\d+'). Host related rules can use arbitrary strings.
  * @param {string} log Log level for firewall rule.
  *   Enum: emerg,alert,crit,err,warning,notice,info,debug,nolog
  * @param {string} macro Use predefined standard macro.
  * @param {int} pos Update rule at position &amp;lt;pos&amp;gt;.
  * @param {string} proto IP protocol. You can use protocol names ('tcp'/'udp') or simple numbers, as defined in '/etc/protocols'.
  * @param {string} source Restrict packet source address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
  * @param {string} sport Restrict TCP/UDP source port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
  * @returns {Result}
  */
  async createRule(action, type, comment, dest, digest, dport, enable, icmp_type, iface, log, macro, pos, proto, source, sport) {
    const parameters = {
      'action': action,
      'type': type,
      'comment': comment,
      'dest': dest,
      'digest': digest,
      'dport': dport,
      'enable': enable,
      'icmp-type': icmp_type,
      'iface': iface,
      'log': log,
      'macro': macro,
      'pos': pos,
      'proto': proto,
      'source': source,
      'sport': sport
    };
    return await this.#client.create(`/nodes/${this.#node}/lxc/${this.#vmid}/firewall/rules`, parameters);
  }

}
/**
 * Class PVEItemRulesFirewallVmidLxcNodeNodesPos
 */
class PVEItemRulesFirewallVmidLxcNodeNodesPos {
  #node;
  #vmid;
  #pos;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid, pos) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
    this.#pos = pos;
  }



  /**
  * Delete rule.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @returns {Result}
  */
  async deleteRule(digest) {
    const parameters = { 'digest': digest };
    return await this.#client.delete(`/nodes/${this.#node}/lxc/${this.#vmid}/firewall/rules/${this.#pos}`, parameters);
  }
  /**
  * Get single rule data.
  * @returns {Result}
  */
  async getRule() {
    return await this.#client.get(`/nodes/${this.#node}/lxc/${this.#vmid}/firewall/rules/${this.#pos}`);
  }
  /**
  * Modify rule data.
  * @param {string} action Rule action ('ACCEPT', 'DROP', 'REJECT') or security group name.
  * @param {string} comment Descriptive comment.
  * @param {string} delete_ A list of settings you want to delete.
  * @param {string} dest Restrict packet destination address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {string} dport Restrict TCP/UDP destination port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
  * @param {int} enable Flag to enable/disable a rule.
  * @param {string} icmp_type Specify icmp-type. Only valid if proto equals 'icmp'.
  * @param {string} iface Network interface name. You have to use network configuration key names for VMs and containers ('net\d+'). Host related rules can use arbitrary strings.
  * @param {string} log Log level for firewall rule.
  *   Enum: emerg,alert,crit,err,warning,notice,info,debug,nolog
  * @param {string} macro Use predefined standard macro.
  * @param {int} moveto Move rule to new position &amp;lt;moveto&amp;gt;. Other arguments are ignored.
  * @param {string} proto IP protocol. You can use protocol names ('tcp'/'udp') or simple numbers, as defined in '/etc/protocols'.
  * @param {string} source Restrict packet source address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
  * @param {string} sport Restrict TCP/UDP source port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
  * @param {string} type Rule type.
  *   Enum: in,out,group
  * @returns {Result}
  */
  async updateRule(action, comment, delete_, dest, digest, dport, enable, icmp_type, iface, log, macro, moveto, proto, source, sport, type) {
    const parameters = {
      'action': action,
      'comment': comment,
      'delete': delete_,
      'dest': dest,
      'digest': digest,
      'dport': dport,
      'enable': enable,
      'icmp-type': icmp_type,
      'iface': iface,
      'log': log,
      'macro': macro,
      'moveto': moveto,
      'proto': proto,
      'source': source,
      'sport': sport,
      'type': type
    };
    return await this.#client.set(`/nodes/${this.#node}/lxc/${this.#vmid}/firewall/rules/${this.#pos}`, parameters);
  }

}

/**
 * Class PVEFirewallVmidLxcNodeNodesAliases
 */
class PVEFirewallVmidLxcNodeNodesAliases {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }


  /**
   * Get ItemAliasesFirewallVmidLxcNodeNodesName
   * @param name
   * @returns {PVEItemAliasesFirewallVmidLxcNodeNodesName}
   */
  get(name) { return new PVEItemAliasesFirewallVmidLxcNodeNodesName(this.#client, this.#node, this.#vmid, name); }

  /**
  * List aliases
  * @returns {Result}
  */
  async getAliases() {
    return await this.#client.get(`/nodes/${this.#node}/lxc/${this.#vmid}/firewall/aliases`);
  }
  /**
  * Create IP or Network Alias.
  * @param {string} cidr Network/IP specification in CIDR format.
  * @param {string} name Alias name.
  * @param {string} comment
  * @returns {Result}
  */
  async createAlias(cidr, name, comment) {
    const parameters = {
      'cidr': cidr,
      'name': name,
      'comment': comment
    };
    return await this.#client.create(`/nodes/${this.#node}/lxc/${this.#vmid}/firewall/aliases`, parameters);
  }

}
/**
 * Class PVEItemAliasesFirewallVmidLxcNodeNodesName
 */
class PVEItemAliasesFirewallVmidLxcNodeNodesName {
  #node;
  #vmid;
  #name;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid, name) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
    this.#name = name;
  }



  /**
  * Remove IP or Network alias.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @returns {Result}
  */
  async removeAlias(digest) {
    const parameters = { 'digest': digest };
    return await this.#client.delete(`/nodes/${this.#node}/lxc/${this.#vmid}/firewall/aliases/${this.#name}`, parameters);
  }
  /**
  * Read alias.
  * @returns {Result}
  */
  async readAlias() {
    return await this.#client.get(`/nodes/${this.#node}/lxc/${this.#vmid}/firewall/aliases/${this.#name}`);
  }
  /**
  * Update IP or Network alias.
  * @param {string} cidr Network/IP specification in CIDR format.
  * @param {string} comment
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {string} rename Rename an existing alias.
  * @returns {Result}
  */
  async updateAlias(cidr, comment, digest, rename) {
    const parameters = {
      'cidr': cidr,
      'comment': comment,
      'digest': digest,
      'rename': rename
    };
    return await this.#client.set(`/nodes/${this.#node}/lxc/${this.#vmid}/firewall/aliases/${this.#name}`, parameters);
  }

}

/**
 * Class PVEFirewallVmidLxcNodeNodesIpset
 */
class PVEFirewallVmidLxcNodeNodesIpset {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }


  /**
   * Get ItemIpsetFirewallVmidLxcNodeNodesName
   * @param name
   * @returns {PVEItemIpsetFirewallVmidLxcNodeNodesName}
   */
  get(name) { return new PVEItemIpsetFirewallVmidLxcNodeNodesName(this.#client, this.#node, this.#vmid, name); }

  /**
  * List IPSets
  * @returns {Result}
  */
  async ipsetIndex() {
    return await this.#client.get(`/nodes/${this.#node}/lxc/${this.#vmid}/firewall/ipset`);
  }
  /**
  * Create new IPSet
  * @param {string} name IP set name.
  * @param {string} comment
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {string} rename Rename an existing IPSet. You can set 'rename' to the same value as 'name' to update the 'comment' of an existing IPSet.
  * @returns {Result}
  */
  async createIpset(name, comment, digest, rename) {
    const parameters = {
      'name': name,
      'comment': comment,
      'digest': digest,
      'rename': rename
    };
    return await this.#client.create(`/nodes/${this.#node}/lxc/${this.#vmid}/firewall/ipset`, parameters);
  }

}
/**
 * Class PVEItemIpsetFirewallVmidLxcNodeNodesName
 */
class PVEItemIpsetFirewallVmidLxcNodeNodesName {
  #node;
  #vmid;
  #name;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid, name) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
    this.#name = name;
  }


  /**
   * Get ItemNameIpsetFirewallVmidLxcNodeNodesCidr
   * @param cidr
   * @returns {PVEItemNameIpsetFirewallVmidLxcNodeNodesCidr}
   */
  get(cidr) { return new PVEItemNameIpsetFirewallVmidLxcNodeNodesCidr(this.#client, this.#node, this.#vmid, this.#name, cidr); }

  /**
  * Delete IPSet
  * @returns {Result}
  */
  async deleteIpset() {
    return await this.#client.delete(`/nodes/${this.#node}/lxc/${this.#vmid}/firewall/ipset/${this.#name}`);
  }
  /**
  * List IPSet content
  * @returns {Result}
  */
  async getIpset() {
    return await this.#client.get(`/nodes/${this.#node}/lxc/${this.#vmid}/firewall/ipset/${this.#name}`);
  }
  /**
  * Add IP or Network to IPSet.
  * @param {string} cidr Network/IP specification in CIDR format.
  * @param {string} comment
  * @param {bool} nomatch
  * @returns {Result}
  */
  async createIp(cidr, comment, nomatch) {
    const parameters = {
      'cidr': cidr,
      'comment': comment,
      'nomatch': nomatch
    };
    return await this.#client.create(`/nodes/${this.#node}/lxc/${this.#vmid}/firewall/ipset/${this.#name}`, parameters);
  }

}
/**
 * Class PVEItemNameIpsetFirewallVmidLxcNodeNodesCidr
 */
class PVEItemNameIpsetFirewallVmidLxcNodeNodesCidr {
  #node;
  #vmid;
  #name;
  #cidr;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid, name, cidr) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
    this.#name = name;
    this.#cidr = cidr;
  }



  /**
  * Remove IP or Network from IPSet.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @returns {Result}
  */
  async removeIp(digest) {
    const parameters = { 'digest': digest };
    return await this.#client.delete(`/nodes/${this.#node}/lxc/${this.#vmid}/firewall/ipset/${this.#name}/${this.#cidr}`, parameters);
  }
  /**
  * Read IP or Network settings from IPSet.
  * @returns {Result}
  */
  async readIp() {
    return await this.#client.get(`/nodes/${this.#node}/lxc/${this.#vmid}/firewall/ipset/${this.#name}/${this.#cidr}`);
  }
  /**
  * Update IP or Network settings
  * @param {string} comment
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {bool} nomatch
  * @returns {Result}
  */
  async updateIp(comment, digest, nomatch) {
    const parameters = {
      'comment': comment,
      'digest': digest,
      'nomatch': nomatch
    };
    return await this.#client.set(`/nodes/${this.#node}/lxc/${this.#vmid}/firewall/ipset/${this.#name}/${this.#cidr}`, parameters);
  }

}

/**
 * Class PVEFirewallVmidLxcNodeNodesOptions
 */
class PVEFirewallVmidLxcNodeNodesOptions {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Get VM firewall options.
  * @returns {Result}
  */
  async getOptions() {
    return await this.#client.get(`/nodes/${this.#node}/lxc/${this.#vmid}/firewall/options`);
  }
  /**
  * Set Firewall options.
  * @param {string} delete_ A list of settings you want to delete.
  * @param {bool} dhcp Enable DHCP.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {bool} enable Enable/disable firewall rules.
  * @param {bool} ipfilter Enable default IP filters. This is equivalent to adding an empty ipfilter-net&amp;lt;id&amp;gt; ipset for every interface. Such ipsets implicitly contain sane default restrictions such as restricting IPv6 link local addresses to the one derived from the interface's MAC address. For containers the configured IP addresses will be implicitly added.
  * @param {string} log_level_in Log level for incoming traffic.
  *   Enum: emerg,alert,crit,err,warning,notice,info,debug,nolog
  * @param {string} log_level_out Log level for outgoing traffic.
  *   Enum: emerg,alert,crit,err,warning,notice,info,debug,nolog
  * @param {bool} macfilter Enable/disable MAC address filter.
  * @param {bool} ndp Enable NDP (Neighbor Discovery Protocol).
  * @param {string} policy_in Input policy.
  *   Enum: ACCEPT,REJECT,DROP
  * @param {string} policy_out Output policy.
  *   Enum: ACCEPT,REJECT,DROP
  * @param {bool} radv Allow sending Router Advertisement.
  * @returns {Result}
  */
  async setOptions(delete_, dhcp, digest, enable, ipfilter, log_level_in, log_level_out, macfilter, ndp, policy_in, policy_out, radv) {
    const parameters = {
      'delete': delete_,
      'dhcp': dhcp,
      'digest': digest,
      'enable': enable,
      'ipfilter': ipfilter,
      'log_level_in': log_level_in,
      'log_level_out': log_level_out,
      'macfilter': macfilter,
      'ndp': ndp,
      'policy_in': policy_in,
      'policy_out': policy_out,
      'radv': radv
    };
    return await this.#client.set(`/nodes/${this.#node}/lxc/${this.#vmid}/firewall/options`, parameters);
  }

}

/**
 * Class PVEFirewallVmidLxcNodeNodesLog
 */
class PVEFirewallVmidLxcNodeNodesLog {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Read firewall log
  * @param {int} limit
  * @param {int} start
  * @returns {Result}
  */
  async log(limit, start) {
    const parameters = {
      'limit': limit,
      'start': start
    };
    return await this.#client.get(`/nodes/${this.#node}/lxc/${this.#vmid}/firewall/log`, parameters);
  }

}

/**
 * Class PVEFirewallVmidLxcNodeNodesRefs
 */
class PVEFirewallVmidLxcNodeNodesRefs {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Lists possible IPSet/Alias reference which are allowed in source/dest properties.
  * @param {string} type Only list references of specified type.
  *   Enum: alias,ipset
  * @returns {Result}
  */
  async refs(type) {
    const parameters = { 'type': type };
    return await this.#client.get(`/nodes/${this.#node}/lxc/${this.#vmid}/firewall/refs`, parameters);
  }

}

/**
 * Class PVEVmidLxcNodeNodesRrd
 */
class PVEVmidLxcNodeNodesRrd {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Read VM RRD statistics (returns PNG)
  * @param {string} ds The list of datasources you want to display.
  * @param {string} timeframe Specify the time frame you are interested in.
  *   Enum: hour,day,week,month,year
  * @param {string} cf The RRD consolidation function
  *   Enum: AVERAGE,MAX
  * @returns {Result}
  */
  async rrd(ds, timeframe, cf) {
    const parameters = {
      'ds': ds,
      'timeframe': timeframe,
      'cf': cf
    };
    return await this.#client.get(`/nodes/${this.#node}/lxc/${this.#vmid}/rrd`, parameters);
  }

}

/**
 * Class PVEVmidLxcNodeNodesRrddata
 */
class PVEVmidLxcNodeNodesRrddata {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Read VM RRD statistics
  * @param {string} timeframe Specify the time frame you are interested in.
  *   Enum: hour,day,week,month,year
  * @param {string} cf The RRD consolidation function
  *   Enum: AVERAGE,MAX
  * @returns {Result}
  */
  async rrddata(timeframe, cf) {
    const parameters = {
      'timeframe': timeframe,
      'cf': cf
    };
    return await this.#client.get(`/nodes/${this.#node}/lxc/${this.#vmid}/rrddata`, parameters);
  }

}

/**
 * Class PVEVmidLxcNodeNodesVncproxy
 */
class PVEVmidLxcNodeNodesVncproxy {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Creates a TCP VNC proxy connections.
  * @param {int} height sets the height of the console in pixels.
  * @param {bool} websocket use websocket instead of standard VNC.
  * @param {int} width sets the width of the console in pixels.
  * @returns {Result}
  */
  async vncproxy(height, websocket, width) {
    const parameters = {
      'height': height,
      'websocket': websocket,
      'width': width
    };
    return await this.#client.create(`/nodes/${this.#node}/lxc/${this.#vmid}/vncproxy`, parameters);
  }

}

/**
 * Class PVEVmidLxcNodeNodesTermproxy
 */
class PVEVmidLxcNodeNodesTermproxy {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Creates a TCP proxy connection.
  * @returns {Result}
  */
  async termproxy() {
    return await this.#client.create(`/nodes/${this.#node}/lxc/${this.#vmid}/termproxy`);
  }

}

/**
 * Class PVEVmidLxcNodeNodesVncwebsocket
 */
class PVEVmidLxcNodeNodesVncwebsocket {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Opens a weksocket for VNC traffic.
  * @param {int} port Port number returned by previous vncproxy call.
  * @param {string} vncticket Ticket from previous call to vncproxy.
  * @returns {Result}
  */
  async vncwebsocket(port, vncticket) {
    const parameters = {
      'port': port,
      'vncticket': vncticket
    };
    return await this.#client.get(`/nodes/${this.#node}/lxc/${this.#vmid}/vncwebsocket`, parameters);
  }

}

/**
 * Class PVEVmidLxcNodeNodesSpiceproxy
 */
class PVEVmidLxcNodeNodesSpiceproxy {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Returns a SPICE configuration to connect to the CT.
  * @param {string} proxy SPICE proxy server. This can be used by the client to specify the proxy server. All nodes in a cluster runs 'spiceproxy', so it is up to the client to choose one. By default, we return the node where the VM is currently running. As reasonable setting is to use same node you use to connect to the API (This is window.location.hostname for the JS GUI).
  * @returns {Result}
  */
  async spiceproxy(proxy) {
    const parameters = { 'proxy': proxy };
    return await this.#client.create(`/nodes/${this.#node}/lxc/${this.#vmid}/spiceproxy`, parameters);
  }

}

/**
 * Class PVEVmidLxcNodeNodesMigrate
 */
class PVEVmidLxcNodeNodesMigrate {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Migrate the container to another node. Creates a new migration task.
  * @param {string} target Target node.
  * @param {float} bwlimit Override I/O bandwidth limit (in KiB/s).
  * @param {bool} online Use online/live migration.
  * @param {bool} restart Use restart migration
  * @param {int} timeout Timeout in seconds for shutdown for restart migration
  * @returns {Result}
  */
  async migrateVm(target, bwlimit, online, restart, timeout) {
    const parameters = {
      'target': target,
      'bwlimit': bwlimit,
      'online': online,
      'restart': restart,
      'timeout': timeout
    };
    return await this.#client.create(`/nodes/${this.#node}/lxc/${this.#vmid}/migrate`, parameters);
  }

}

/**
 * Class PVEVmidLxcNodeNodesFeature
 */
class PVEVmidLxcNodeNodesFeature {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Check if feature for virtual machine is available.
  * @param {string} feature Feature to check.
  *   Enum: snapshot,clone,copy
  * @param {string} snapname The name of the snapshot.
  * @returns {Result}
  */
  async vmFeature(feature, snapname) {
    const parameters = {
      'feature': feature,
      'snapname': snapname
    };
    return await this.#client.get(`/nodes/${this.#node}/lxc/${this.#vmid}/feature`, parameters);
  }

}

/**
 * Class PVEVmidLxcNodeNodesTemplate
 */
class PVEVmidLxcNodeNodesTemplate {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Create a Template.
  * @returns {Result}
  */
  async template() {
    return await this.#client.create(`/nodes/${this.#node}/lxc/${this.#vmid}/template`);
  }

}

/**
 * Class PVEVmidLxcNodeNodesClone
 */
class PVEVmidLxcNodeNodesClone {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Create a container clone/copy
  * @param {int} newid VMID for the clone.
  * @param {float} bwlimit Override I/O bandwidth limit (in KiB/s).
  * @param {string} description Description for the new CT.
  * @param {bool} full Create a full copy of all disks. This is always done when you clone a normal CT. For CT templates, we try to create a linked clone by default.
  * @param {string} hostname Set a hostname for the new CT.
  * @param {string} pool Add the new CT to the specified pool.
  * @param {string} snapname The name of the snapshot.
  * @param {string} storage Target storage for full clone.
  * @param {string} target Target node. Only allowed if the original VM is on shared storage.
  * @returns {Result}
  */
  async cloneVm(newid, bwlimit, description, full, hostname, pool, snapname, storage, target) {
    const parameters = {
      'newid': newid,
      'bwlimit': bwlimit,
      'description': description,
      'full': full,
      'hostname': hostname,
      'pool': pool,
      'snapname': snapname,
      'storage': storage,
      'target': target
    };
    return await this.#client.create(`/nodes/${this.#node}/lxc/${this.#vmid}/clone`, parameters);
  }

}

/**
 * Class PVEVmidLxcNodeNodesResize
 */
class PVEVmidLxcNodeNodesResize {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Resize a container mount point.
  * @param {string} disk The disk you want to resize.
  *   Enum: rootfs,mp0,mp1,mp2,mp3,mp4,mp5,mp6,mp7,mp8,mp9,mp10,mp11,mp12,mp13,mp14,mp15,mp16,mp17,mp18,mp19,mp20,mp21,mp22,mp23,mp24,mp25,mp26,mp27,mp28,mp29,mp30,mp31,mp32,mp33,mp34,mp35,mp36,mp37,mp38,mp39,mp40,mp41,mp42,mp43,mp44,mp45,mp46,mp47,mp48,mp49,mp50,mp51,mp52,mp53,mp54,mp55,mp56,mp57,mp58,mp59,mp60,mp61,mp62,mp63,mp64,mp65,mp66,mp67,mp68,mp69,mp70,mp71,mp72,mp73,mp74,mp75,mp76,mp77,mp78,mp79,mp80,mp81,mp82,mp83,mp84,mp85,mp86,mp87,mp88,mp89,mp90,mp91,mp92,mp93,mp94,mp95,mp96,mp97,mp98,mp99,mp100,mp101,mp102,mp103,mp104,mp105,mp106,mp107,mp108,mp109,mp110,mp111,mp112,mp113,mp114,mp115,mp116,mp117,mp118,mp119,mp120,mp121,mp122,mp123,mp124,mp125,mp126,mp127,mp128,mp129,mp130,mp131,mp132,mp133,mp134,mp135,mp136,mp137,mp138,mp139,mp140,mp141,mp142,mp143,mp144,mp145,mp146,mp147,mp148,mp149,mp150,mp151,mp152,mp153,mp154,mp155,mp156,mp157,mp158,mp159,mp160,mp161,mp162,mp163,mp164,mp165,mp166,mp167,mp168,mp169,mp170,mp171,mp172,mp173,mp174,mp175,mp176,mp177,mp178,mp179,mp180,mp181,mp182,mp183,mp184,mp185,mp186,mp187,mp188,mp189,mp190,mp191,mp192,mp193,mp194,mp195,mp196,mp197,mp198,mp199,mp200,mp201,mp202,mp203,mp204,mp205,mp206,mp207,mp208,mp209,mp210,mp211,mp212,mp213,mp214,mp215,mp216,mp217,mp218,mp219,mp220,mp221,mp222,mp223,mp224,mp225,mp226,mp227,mp228,mp229,mp230,mp231,mp232,mp233,mp234,mp235,mp236,mp237,mp238,mp239,mp240,mp241,mp242,mp243,mp244,mp245,mp246,mp247,mp248,mp249,mp250,mp251,mp252,mp253,mp254,mp255
  * @param {string} size The new size. With the '+' sign the value is added to the actual size of the volume and without it, the value is taken as an absolute one. Shrinking disk size is not supported.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @returns {Result}
  */
  async resizeVm(disk, size, digest) {
    const parameters = {
      'disk': disk,
      'size': size,
      'digest': digest
    };
    return await this.#client.set(`/nodes/${this.#node}/lxc/${this.#vmid}/resize`, parameters);
  }

}

/**
 * Class PVEVmidLxcNodeNodesMoveVolume
 */
class PVEVmidLxcNodeNodesMoveVolume {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Move a rootfs-/mp-volume to a different storage or to a different container.
  * @param {string} volume Volume which will be moved.
  *   Enum: rootfs,mp0,mp1,mp2,mp3,mp4,mp5,mp6,mp7,mp8,mp9,mp10,mp11,mp12,mp13,mp14,mp15,mp16,mp17,mp18,mp19,mp20,mp21,mp22,mp23,mp24,mp25,mp26,mp27,mp28,mp29,mp30,mp31,mp32,mp33,mp34,mp35,mp36,mp37,mp38,mp39,mp40,mp41,mp42,mp43,mp44,mp45,mp46,mp47,mp48,mp49,mp50,mp51,mp52,mp53,mp54,mp55,mp56,mp57,mp58,mp59,mp60,mp61,mp62,mp63,mp64,mp65,mp66,mp67,mp68,mp69,mp70,mp71,mp72,mp73,mp74,mp75,mp76,mp77,mp78,mp79,mp80,mp81,mp82,mp83,mp84,mp85,mp86,mp87,mp88,mp89,mp90,mp91,mp92,mp93,mp94,mp95,mp96,mp97,mp98,mp99,mp100,mp101,mp102,mp103,mp104,mp105,mp106,mp107,mp108,mp109,mp110,mp111,mp112,mp113,mp114,mp115,mp116,mp117,mp118,mp119,mp120,mp121,mp122,mp123,mp124,mp125,mp126,mp127,mp128,mp129,mp130,mp131,mp132,mp133,mp134,mp135,mp136,mp137,mp138,mp139,mp140,mp141,mp142,mp143,mp144,mp145,mp146,mp147,mp148,mp149,mp150,mp151,mp152,mp153,mp154,mp155,mp156,mp157,mp158,mp159,mp160,mp161,mp162,mp163,mp164,mp165,mp166,mp167,mp168,mp169,mp170,mp171,mp172,mp173,mp174,mp175,mp176,mp177,mp178,mp179,mp180,mp181,mp182,mp183,mp184,mp185,mp186,mp187,mp188,mp189,mp190,mp191,mp192,mp193,mp194,mp195,mp196,mp197,mp198,mp199,mp200,mp201,mp202,mp203,mp204,mp205,mp206,mp207,mp208,mp209,mp210,mp211,mp212,mp213,mp214,mp215,mp216,mp217,mp218,mp219,mp220,mp221,mp222,mp223,mp224,mp225,mp226,mp227,mp228,mp229,mp230,mp231,mp232,mp233,mp234,mp235,mp236,mp237,mp238,mp239,mp240,mp241,mp242,mp243,mp244,mp245,mp246,mp247,mp248,mp249,mp250,mp251,mp252,mp253,mp254,mp255,unused0,unused1,unused2,unused3,unused4,unused5,unused6,unused7,unused8,unused9,unused10,unused11,unused12,unused13,unused14,unused15,unused16,unused17,unused18,unused19,unused20,unused21,unused22,unused23,unused24,unused25,unused26,unused27,unused28,unused29,unused30,unused31,unused32,unused33,unused34,unused35,unused36,unused37,unused38,unused39,unused40,unused41,unused42,unused43,unused44,unused45,unused46,unused47,unused48,unused49,unused50,unused51,unused52,unused53,unused54,unused55,unused56,unused57,unused58,unused59,unused60,unused61,unused62,unused63,unused64,unused65,unused66,unused67,unused68,unused69,unused70,unused71,unused72,unused73,unused74,unused75,unused76,unused77,unused78,unused79,unused80,unused81,unused82,unused83,unused84,unused85,unused86,unused87,unused88,unused89,unused90,unused91,unused92,unused93,unused94,unused95,unused96,unused97,unused98,unused99,unused100,unused101,unused102,unused103,unused104,unused105,unused106,unused107,unused108,unused109,unused110,unused111,unused112,unused113,unused114,unused115,unused116,unused117,unused118,unused119,unused120,unused121,unused122,unused123,unused124,unused125,unused126,unused127,unused128,unused129,unused130,unused131,unused132,unused133,unused134,unused135,unused136,unused137,unused138,unused139,unused140,unused141,unused142,unused143,unused144,unused145,unused146,unused147,unused148,unused149,unused150,unused151,unused152,unused153,unused154,unused155,unused156,unused157,unused158,unused159,unused160,unused161,unused162,unused163,unused164,unused165,unused166,unused167,unused168,unused169,unused170,unused171,unused172,unused173,unused174,unused175,unused176,unused177,unused178,unused179,unused180,unused181,unused182,unused183,unused184,unused185,unused186,unused187,unused188,unused189,unused190,unused191,unused192,unused193,unused194,unused195,unused196,unused197,unused198,unused199,unused200,unused201,unused202,unused203,unused204,unused205,unused206,unused207,unused208,unused209,unused210,unused211,unused212,unused213,unused214,unused215,unused216,unused217,unused218,unused219,unused220,unused221,unused222,unused223,unused224,unused225,unused226,unused227,unused228,unused229,unused230,unused231,unused232,unused233,unused234,unused235,unused236,unused237,unused238,unused239,unused240,unused241,unused242,unused243,unused244,unused245,unused246,unused247,unused248,unused249,unused250,unused251,unused252,unused253,unused254,unused255
  * @param {float} bwlimit Override I/O bandwidth limit (in KiB/s).
  * @param {bool} delete_ Delete the original volume after successful copy. By default the original is kept as an unused volume entry.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 " . 		    "digest. This can be used to prevent concurrent modifications.
  * @param {string} storage Target Storage.
  * @param {string} target_digest Prevent changes if current configuration file of the target " . 		    "container has a different SHA1 digest. This can be used to prevent " . 		    "concurrent modifications.
  * @param {int} target_vmid The (unique) ID of the VM.
  * @param {string} target_volume The config key the volume will be moved to. Default is the source volume key.
  *   Enum: rootfs,mp0,mp1,mp2,mp3,mp4,mp5,mp6,mp7,mp8,mp9,mp10,mp11,mp12,mp13,mp14,mp15,mp16,mp17,mp18,mp19,mp20,mp21,mp22,mp23,mp24,mp25,mp26,mp27,mp28,mp29,mp30,mp31,mp32,mp33,mp34,mp35,mp36,mp37,mp38,mp39,mp40,mp41,mp42,mp43,mp44,mp45,mp46,mp47,mp48,mp49,mp50,mp51,mp52,mp53,mp54,mp55,mp56,mp57,mp58,mp59,mp60,mp61,mp62,mp63,mp64,mp65,mp66,mp67,mp68,mp69,mp70,mp71,mp72,mp73,mp74,mp75,mp76,mp77,mp78,mp79,mp80,mp81,mp82,mp83,mp84,mp85,mp86,mp87,mp88,mp89,mp90,mp91,mp92,mp93,mp94,mp95,mp96,mp97,mp98,mp99,mp100,mp101,mp102,mp103,mp104,mp105,mp106,mp107,mp108,mp109,mp110,mp111,mp112,mp113,mp114,mp115,mp116,mp117,mp118,mp119,mp120,mp121,mp122,mp123,mp124,mp125,mp126,mp127,mp128,mp129,mp130,mp131,mp132,mp133,mp134,mp135,mp136,mp137,mp138,mp139,mp140,mp141,mp142,mp143,mp144,mp145,mp146,mp147,mp148,mp149,mp150,mp151,mp152,mp153,mp154,mp155,mp156,mp157,mp158,mp159,mp160,mp161,mp162,mp163,mp164,mp165,mp166,mp167,mp168,mp169,mp170,mp171,mp172,mp173,mp174,mp175,mp176,mp177,mp178,mp179,mp180,mp181,mp182,mp183,mp184,mp185,mp186,mp187,mp188,mp189,mp190,mp191,mp192,mp193,mp194,mp195,mp196,mp197,mp198,mp199,mp200,mp201,mp202,mp203,mp204,mp205,mp206,mp207,mp208,mp209,mp210,mp211,mp212,mp213,mp214,mp215,mp216,mp217,mp218,mp219,mp220,mp221,mp222,mp223,mp224,mp225,mp226,mp227,mp228,mp229,mp230,mp231,mp232,mp233,mp234,mp235,mp236,mp237,mp238,mp239,mp240,mp241,mp242,mp243,mp244,mp245,mp246,mp247,mp248,mp249,mp250,mp251,mp252,mp253,mp254,mp255,unused0,unused1,unused2,unused3,unused4,unused5,unused6,unused7,unused8,unused9,unused10,unused11,unused12,unused13,unused14,unused15,unused16,unused17,unused18,unused19,unused20,unused21,unused22,unused23,unused24,unused25,unused26,unused27,unused28,unused29,unused30,unused31,unused32,unused33,unused34,unused35,unused36,unused37,unused38,unused39,unused40,unused41,unused42,unused43,unused44,unused45,unused46,unused47,unused48,unused49,unused50,unused51,unused52,unused53,unused54,unused55,unused56,unused57,unused58,unused59,unused60,unused61,unused62,unused63,unused64,unused65,unused66,unused67,unused68,unused69,unused70,unused71,unused72,unused73,unused74,unused75,unused76,unused77,unused78,unused79,unused80,unused81,unused82,unused83,unused84,unused85,unused86,unused87,unused88,unused89,unused90,unused91,unused92,unused93,unused94,unused95,unused96,unused97,unused98,unused99,unused100,unused101,unused102,unused103,unused104,unused105,unused106,unused107,unused108,unused109,unused110,unused111,unused112,unused113,unused114,unused115,unused116,unused117,unused118,unused119,unused120,unused121,unused122,unused123,unused124,unused125,unused126,unused127,unused128,unused129,unused130,unused131,unused132,unused133,unused134,unused135,unused136,unused137,unused138,unused139,unused140,unused141,unused142,unused143,unused144,unused145,unused146,unused147,unused148,unused149,unused150,unused151,unused152,unused153,unused154,unused155,unused156,unused157,unused158,unused159,unused160,unused161,unused162,unused163,unused164,unused165,unused166,unused167,unused168,unused169,unused170,unused171,unused172,unused173,unused174,unused175,unused176,unused177,unused178,unused179,unused180,unused181,unused182,unused183,unused184,unused185,unused186,unused187,unused188,unused189,unused190,unused191,unused192,unused193,unused194,unused195,unused196,unused197,unused198,unused199,unused200,unused201,unused202,unused203,unused204,unused205,unused206,unused207,unused208,unused209,unused210,unused211,unused212,unused213,unused214,unused215,unused216,unused217,unused218,unused219,unused220,unused221,unused222,unused223,unused224,unused225,unused226,unused227,unused228,unused229,unused230,unused231,unused232,unused233,unused234,unused235,unused236,unused237,unused238,unused239,unused240,unused241,unused242,unused243,unused244,unused245,unused246,unused247,unused248,unused249,unused250,unused251,unused252,unused253,unused254,unused255
  * @returns {Result}
  */
  async moveVolume(volume, bwlimit, delete_, digest, storage, target_digest, target_vmid, target_volume) {
    const parameters = {
      'volume': volume,
      'bwlimit': bwlimit,
      'delete': delete_,
      'digest': digest,
      'storage': storage,
      'target-digest': target_digest,
      'target-vmid': target_vmid,
      'target-volume': target_volume
    };
    return await this.#client.create(`/nodes/${this.#node}/lxc/${this.#vmid}/move_volume`, parameters);
  }

}

/**
 * Class PVEVmidLxcNodeNodesPending
 */
class PVEVmidLxcNodeNodesPending {
  #node;
  #vmid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, vmid) {
    this.#client = client;
    this.#node = node;
    this.#vmid = vmid;
  }



  /**
  * Get container configuration, including pending changes.
  * @returns {Result}
  */
  async vmPending() {
    return await this.#client.get(`/nodes/${this.#node}/lxc/${this.#vmid}/pending`);
  }

}

/**
 * Class PVENodeNodesCeph
 */
class PVENodeNodesCeph {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }

  #osd;
  /**
   * Get CephNodeNodesOsd
   * @returns {PVECephNodeNodesOsd}
   */
  get osd() { return this.#osd == null ? (this.#osd = new PVECephNodeNodesOsd(this.#client, this.#node)) : this.#osd; }
  #mds;
  /**
   * Get CephNodeNodesMds
   * @returns {PVECephNodeNodesMds}
   */
  get mds() { return this.#mds == null ? (this.#mds = new PVECephNodeNodesMds(this.#client, this.#node)) : this.#mds; }
  #mgr;
  /**
   * Get CephNodeNodesMgr
   * @returns {PVECephNodeNodesMgr}
   */
  get mgr() { return this.#mgr == null ? (this.#mgr = new PVECephNodeNodesMgr(this.#client, this.#node)) : this.#mgr; }
  #mon;
  /**
   * Get CephNodeNodesMon
   * @returns {PVECephNodeNodesMon}
   */
  get mon() { return this.#mon == null ? (this.#mon = new PVECephNodeNodesMon(this.#client, this.#node)) : this.#mon; }
  #fs;
  /**
   * Get CephNodeNodesFs
   * @returns {PVECephNodeNodesFs}
   */
  get fs() { return this.#fs == null ? (this.#fs = new PVECephNodeNodesFs(this.#client, this.#node)) : this.#fs; }
  #pools;
  /**
   * Get CephNodeNodesPools
   * @returns {PVECephNodeNodesPools}
   */
  get pools() { return this.#pools == null ? (this.#pools = new PVECephNodeNodesPools(this.#client, this.#node)) : this.#pools; }
  #config;
  /**
   * Get CephNodeNodesConfig
   * @returns {PVECephNodeNodesConfig}
   */
  get config() { return this.#config == null ? (this.#config = new PVECephNodeNodesConfig(this.#client, this.#node)) : this.#config; }
  #configdb;
  /**
   * Get CephNodeNodesConfigdb
   * @returns {PVECephNodeNodesConfigdb}
   */
  get configdb() { return this.#configdb == null ? (this.#configdb = new PVECephNodeNodesConfigdb(this.#client, this.#node)) : this.#configdb; }
  #init;
  /**
   * Get CephNodeNodesInit
   * @returns {PVECephNodeNodesInit}
   */
  get init() { return this.#init == null ? (this.#init = new PVECephNodeNodesInit(this.#client, this.#node)) : this.#init; }
  #stop;
  /**
   * Get CephNodeNodesStop
   * @returns {PVECephNodeNodesStop}
   */
  get stop() { return this.#stop == null ? (this.#stop = new PVECephNodeNodesStop(this.#client, this.#node)) : this.#stop; }
  #start;
  /**
   * Get CephNodeNodesStart
   * @returns {PVECephNodeNodesStart}
   */
  get start() { return this.#start == null ? (this.#start = new PVECephNodeNodesStart(this.#client, this.#node)) : this.#start; }
  #restart;
  /**
   * Get CephNodeNodesRestart
   * @returns {PVECephNodeNodesRestart}
   */
  get restart() { return this.#restart == null ? (this.#restart = new PVECephNodeNodesRestart(this.#client, this.#node)) : this.#restart; }
  #status;
  /**
   * Get CephNodeNodesStatus
   * @returns {PVECephNodeNodesStatus}
   */
  get status() { return this.#status == null ? (this.#status = new PVECephNodeNodesStatus(this.#client, this.#node)) : this.#status; }
  #crush;
  /**
   * Get CephNodeNodesCrush
   * @returns {PVECephNodeNodesCrush}
   */
  get crush() { return this.#crush == null ? (this.#crush = new PVECephNodeNodesCrush(this.#client, this.#node)) : this.#crush; }
  #log;
  /**
   * Get CephNodeNodesLog
   * @returns {PVECephNodeNodesLog}
   */
  get log() { return this.#log == null ? (this.#log = new PVECephNodeNodesLog(this.#client, this.#node)) : this.#log; }
  #rules;
  /**
   * Get CephNodeNodesRules
   * @returns {PVECephNodeNodesRules}
   */
  get rules() { return this.#rules == null ? (this.#rules = new PVECephNodeNodesRules(this.#client, this.#node)) : this.#rules; }


  /**
  * Directory index.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/nodes/${this.#node}/ceph`);
  }

}
/**
 * Class PVECephNodeNodesOsd
 */
class PVECephNodeNodesOsd {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }


  /**
   * Get ItemOsdCephNodeNodesOsdid
   * @param osdid
   * @returns {PVEItemOsdCephNodeNodesOsdid}
   */
  get(osdid) { return new PVEItemOsdCephNodeNodesOsdid(this.#client, this.#node, osdid); }

  /**
  * Get Ceph osd list/tree.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/nodes/${this.#node}/ceph/osd`);
  }
  /**
  * Create OSD
  * @param {string} dev Block device name.
  * @param {string} crush_device_class Set the device class of the OSD in crush.
  * @param {string} db_dev Block device name for block.db.
  * @param {float} db_dev_size Size in GiB for block.db.
  * @param {bool} encrypted Enables encryption of the OSD.
  * @param {string} wal_dev Block device name for block.wal.
  * @param {float} wal_dev_size Size in GiB for block.wal.
  * @returns {Result}
  */
  async createosd(dev, crush_device_class, db_dev, db_dev_size, encrypted, wal_dev, wal_dev_size) {
    const parameters = {
      'dev': dev,
      'crush-device-class': crush_device_class,
      'db_dev': db_dev,
      'db_dev_size': db_dev_size,
      'encrypted': encrypted,
      'wal_dev': wal_dev,
      'wal_dev_size': wal_dev_size
    };
    return await this.#client.create(`/nodes/${this.#node}/ceph/osd`, parameters);
  }

}
/**
 * Class PVEItemOsdCephNodeNodesOsdid
 */
class PVEItemOsdCephNodeNodesOsdid {
  #node;
  #osdid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, osdid) {
    this.#client = client;
    this.#node = node;
    this.#osdid = osdid;
  }

  #in;
  /**
   * Get OsdidOsdCephNodeNodesIn
   * @returns {PVEOsdidOsdCephNodeNodesIn}
   */
  get in() { return this.#in == null ? (this.#in = new PVEOsdidOsdCephNodeNodesIn(this.#client, this.#node, this.#osdid)) : this.#in; }
  #out;
  /**
   * Get OsdidOsdCephNodeNodesOut
   * @returns {PVEOsdidOsdCephNodeNodesOut}
   */
  get out() { return this.#out == null ? (this.#out = new PVEOsdidOsdCephNodeNodesOut(this.#client, this.#node, this.#osdid)) : this.#out; }
  #scrub;
  /**
   * Get OsdidOsdCephNodeNodesScrub
   * @returns {PVEOsdidOsdCephNodeNodesScrub}
   */
  get scrub() { return this.#scrub == null ? (this.#scrub = new PVEOsdidOsdCephNodeNodesScrub(this.#client, this.#node, this.#osdid)) : this.#scrub; }


  /**
  * Destroy OSD
  * @param {bool} cleanup If set, we remove partition table entries.
  * @returns {Result}
  */
  async destroyosd(cleanup) {
    const parameters = { 'cleanup': cleanup };
    return await this.#client.delete(`/nodes/${this.#node}/ceph/osd/${this.#osdid}`, parameters);
  }

}
/**
 * Class PVEOsdidOsdCephNodeNodesIn
 */
class PVEOsdidOsdCephNodeNodesIn {
  #node;
  #osdid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, osdid) {
    this.#client = client;
    this.#node = node;
    this.#osdid = osdid;
  }



  /**
  * ceph osd in
  * @returns {Result}
  */
  async in() {
    return await this.#client.create(`/nodes/${this.#node}/ceph/osd/${this.#osdid}/in`);
  }

}

/**
 * Class PVEOsdidOsdCephNodeNodesOut
 */
class PVEOsdidOsdCephNodeNodesOut {
  #node;
  #osdid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, osdid) {
    this.#client = client;
    this.#node = node;
    this.#osdid = osdid;
  }



  /**
  * ceph osd out
  * @returns {Result}
  */
  async out() {
    return await this.#client.create(`/nodes/${this.#node}/ceph/osd/${this.#osdid}/out`);
  }

}

/**
 * Class PVEOsdidOsdCephNodeNodesScrub
 */
class PVEOsdidOsdCephNodeNodesScrub {
  #node;
  #osdid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, osdid) {
    this.#client = client;
    this.#node = node;
    this.#osdid = osdid;
  }



  /**
  * Instruct the OSD to scrub.
  * @param {bool} deep If set, instructs a deep scrub instead of a normal one.
  * @returns {Result}
  */
  async scrub(deep) {
    const parameters = { 'deep': deep };
    return await this.#client.create(`/nodes/${this.#node}/ceph/osd/${this.#osdid}/scrub`, parameters);
  }

}

/**
 * Class PVECephNodeNodesMds
 */
class PVECephNodeNodesMds {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }


  /**
   * Get ItemMdsCephNodeNodesName
   * @param name
   * @returns {PVEItemMdsCephNodeNodesName}
   */
  get(name) { return new PVEItemMdsCephNodeNodesName(this.#client, this.#node, name); }

  /**
  * MDS directory index.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/nodes/${this.#node}/ceph/mds`);
  }

}
/**
 * Class PVEItemMdsCephNodeNodesName
 */
class PVEItemMdsCephNodeNodesName {
  #node;
  #name;
  /** @type {PveClient} */
  #client;

  constructor(client, node, name) {
    this.#client = client;
    this.#node = node;
    this.#name = name;
  }



  /**
  * Destroy Ceph Metadata Server
  * @returns {Result}
  */
  async destroymds() {
    return await this.#client.delete(`/nodes/${this.#node}/ceph/mds/${this.#name}`);
  }
  /**
  * Create Ceph Metadata Server (MDS)
  * @param {bool} hotstandby Determines whether a ceph-mds daemon should poll and replay the log of an active MDS. Faster switch on MDS failure, but needs more idle resources.
  * @returns {Result}
  */
  async createmds(hotstandby) {
    const parameters = { 'hotstandby': hotstandby };
    return await this.#client.create(`/nodes/${this.#node}/ceph/mds/${this.#name}`, parameters);
  }

}

/**
 * Class PVECephNodeNodesMgr
 */
class PVECephNodeNodesMgr {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }


  /**
   * Get ItemMgrCephNodeNodesId
   * @param id
   * @returns {PVEItemMgrCephNodeNodesId}
   */
  get(id) { return new PVEItemMgrCephNodeNodesId(this.#client, this.#node, id); }

  /**
  * MGR directory index.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/nodes/${this.#node}/ceph/mgr`);
  }

}
/**
 * Class PVEItemMgrCephNodeNodesId
 */
class PVEItemMgrCephNodeNodesId {
  #node;
  #id;
  /** @type {PveClient} */
  #client;

  constructor(client, node, id) {
    this.#client = client;
    this.#node = node;
    this.#id = id;
  }



  /**
  * Destroy Ceph Manager.
  * @returns {Result}
  */
  async destroymgr() {
    return await this.#client.delete(`/nodes/${this.#node}/ceph/mgr/${this.#id}`);
  }
  /**
  * Create Ceph Manager
  * @returns {Result}
  */
  async createmgr() {
    return await this.#client.create(`/nodes/${this.#node}/ceph/mgr/${this.#id}`);
  }

}

/**
 * Class PVECephNodeNodesMon
 */
class PVECephNodeNodesMon {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }


  /**
   * Get ItemMonCephNodeNodesMonid
   * @param monid
   * @returns {PVEItemMonCephNodeNodesMonid}
   */
  get(monid) { return new PVEItemMonCephNodeNodesMonid(this.#client, this.#node, monid); }

  /**
  * Get Ceph monitor list.
  * @returns {Result}
  */
  async listmon() {
    return await this.#client.get(`/nodes/${this.#node}/ceph/mon`);
  }

}
/**
 * Class PVEItemMonCephNodeNodesMonid
 */
class PVEItemMonCephNodeNodesMonid {
  #node;
  #monid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, monid) {
    this.#client = client;
    this.#node = node;
    this.#monid = monid;
  }



  /**
  * Destroy Ceph Monitor and Manager.
  * @returns {Result}
  */
  async destroymon() {
    return await this.#client.delete(`/nodes/${this.#node}/ceph/mon/${this.#monid}`);
  }
  /**
  * Create Ceph Monitor and Manager
  * @param {string} mon_address Overwrites autodetected monitor IP address(es). Must be in the public network(s) of Ceph.
  * @returns {Result}
  */
  async createmon(mon_address) {
    const parameters = { 'mon-address': mon_address };
    return await this.#client.create(`/nodes/${this.#node}/ceph/mon/${this.#monid}`, parameters);
  }

}

/**
 * Class PVECephNodeNodesFs
 */
class PVECephNodeNodesFs {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }


  /**
   * Get ItemFsCephNodeNodesName
   * @param name
   * @returns {PVEItemFsCephNodeNodesName}
   */
  get(name) { return new PVEItemFsCephNodeNodesName(this.#client, this.#node, name); }

  /**
  * Directory index.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/nodes/${this.#node}/ceph/fs`);
  }

}
/**
 * Class PVEItemFsCephNodeNodesName
 */
class PVEItemFsCephNodeNodesName {
  #node;
  #name;
  /** @type {PveClient} */
  #client;

  constructor(client, node, name) {
    this.#client = client;
    this.#node = node;
    this.#name = name;
  }



  /**
  * Create a Ceph filesystem
  * @param {bool} add_storage Configure the created CephFS as storage for this cluster.
  * @param {int} pg_num Number of placement groups for the backing data pool. The metadata pool will use a quarter of this.
  * @returns {Result}
  */
  async createfs(add_storage, pg_num) {
    const parameters = {
      'add-storage': add_storage,
      'pg_num': pg_num
    };
    return await this.#client.create(`/nodes/${this.#node}/ceph/fs/${this.#name}`, parameters);
  }

}

/**
 * Class PVECephNodeNodesPools
 */
class PVECephNodeNodesPools {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }


  /**
   * Get ItemPoolsCephNodeNodesName
   * @param name
   * @returns {PVEItemPoolsCephNodeNodesName}
   */
  get(name) { return new PVEItemPoolsCephNodeNodesName(this.#client, this.#node, name); }

  /**
  * List all pools.
  * @returns {Result}
  */
  async lspools() {
    return await this.#client.get(`/nodes/${this.#node}/ceph/pools`);
  }
  /**
  * Create POOL
  * @param {string} name The name of the pool. It must be unique.
  * @param {bool} add_storages Configure VM and CT storage using the new pool.
  * @param {string} application The application of the pool.
  *   Enum: rbd,cephfs,rgw
  * @param {string} crush_rule The rule to use for mapping object placement in the cluster.
  * @param {int} min_size Minimum number of replicas per object
  * @param {string} pg_autoscale_mode The automatic PG scaling mode of the pool.
  *   Enum: on,off,warn
  * @param {int} pg_num Number of placement groups.
  * @param {int} pg_num_min Minimal number of placement groups.
  * @param {int} size Number of replicas per object
  * @param {string} target_size The estimated target size of the pool for the PG autoscaler.
  * @param {float} target_size_ratio The estimated target ratio of the pool for the PG autoscaler.
  * @returns {Result}
  */
  async createpool(name, add_storages, application, crush_rule, min_size, pg_autoscale_mode, pg_num, pg_num_min, size, target_size, target_size_ratio) {
    const parameters = {
      'name': name,
      'add_storages': add_storages,
      'application': application,
      'crush_rule': crush_rule,
      'min_size': min_size,
      'pg_autoscale_mode': pg_autoscale_mode,
      'pg_num': pg_num,
      'pg_num_min': pg_num_min,
      'size': size,
      'target_size': target_size,
      'target_size_ratio': target_size_ratio
    };
    return await this.#client.create(`/nodes/${this.#node}/ceph/pools`, parameters);
  }

}
/**
 * Class PVEItemPoolsCephNodeNodesName
 */
class PVEItemPoolsCephNodeNodesName {
  #node;
  #name;
  /** @type {PveClient} */
  #client;

  constructor(client, node, name) {
    this.#client = client;
    this.#node = node;
    this.#name = name;
  }



  /**
  * Destroy pool
  * @param {bool} force If true, destroys pool even if in use
  * @param {bool} remove_storages Remove all pveceph-managed storages configured for this pool
  * @returns {Result}
  */
  async destroypool(force, remove_storages) {
    const parameters = {
      'force': force,
      'remove_storages': remove_storages
    };
    return await this.#client.delete(`/nodes/${this.#node}/ceph/pools/${this.#name}`, parameters);
  }
  /**
  * List pool settings.
  * @param {bool} verbose If enabled, will display additional data(eg. statistics).
  * @returns {Result}
  */
  async getpool(verbose) {
    const parameters = { 'verbose': verbose };
    return await this.#client.get(`/nodes/${this.#node}/ceph/pools/${this.#name}`, parameters);
  }
  /**
  * Change POOL settings
  * @param {string} application The application of the pool.
  *   Enum: rbd,cephfs,rgw
  * @param {string} crush_rule The rule to use for mapping object placement in the cluster.
  * @param {int} min_size Minimum number of replicas per object
  * @param {string} pg_autoscale_mode The automatic PG scaling mode of the pool.
  *   Enum: on,off,warn
  * @param {int} pg_num Number of placement groups.
  * @param {int} pg_num_min Minimal number of placement groups.
  * @param {int} size Number of replicas per object
  * @param {string} target_size The estimated target size of the pool for the PG autoscaler.
  * @param {float} target_size_ratio The estimated target ratio of the pool for the PG autoscaler.
  * @returns {Result}
  */
  async setpool(application, crush_rule, min_size, pg_autoscale_mode, pg_num, pg_num_min, size, target_size, target_size_ratio) {
    const parameters = {
      'application': application,
      'crush_rule': crush_rule,
      'min_size': min_size,
      'pg_autoscale_mode': pg_autoscale_mode,
      'pg_num': pg_num,
      'pg_num_min': pg_num_min,
      'size': size,
      'target_size': target_size,
      'target_size_ratio': target_size_ratio
    };
    return await this.#client.set(`/nodes/${this.#node}/ceph/pools/${this.#name}`, parameters);
  }

}

/**
 * Class PVECephNodeNodesConfig
 */
class PVECephNodeNodesConfig {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Get Ceph configuration.
  * @returns {Result}
  */
  async config() {
    return await this.#client.get(`/nodes/${this.#node}/ceph/config`);
  }

}

/**
 * Class PVECephNodeNodesConfigdb
 */
class PVECephNodeNodesConfigdb {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Get Ceph configuration database.
  * @returns {Result}
  */
  async configdb() {
    return await this.#client.get(`/nodes/${this.#node}/ceph/configdb`);
  }

}

/**
 * Class PVECephNodeNodesInit
 */
class PVECephNodeNodesInit {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Create initial ceph default configuration and setup symlinks.
  * @param {string} cluster_network Declare a separate cluster network, OSDs will routeheartbeat, object replication and recovery traffic over it
  * @param {bool} disable_cephx Disable cephx authentication.  WARNING: cephx is a security feature protecting against man-in-the-middle attacks. Only consider disabling cephx if your network is private!
  * @param {int} min_size Minimum number of available replicas per object to allow I/O
  * @param {string} network Use specific network for all ceph related traffic
  * @param {int} pg_bits Placement group bits, used to specify the default number of placement groups.  NOTE: 'osd pool default pg num' does not work for default pools.
  * @param {int} size Targeted number of replicas per object
  * @returns {Result}
  */
  async init(cluster_network, disable_cephx, min_size, network, pg_bits, size) {
    const parameters = {
      'cluster-network': cluster_network,
      'disable_cephx': disable_cephx,
      'min_size': min_size,
      'network': network,
      'pg_bits': pg_bits,
      'size': size
    };
    return await this.#client.create(`/nodes/${this.#node}/ceph/init`, parameters);
  }

}

/**
 * Class PVECephNodeNodesStop
 */
class PVECephNodeNodesStop {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Stop ceph services.
  * @param {string} service Ceph service name.
  * @returns {Result}
  */
  async stop(service) {
    const parameters = { 'service': service };
    return await this.#client.create(`/nodes/${this.#node}/ceph/stop`, parameters);
  }

}

/**
 * Class PVECephNodeNodesStart
 */
class PVECephNodeNodesStart {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Start ceph services.
  * @param {string} service Ceph service name.
  * @returns {Result}
  */
  async start(service) {
    const parameters = { 'service': service };
    return await this.#client.create(`/nodes/${this.#node}/ceph/start`, parameters);
  }

}

/**
 * Class PVECephNodeNodesRestart
 */
class PVECephNodeNodesRestart {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Restart ceph services.
  * @param {string} service Ceph service name.
  * @returns {Result}
  */
  async restart(service) {
    const parameters = { 'service': service };
    return await this.#client.create(`/nodes/${this.#node}/ceph/restart`, parameters);
  }

}

/**
 * Class PVECephNodeNodesStatus
 */
class PVECephNodeNodesStatus {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Get ceph status.
  * @returns {Result}
  */
  async status() {
    return await this.#client.get(`/nodes/${this.#node}/ceph/status`);
  }

}

/**
 * Class PVECephNodeNodesCrush
 */
class PVECephNodeNodesCrush {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Get OSD crush map
  * @returns {Result}
  */
  async crush() {
    return await this.#client.get(`/nodes/${this.#node}/ceph/crush`);
  }

}

/**
 * Class PVECephNodeNodesLog
 */
class PVECephNodeNodesLog {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Read ceph log
  * @param {int} limit
  * @param {int} start
  * @returns {Result}
  */
  async log(limit, start) {
    const parameters = {
      'limit': limit,
      'start': start
    };
    return await this.#client.get(`/nodes/${this.#node}/ceph/log`, parameters);
  }

}

/**
 * Class PVECephNodeNodesRules
 */
class PVECephNodeNodesRules {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * List ceph rules.
  * @returns {Result}
  */
  async rules() {
    return await this.#client.get(`/nodes/${this.#node}/ceph/rules`);
  }

}

/**
 * Class PVENodeNodesVzdump
 */
class PVENodeNodesVzdump {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }

  #defaults;
  /**
   * Get VzdumpNodeNodesDefaults
   * @returns {PVEVzdumpNodeNodesDefaults}
   */
  get defaults() { return this.#defaults == null ? (this.#defaults = new PVEVzdumpNodeNodesDefaults(this.#client, this.#node)) : this.#defaults; }
  #extractconfig;
  /**
   * Get VzdumpNodeNodesExtractconfig
   * @returns {PVEVzdumpNodeNodesExtractconfig}
   */
  get extractconfig() { return this.#extractconfig == null ? (this.#extractconfig = new PVEVzdumpNodeNodesExtractconfig(this.#client, this.#node)) : this.#extractconfig; }


  /**
  * Create backup.
  * @param {bool} all Backup all known guest systems on this host.
  * @param {int} bwlimit Limit I/O bandwidth (KBytes per second).
  * @param {string} compress Compress dump file.
  *   Enum: 0,1,gzip,lzo,zstd
  * @param {string} dumpdir Store resulting files to specified directory.
  * @param {string} exclude Exclude specified guest systems (assumes --all)
  * @param {string} exclude_path Exclude certain files/directories (shell globs). Paths starting with '/' are anchored to the container's root,  other paths match relative to each subdirectory.
  * @param {int} ionice Set CFQ ionice priority.
  * @param {int} lockwait Maximal time to wait for the global lock (minutes).
  * @param {string} mailnotification Specify when to send an email
  *   Enum: always,failure
  * @param {string} mailto Comma-separated list of email addresses or users that should receive email notifications.
  * @param {int} maxfiles Deprecated: use 'prune-backups' instead. Maximal number of backup files per guest system.
  * @param {string} mode Backup mode.
  *   Enum: snapshot,suspend,stop
  * @param {int} pigz Use pigz instead of gzip when N&amp;gt;0. N=1 uses half of cores, N&amp;gt;1 uses N as thread count.
  * @param {string} pool Backup all known guest systems included in the specified pool.
  * @param {string} prune_backups Use these retention options instead of those from the storage configuration.
  * @param {bool} quiet Be quiet.
  * @param {bool} remove Prune older backups according to 'prune-backups'.
  * @param {string} script Use specified hook script.
  * @param {bool} stdexcludes Exclude temporary files and logs.
  * @param {bool} stdout Write tar to stdout, not to a file.
  * @param {bool} stop Stop running backup jobs on this host.
  * @param {int} stopwait Maximal time to wait until a guest system is stopped (minutes).
  * @param {string} storage Store resulting file to this storage.
  * @param {string} tmpdir Store temporary files to specified directory.
  * @param {string} vmid The ID of the guest system you want to backup.
  * @param {int} zstd Zstd threads. N=0 uses half of the available cores, N&amp;gt;0 uses N as thread count.
  * @returns {Result}
  */
  async vzdump(all, bwlimit, compress, dumpdir, exclude, exclude_path, ionice, lockwait, mailnotification, mailto, maxfiles, mode, pigz, pool, prune_backups, quiet, remove, script, stdexcludes, stdout, stop, stopwait, storage, tmpdir, vmid, zstd) {
    const parameters = {
      'all': all,
      'bwlimit': bwlimit,
      'compress': compress,
      'dumpdir': dumpdir,
      'exclude': exclude,
      'exclude-path': exclude_path,
      'ionice': ionice,
      'lockwait': lockwait,
      'mailnotification': mailnotification,
      'mailto': mailto,
      'maxfiles': maxfiles,
      'mode': mode,
      'pigz': pigz,
      'pool': pool,
      'prune-backups': prune_backups,
      'quiet': quiet,
      'remove': remove,
      'script': script,
      'stdexcludes': stdexcludes,
      'stdout': stdout,
      'stop': stop,
      'stopwait': stopwait,
      'storage': storage,
      'tmpdir': tmpdir,
      'vmid': vmid,
      'zstd': zstd
    };
    return await this.#client.create(`/nodes/${this.#node}/vzdump`, parameters);
  }

}
/**
 * Class PVEVzdumpNodeNodesDefaults
 */
class PVEVzdumpNodeNodesDefaults {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Get the currently configured vzdump defaults.
  * @param {string} storage The storage identifier.
  * @returns {Result}
  */
  async defaults(storage) {
    const parameters = { 'storage': storage };
    return await this.#client.get(`/nodes/${this.#node}/vzdump/defaults`, parameters);
  }

}

/**
 * Class PVEVzdumpNodeNodesExtractconfig
 */
class PVEVzdumpNodeNodesExtractconfig {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Extract configuration from vzdump backup archive.
  * @param {string} volume Volume identifier
  * @returns {Result}
  */
  async extractconfig(volume) {
    const parameters = { 'volume': volume };
    return await this.#client.get(`/nodes/${this.#node}/vzdump/extractconfig`, parameters);
  }

}

/**
 * Class PVENodeNodesServices
 */
class PVENodeNodesServices {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }


  /**
   * Get ItemServicesNodeNodesService
   * @param service
   * @returns {PVEItemServicesNodeNodesService}
   */
  get(service) { return new PVEItemServicesNodeNodesService(this.#client, this.#node, service); }

  /**
  * Service list.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/nodes/${this.#node}/services`);
  }

}
/**
 * Class PVEItemServicesNodeNodesService
 */
class PVEItemServicesNodeNodesService {
  #node;
  #service;
  /** @type {PveClient} */
  #client;

  constructor(client, node, service) {
    this.#client = client;
    this.#node = node;
    this.#service = service;
  }

  #state;
  /**
   * Get ServiceServicesNodeNodesState
   * @returns {PVEServiceServicesNodeNodesState}
   */
  get state() { return this.#state == null ? (this.#state = new PVEServiceServicesNodeNodesState(this.#client, this.#node, this.#service)) : this.#state; }
  #start;
  /**
   * Get ServiceServicesNodeNodesStart
   * @returns {PVEServiceServicesNodeNodesStart}
   */
  get start() { return this.#start == null ? (this.#start = new PVEServiceServicesNodeNodesStart(this.#client, this.#node, this.#service)) : this.#start; }
  #stop;
  /**
   * Get ServiceServicesNodeNodesStop
   * @returns {PVEServiceServicesNodeNodesStop}
   */
  get stop() { return this.#stop == null ? (this.#stop = new PVEServiceServicesNodeNodesStop(this.#client, this.#node, this.#service)) : this.#stop; }
  #restart;
  /**
   * Get ServiceServicesNodeNodesRestart
   * @returns {PVEServiceServicesNodeNodesRestart}
   */
  get restart() { return this.#restart == null ? (this.#restart = new PVEServiceServicesNodeNodesRestart(this.#client, this.#node, this.#service)) : this.#restart; }
  #reload;
  /**
   * Get ServiceServicesNodeNodesReload
   * @returns {PVEServiceServicesNodeNodesReload}
   */
  get reload() { return this.#reload == null ? (this.#reload = new PVEServiceServicesNodeNodesReload(this.#client, this.#node, this.#service)) : this.#reload; }


  /**
  * Directory index
  * @returns {Result}
  */
  async srvcmdidx() {
    return await this.#client.get(`/nodes/${this.#node}/services/${this.#service}`);
  }

}
/**
 * Class PVEServiceServicesNodeNodesState
 */
class PVEServiceServicesNodeNodesState {
  #node;
  #service;
  /** @type {PveClient} */
  #client;

  constructor(client, node, service) {
    this.#client = client;
    this.#node = node;
    this.#service = service;
  }



  /**
  * Read service properties
  * @returns {Result}
  */
  async serviceState() {
    return await this.#client.get(`/nodes/${this.#node}/services/${this.#service}/state`);
  }

}

/**
 * Class PVEServiceServicesNodeNodesStart
 */
class PVEServiceServicesNodeNodesStart {
  #node;
  #service;
  /** @type {PveClient} */
  #client;

  constructor(client, node, service) {
    this.#client = client;
    this.#node = node;
    this.#service = service;
  }



  /**
  * Start service.
  * @returns {Result}
  */
  async serviceStart() {
    return await this.#client.create(`/nodes/${this.#node}/services/${this.#service}/start`);
  }

}

/**
 * Class PVEServiceServicesNodeNodesStop
 */
class PVEServiceServicesNodeNodesStop {
  #node;
  #service;
  /** @type {PveClient} */
  #client;

  constructor(client, node, service) {
    this.#client = client;
    this.#node = node;
    this.#service = service;
  }



  /**
  * Stop service.
  * @returns {Result}
  */
  async serviceStop() {
    return await this.#client.create(`/nodes/${this.#node}/services/${this.#service}/stop`);
  }

}

/**
 * Class PVEServiceServicesNodeNodesRestart
 */
class PVEServiceServicesNodeNodesRestart {
  #node;
  #service;
  /** @type {PveClient} */
  #client;

  constructor(client, node, service) {
    this.#client = client;
    this.#node = node;
    this.#service = service;
  }



  /**
  * Hard restart service. Use reload if you want to reduce interruptions.
  * @returns {Result}
  */
  async serviceRestart() {
    return await this.#client.create(`/nodes/${this.#node}/services/${this.#service}/restart`);
  }

}

/**
 * Class PVEServiceServicesNodeNodesReload
 */
class PVEServiceServicesNodeNodesReload {
  #node;
  #service;
  /** @type {PveClient} */
  #client;

  constructor(client, node, service) {
    this.#client = client;
    this.#node = node;
    this.#service = service;
  }



  /**
  * Reload service. Falls back to restart if service cannot be reloaded.
  * @returns {Result}
  */
  async serviceReload() {
    return await this.#client.create(`/nodes/${this.#node}/services/${this.#service}/reload`);
  }

}

/**
 * Class PVENodeNodesSubscription
 */
class PVENodeNodesSubscription {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Delete subscription key of this node.
  * @returns {Result}
  */
  async delete_() {
    return await this.#client.delete(`/nodes/${this.#node}/subscription`);
  }
  /**
  * Read subscription info.
  * @returns {Result}
  */
  async get() {
    return await this.#client.get(`/nodes/${this.#node}/subscription`);
  }
  /**
  * Update subscription info.
  * @param {bool} force Always connect to server, even if we have up to date info inside local cache.
  * @returns {Result}
  */
  async update(force) {
    const parameters = { 'force': force };
    return await this.#client.create(`/nodes/${this.#node}/subscription`, parameters);
  }
  /**
  * Set subscription key.
  * @param {string} key Proxmox VE subscription key
  * @returns {Result}
  */
  async set(key) {
    const parameters = { 'key': key };
    return await this.#client.set(`/nodes/${this.#node}/subscription`, parameters);
  }

}

/**
 * Class PVENodeNodesNetwork
 */
class PVENodeNodesNetwork {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }


  /**
   * Get ItemNetworkNodeNodesIface
   * @param iface
   * @returns {PVEItemNetworkNodeNodesIface}
   */
  get(iface) { return new PVEItemNetworkNodeNodesIface(this.#client, this.#node, iface); }

  /**
  * Revert network configuration changes.
  * @returns {Result}
  */
  async revertNetworkChanges() {
    return await this.#client.delete(`/nodes/${this.#node}/network`);
  }
  /**
  * List available networks
  * @param {string} type Only list specific interface types.
  *   Enum: bridge,bond,eth,alias,vlan,OVSBridge,OVSBond,OVSPort,OVSIntPort,any_bridge
  * @returns {Result}
  */
  async index(type) {
    const parameters = { 'type': type };
    return await this.#client.get(`/nodes/${this.#node}/network`, parameters);
  }
  /**
  * Create network device configuration
  * @param {string} iface Network interface name.
  * @param {string} type Network interface type
  *   Enum: bridge,bond,eth,alias,vlan,OVSBridge,OVSBond,OVSPort,OVSIntPort,unknown
  * @param {string} address IP address.
  * @param {string} address6 IP address.
  * @param {bool} autostart Automatically start interface on boot.
  * @param {string} bond_primary Specify the primary interface for active-backup bond.
  * @param {string} bond_mode Bonding mode.
  *   Enum: balance-rr,active-backup,balance-xor,broadcast,802.3ad,balance-tlb,balance-alb,balance-slb,lacp-balance-slb,lacp-balance-tcp
  * @param {string} bond_xmit_hash_policy Selects the transmit hash policy to use for slave selection in balance-xor and 802.3ad modes.
  *   Enum: layer2,layer2+3,layer3+4
  * @param {string} bridge_ports Specify the interfaces you want to add to your bridge.
  * @param {bool} bridge_vlan_aware Enable bridge vlan support.
  * @param {string} cidr IPv4 CIDR.
  * @param {string} cidr6 IPv6 CIDR.
  * @param {string} comments Comments
  * @param {string} comments6 Comments
  * @param {string} gateway Default gateway address.
  * @param {string} gateway6 Default ipv6 gateway address.
  * @param {int} mtu MTU.
  * @param {string} netmask Network mask.
  * @param {int} netmask6 Network mask.
  * @param {string} ovs_bonds Specify the interfaces used by the bonding device.
  * @param {string} ovs_bridge The OVS bridge associated with a OVS port. This is required when you create an OVS port.
  * @param {string} ovs_options OVS interface options.
  * @param {string} ovs_ports Specify the interfaces you want to add to your bridge.
  * @param {int} ovs_tag Specify a VLan tag (used by OVSPort, OVSIntPort, OVSBond)
  * @param {string} slaves Specify the interfaces used by the bonding device.
  * @param {int} vlan_id vlan-id for a custom named vlan interface (ifupdown2 only).
  * @param {string} vlan_raw_device Specify the raw interface for the vlan interface.
  * @returns {Result}
  */
  async createNetwork(iface, type, address, address6, autostart, bond_primary, bond_mode, bond_xmit_hash_policy, bridge_ports, bridge_vlan_aware, cidr, cidr6, comments, comments6, gateway, gateway6, mtu, netmask, netmask6, ovs_bonds, ovs_bridge, ovs_options, ovs_ports, ovs_tag, slaves, vlan_id, vlan_raw_device) {
    const parameters = {
      'iface': iface,
      'type': type,
      'address': address,
      'address6': address6,
      'autostart': autostart,
      'bond-primary': bond_primary,
      'bond_mode': bond_mode,
      'bond_xmit_hash_policy': bond_xmit_hash_policy,
      'bridge_ports': bridge_ports,
      'bridge_vlan_aware': bridge_vlan_aware,
      'cidr': cidr,
      'cidr6': cidr6,
      'comments': comments,
      'comments6': comments6,
      'gateway': gateway,
      'gateway6': gateway6,
      'mtu': mtu,
      'netmask': netmask,
      'netmask6': netmask6,
      'ovs_bonds': ovs_bonds,
      'ovs_bridge': ovs_bridge,
      'ovs_options': ovs_options,
      'ovs_ports': ovs_ports,
      'ovs_tag': ovs_tag,
      'slaves': slaves,
      'vlan-id': vlan_id,
      'vlan-raw-device': vlan_raw_device
    };
    return await this.#client.create(`/nodes/${this.#node}/network`, parameters);
  }
  /**
  * Reload network configuration
  * @returns {Result}
  */
  async reloadNetworkConfig() {
    return await this.#client.set(`/nodes/${this.#node}/network`);
  }

}
/**
 * Class PVEItemNetworkNodeNodesIface
 */
class PVEItemNetworkNodeNodesIface {
  #node;
  #iface;
  /** @type {PveClient} */
  #client;

  constructor(client, node, iface) {
    this.#client = client;
    this.#node = node;
    this.#iface = iface;
  }



  /**
  * Delete network device configuration
  * @returns {Result}
  */
  async deleteNetwork() {
    return await this.#client.delete(`/nodes/${this.#node}/network/${this.#iface}`);
  }
  /**
  * Read network device configuration
  * @returns {Result}
  */
  async networkConfig() {
    return await this.#client.get(`/nodes/${this.#node}/network/${this.#iface}`);
  }
  /**
  * Update network device configuration
  * @param {string} type Network interface type
  *   Enum: bridge,bond,eth,alias,vlan,OVSBridge,OVSBond,OVSPort,OVSIntPort,unknown
  * @param {string} address IP address.
  * @param {string} address6 IP address.
  * @param {bool} autostart Automatically start interface on boot.
  * @param {string} bond_primary Specify the primary interface for active-backup bond.
  * @param {string} bond_mode Bonding mode.
  *   Enum: balance-rr,active-backup,balance-xor,broadcast,802.3ad,balance-tlb,balance-alb,balance-slb,lacp-balance-slb,lacp-balance-tcp
  * @param {string} bond_xmit_hash_policy Selects the transmit hash policy to use for slave selection in balance-xor and 802.3ad modes.
  *   Enum: layer2,layer2+3,layer3+4
  * @param {string} bridge_ports Specify the interfaces you want to add to your bridge.
  * @param {bool} bridge_vlan_aware Enable bridge vlan support.
  * @param {string} cidr IPv4 CIDR.
  * @param {string} cidr6 IPv6 CIDR.
  * @param {string} comments Comments
  * @param {string} comments6 Comments
  * @param {string} delete_ A list of settings you want to delete.
  * @param {string} gateway Default gateway address.
  * @param {string} gateway6 Default ipv6 gateway address.
  * @param {int} mtu MTU.
  * @param {string} netmask Network mask.
  * @param {int} netmask6 Network mask.
  * @param {string} ovs_bonds Specify the interfaces used by the bonding device.
  * @param {string} ovs_bridge The OVS bridge associated with a OVS port. This is required when you create an OVS port.
  * @param {string} ovs_options OVS interface options.
  * @param {string} ovs_ports Specify the interfaces you want to add to your bridge.
  * @param {int} ovs_tag Specify a VLan tag (used by OVSPort, OVSIntPort, OVSBond)
  * @param {string} slaves Specify the interfaces used by the bonding device.
  * @param {int} vlan_id vlan-id for a custom named vlan interface (ifupdown2 only).
  * @param {string} vlan_raw_device Specify the raw interface for the vlan interface.
  * @returns {Result}
  */
  async updateNetwork(type, address, address6, autostart, bond_primary, bond_mode, bond_xmit_hash_policy, bridge_ports, bridge_vlan_aware, cidr, cidr6, comments, comments6, delete_, gateway, gateway6, mtu, netmask, netmask6, ovs_bonds, ovs_bridge, ovs_options, ovs_ports, ovs_tag, slaves, vlan_id, vlan_raw_device) {
    const parameters = {
      'type': type,
      'address': address,
      'address6': address6,
      'autostart': autostart,
      'bond-primary': bond_primary,
      'bond_mode': bond_mode,
      'bond_xmit_hash_policy': bond_xmit_hash_policy,
      'bridge_ports': bridge_ports,
      'bridge_vlan_aware': bridge_vlan_aware,
      'cidr': cidr,
      'cidr6': cidr6,
      'comments': comments,
      'comments6': comments6,
      'delete': delete_,
      'gateway': gateway,
      'gateway6': gateway6,
      'mtu': mtu,
      'netmask': netmask,
      'netmask6': netmask6,
      'ovs_bonds': ovs_bonds,
      'ovs_bridge': ovs_bridge,
      'ovs_options': ovs_options,
      'ovs_ports': ovs_ports,
      'ovs_tag': ovs_tag,
      'slaves': slaves,
      'vlan-id': vlan_id,
      'vlan-raw-device': vlan_raw_device
    };
    return await this.#client.set(`/nodes/${this.#node}/network/${this.#iface}`, parameters);
  }

}

/**
 * Class PVENodeNodesTasks
 */
class PVENodeNodesTasks {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }


  /**
   * Get ItemTasksNodeNodesUpid
   * @param upid
   * @returns {PVEItemTasksNodeNodesUpid}
   */
  get(upid) { return new PVEItemTasksNodeNodesUpid(this.#client, this.#node, upid); }

  /**
  * Read task list for one node (finished tasks).
  * @param {bool} errors Only list tasks with a status of ERROR.
  * @param {int} limit Only list this amount of tasks.
  * @param {int} since Only list tasks since this UNIX epoch.
  * @param {string} source List archived, active or all tasks.
  *   Enum: archive,active,all
  * @param {int} start List tasks beginning from this offset.
  * @param {string} statusfilter List of Task States that should be returned.
  * @param {string} typefilter Only list tasks of this type (e.g., vzstart, vzdump).
  * @param {int} until Only list tasks until this UNIX epoch.
  * @param {string} userfilter Only list tasks from this user.
  * @param {int} vmid Only list tasks for this VM.
  * @returns {Result}
  */
  async nodeTasks(errors, limit, since, source, start, statusfilter, typefilter, until, userfilter, vmid) {
    const parameters = {
      'errors': errors,
      'limit': limit,
      'since': since,
      'source': source,
      'start': start,
      'statusfilter': statusfilter,
      'typefilter': typefilter,
      'until': until,
      'userfilter': userfilter,
      'vmid': vmid
    };
    return await this.#client.get(`/nodes/${this.#node}/tasks`, parameters);
  }

}
/**
 * Class PVEItemTasksNodeNodesUpid
 */
class PVEItemTasksNodeNodesUpid {
  #node;
  #upid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, upid) {
    this.#client = client;
    this.#node = node;
    this.#upid = upid;
  }

  #log;
  /**
   * Get UpidTasksNodeNodesLog
   * @returns {PVEUpidTasksNodeNodesLog}
   */
  get log() { return this.#log == null ? (this.#log = new PVEUpidTasksNodeNodesLog(this.#client, this.#node, this.#upid)) : this.#log; }
  #status;
  /**
   * Get UpidTasksNodeNodesStatus
   * @returns {PVEUpidTasksNodeNodesStatus}
   */
  get status() { return this.#status == null ? (this.#status = new PVEUpidTasksNodeNodesStatus(this.#client, this.#node, this.#upid)) : this.#status; }


  /**
  * Stop a task.
  * @returns {Result}
  */
  async stopTask() {
    return await this.#client.delete(`/nodes/${this.#node}/tasks/${this.#upid}`);
  }
  /**
  *
  * @returns {Result}
  */
  async upidIndex() {
    return await this.#client.get(`/nodes/${this.#node}/tasks/${this.#upid}`);
  }

}
/**
 * Class PVEUpidTasksNodeNodesLog
 */
class PVEUpidTasksNodeNodesLog {
  #node;
  #upid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, upid) {
    this.#client = client;
    this.#node = node;
    this.#upid = upid;
  }



  /**
  * Read task log.
  * @param {int} limit The maximum amount of lines that should be printed.
  * @param {int} start The line number to start printing at.
  * @returns {Result}
  */
  async readTaskLog(limit, start) {
    const parameters = {
      'limit': limit,
      'start': start
    };
    return await this.#client.get(`/nodes/${this.#node}/tasks/${this.#upid}/log`, parameters);
  }

}

/**
 * Class PVEUpidTasksNodeNodesStatus
 */
class PVEUpidTasksNodeNodesStatus {
  #node;
  #upid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, upid) {
    this.#client = client;
    this.#node = node;
    this.#upid = upid;
  }



  /**
  * Read task status.
  * @returns {Result}
  */
  async readTaskStatus() {
    return await this.#client.get(`/nodes/${this.#node}/tasks/${this.#upid}/status`);
  }

}

/**
 * Class PVENodeNodesScan
 */
class PVENodeNodesScan {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }

  #nfs;
  /**
   * Get ScanNodeNodesNfs
   * @returns {PVEScanNodeNodesNfs}
   */
  get nfs() { return this.#nfs == null ? (this.#nfs = new PVEScanNodeNodesNfs(this.#client, this.#node)) : this.#nfs; }
  #cifs;
  /**
   * Get ScanNodeNodesCifs
   * @returns {PVEScanNodeNodesCifs}
   */
  get cifs() { return this.#cifs == null ? (this.#cifs = new PVEScanNodeNodesCifs(this.#client, this.#node)) : this.#cifs; }
  #pbs;
  /**
   * Get ScanNodeNodesPbs
   * @returns {PVEScanNodeNodesPbs}
   */
  get pbs() { return this.#pbs == null ? (this.#pbs = new PVEScanNodeNodesPbs(this.#client, this.#node)) : this.#pbs; }
  #glusterfs;
  /**
   * Get ScanNodeNodesGlusterfs
   * @returns {PVEScanNodeNodesGlusterfs}
   */
  get glusterfs() { return this.#glusterfs == null ? (this.#glusterfs = new PVEScanNodeNodesGlusterfs(this.#client, this.#node)) : this.#glusterfs; }
  #iscsi;
  /**
   * Get ScanNodeNodesIscsi
   * @returns {PVEScanNodeNodesIscsi}
   */
  get iscsi() { return this.#iscsi == null ? (this.#iscsi = new PVEScanNodeNodesIscsi(this.#client, this.#node)) : this.#iscsi; }
  #lvm;
  /**
   * Get ScanNodeNodesLvm
   * @returns {PVEScanNodeNodesLvm}
   */
  get lvm() { return this.#lvm == null ? (this.#lvm = new PVEScanNodeNodesLvm(this.#client, this.#node)) : this.#lvm; }
  #lvmthin;
  /**
   * Get ScanNodeNodesLvmthin
   * @returns {PVEScanNodeNodesLvmthin}
   */
  get lvmthin() { return this.#lvmthin == null ? (this.#lvmthin = new PVEScanNodeNodesLvmthin(this.#client, this.#node)) : this.#lvmthin; }
  #zfs;
  /**
   * Get ScanNodeNodesZfs
   * @returns {PVEScanNodeNodesZfs}
   */
  get zfs() { return this.#zfs == null ? (this.#zfs = new PVEScanNodeNodesZfs(this.#client, this.#node)) : this.#zfs; }


  /**
  * Index of available scan methods
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/nodes/${this.#node}/scan`);
  }

}
/**
 * Class PVEScanNodeNodesNfs
 */
class PVEScanNodeNodesNfs {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Scan remote NFS server.
  * @param {string} server The server address (name or IP).
  * @returns {Result}
  */
  async nfsscan(server) {
    const parameters = { 'server': server };
    return await this.#client.get(`/nodes/${this.#node}/scan/nfs`, parameters);
  }

}

/**
 * Class PVEScanNodeNodesCifs
 */
class PVEScanNodeNodesCifs {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Scan remote CIFS server.
  * @param {string} server The server address (name or IP).
  * @param {string} domain SMB domain (Workgroup).
  * @param {string} password User password.
  * @param {string} username User name.
  * @returns {Result}
  */
  async cifsscan(server, domain, password, username) {
    const parameters = {
      'server': server,
      'domain': domain,
      'password': password,
      'username': username
    };
    return await this.#client.get(`/nodes/${this.#node}/scan/cifs`, parameters);
  }

}

/**
 * Class PVEScanNodeNodesPbs
 */
class PVEScanNodeNodesPbs {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Scan remote Proxmox Backup Server.
  * @param {string} password User password or API token secret.
  * @param {string} server The server address (name or IP).
  * @param {string} username User-name or API token-ID.
  * @param {string} fingerprint Certificate SHA 256 fingerprint.
  * @param {int} port Optional port.
  * @returns {Result}
  */
  async pbsscan(password, server, username, fingerprint, port) {
    const parameters = {
      'password': password,
      'server': server,
      'username': username,
      'fingerprint': fingerprint,
      'port': port
    };
    return await this.#client.get(`/nodes/${this.#node}/scan/pbs`, parameters);
  }

}

/**
 * Class PVEScanNodeNodesGlusterfs
 */
class PVEScanNodeNodesGlusterfs {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Scan remote GlusterFS server.
  * @param {string} server The server address (name or IP).
  * @returns {Result}
  */
  async glusterfsscan(server) {
    const parameters = { 'server': server };
    return await this.#client.get(`/nodes/${this.#node}/scan/glusterfs`, parameters);
  }

}

/**
 * Class PVEScanNodeNodesIscsi
 */
class PVEScanNodeNodesIscsi {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Scan remote iSCSI server.
  * @param {string} portal The iSCSI portal (IP or DNS name with optional port).
  * @returns {Result}
  */
  async iscsiscan(portal) {
    const parameters = { 'portal': portal };
    return await this.#client.get(`/nodes/${this.#node}/scan/iscsi`, parameters);
  }

}

/**
 * Class PVEScanNodeNodesLvm
 */
class PVEScanNodeNodesLvm {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * List local LVM volume groups.
  * @returns {Result}
  */
  async lvmscan() {
    return await this.#client.get(`/nodes/${this.#node}/scan/lvm`);
  }

}

/**
 * Class PVEScanNodeNodesLvmthin
 */
class PVEScanNodeNodesLvmthin {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * List local LVM Thin Pools.
  * @param {string} vg
  * @returns {Result}
  */
  async lvmthinscan(vg) {
    const parameters = { 'vg': vg };
    return await this.#client.get(`/nodes/${this.#node}/scan/lvmthin`, parameters);
  }

}

/**
 * Class PVEScanNodeNodesZfs
 */
class PVEScanNodeNodesZfs {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Scan zfs pool list on local node.
  * @returns {Result}
  */
  async zfsscan() {
    return await this.#client.get(`/nodes/${this.#node}/scan/zfs`);
  }

}

/**
 * Class PVENodeNodesHardware
 */
class PVENodeNodesHardware {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }

  #pci;
  /**
   * Get HardwareNodeNodesPci
   * @returns {PVEHardwareNodeNodesPci}
   */
  get pci() { return this.#pci == null ? (this.#pci = new PVEHardwareNodeNodesPci(this.#client, this.#node)) : this.#pci; }
  #usb;
  /**
   * Get HardwareNodeNodesUsb
   * @returns {PVEHardwareNodeNodesUsb}
   */
  get usb() { return this.#usb == null ? (this.#usb = new PVEHardwareNodeNodesUsb(this.#client, this.#node)) : this.#usb; }


  /**
  * Index of hardware types
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/nodes/${this.#node}/hardware`);
  }

}
/**
 * Class PVEHardwareNodeNodesPci
 */
class PVEHardwareNodeNodesPci {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }


  /**
   * Get ItemPciHardwareNodeNodesPciid
   * @param pciid
   * @returns {PVEItemPciHardwareNodeNodesPciid}
   */
  get(pciid) { return new PVEItemPciHardwareNodeNodesPciid(this.#client, this.#node, pciid); }

  /**
  * List local PCI devices.
  * @param {string} pci_class_blacklist A list of blacklisted PCI classes, which will not be returned. Following are filtered by default: Memory Controller (05), Bridge (06) and Processor (0b).
  * @param {bool} verbose If disabled, does only print the PCI IDs. Otherwise, additional information like vendor and device will be returned.
  * @returns {Result}
  */
  async pciscan(pci_class_blacklist, verbose) {
    const parameters = {
      'pci-class-blacklist': pci_class_blacklist,
      'verbose': verbose
    };
    return await this.#client.get(`/nodes/${this.#node}/hardware/pci`, parameters);
  }

}
/**
 * Class PVEItemPciHardwareNodeNodesPciid
 */
class PVEItemPciHardwareNodeNodesPciid {
  #node;
  #pciid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, pciid) {
    this.#client = client;
    this.#node = node;
    this.#pciid = pciid;
  }

  #mdev;
  /**
   * Get PciidPciHardwareNodeNodesMdev
   * @returns {PVEPciidPciHardwareNodeNodesMdev}
   */
  get mdev() { return this.#mdev == null ? (this.#mdev = new PVEPciidPciHardwareNodeNodesMdev(this.#client, this.#node, this.#pciid)) : this.#mdev; }


  /**
  * Index of available pci methods
  * @returns {Result}
  */
  async pciindex() {
    return await this.#client.get(`/nodes/${this.#node}/hardware/pci/${this.#pciid}`);
  }

}
/**
 * Class PVEPciidPciHardwareNodeNodesMdev
 */
class PVEPciidPciHardwareNodeNodesMdev {
  #node;
  #pciid;
  /** @type {PveClient} */
  #client;

  constructor(client, node, pciid) {
    this.#client = client;
    this.#node = node;
    this.#pciid = pciid;
  }



  /**
  * List mediated device types for given PCI device.
  * @returns {Result}
  */
  async mdevscan() {
    return await this.#client.get(`/nodes/${this.#node}/hardware/pci/${this.#pciid}/mdev`);
  }

}

/**
 * Class PVEHardwareNodeNodesUsb
 */
class PVEHardwareNodeNodesUsb {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * List local USB devices.
  * @returns {Result}
  */
  async usbscan() {
    return await this.#client.get(`/nodes/${this.#node}/hardware/usb`);
  }

}

/**
 * Class PVENodeNodesCapabilities
 */
class PVENodeNodesCapabilities {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }

  #qemu;
  /**
   * Get CapabilitiesNodeNodesQemu
   * @returns {PVECapabilitiesNodeNodesQemu}
   */
  get qemu() { return this.#qemu == null ? (this.#qemu = new PVECapabilitiesNodeNodesQemu(this.#client, this.#node)) : this.#qemu; }


  /**
  * Node capabilities index.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/nodes/${this.#node}/capabilities`);
  }

}
/**
 * Class PVECapabilitiesNodeNodesQemu
 */
class PVECapabilitiesNodeNodesQemu {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }

  #cpu;
  /**
   * Get QemuCapabilitiesNodeNodesCpu
   * @returns {PVEQemuCapabilitiesNodeNodesCpu}
   */
  get cpu() { return this.#cpu == null ? (this.#cpu = new PVEQemuCapabilitiesNodeNodesCpu(this.#client, this.#node)) : this.#cpu; }
  #machines;
  /**
   * Get QemuCapabilitiesNodeNodesMachines
   * @returns {PVEQemuCapabilitiesNodeNodesMachines}
   */
  get machines() { return this.#machines == null ? (this.#machines = new PVEQemuCapabilitiesNodeNodesMachines(this.#client, this.#node)) : this.#machines; }


  /**
  * QEMU capabilities index.
  * @returns {Result}
  */
  async qemuCapsIndex() {
    return await this.#client.get(`/nodes/${this.#node}/capabilities/qemu`);
  }

}
/**
 * Class PVEQemuCapabilitiesNodeNodesCpu
 */
class PVEQemuCapabilitiesNodeNodesCpu {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * List all custom and default CPU models.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/nodes/${this.#node}/capabilities/qemu/cpu`);
  }

}

/**
 * Class PVEQemuCapabilitiesNodeNodesMachines
 */
class PVEQemuCapabilitiesNodeNodesMachines {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Get available QEMU/KVM machine types.
  * @returns {Result}
  */
  async types() {
    return await this.#client.get(`/nodes/${this.#node}/capabilities/qemu/machines`);
  }

}

/**
 * Class PVENodeNodesStorage
 */
class PVENodeNodesStorage {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }


  /**
   * Get ItemStorageNodeNodesStorage
   * @param storage
   * @returns {PVEItemStorageNodeNodesStorage}
   */
  get(storage) { return new PVEItemStorageNodeNodesStorage(this.#client, this.#node, storage); }

  /**
  * Get status for all datastores.
  * @param {string} content Only list stores which support this content type.
  * @param {bool} enabled Only list stores which are enabled (not disabled in config).
  * @param {bool} format Include information about formats
  * @param {string} storage Only list status for  specified storage
  * @param {string} target If target is different to 'node', we only lists shared storages which content is accessible on this 'node' and the specified 'target' node.
  * @returns {Result}
  */
  async index(content, enabled, format, storage, target) {
    const parameters = {
      'content': content,
      'enabled': enabled,
      'format': format,
      'storage': storage,
      'target': target
    };
    return await this.#client.get(`/nodes/${this.#node}/storage`, parameters);
  }

}
/**
 * Class PVEItemStorageNodeNodesStorage
 */
class PVEItemStorageNodeNodesStorage {
  #node;
  #storage;
  /** @type {PveClient} */
  #client;

  constructor(client, node, storage) {
    this.#client = client;
    this.#node = node;
    this.#storage = storage;
  }

  #prunebackups;
  /**
   * Get StorageStorageNodeNodesPrunebackups
   * @returns {PVEStorageStorageNodeNodesPrunebackups}
   */
  get prunebackups() { return this.#prunebackups == null ? (this.#prunebackups = new PVEStorageStorageNodeNodesPrunebackups(this.#client, this.#node, this.#storage)) : this.#prunebackups; }
  #content;
  /**
   * Get StorageStorageNodeNodesContent
   * @returns {PVEStorageStorageNodeNodesContent}
   */
  get content() { return this.#content == null ? (this.#content = new PVEStorageStorageNodeNodesContent(this.#client, this.#node, this.#storage)) : this.#content; }
  #fileRestore;
  /**
   * Get StorageStorageNodeNodesFileRestore
   * @returns {PVEStorageStorageNodeNodesFileRestore}
   */
  get fileRestore() { return this.#fileRestore == null ? (this.#fileRestore = new PVEStorageStorageNodeNodesFileRestore(this.#client, this.#node, this.#storage)) : this.#fileRestore; }
  #status;
  /**
   * Get StorageStorageNodeNodesStatus
   * @returns {PVEStorageStorageNodeNodesStatus}
   */
  get status() { return this.#status == null ? (this.#status = new PVEStorageStorageNodeNodesStatus(this.#client, this.#node, this.#storage)) : this.#status; }
  #rrd;
  /**
   * Get StorageStorageNodeNodesRrd
   * @returns {PVEStorageStorageNodeNodesRrd}
   */
  get rrd() { return this.#rrd == null ? (this.#rrd = new PVEStorageStorageNodeNodesRrd(this.#client, this.#node, this.#storage)) : this.#rrd; }
  #rrddata;
  /**
   * Get StorageStorageNodeNodesRrddata
   * @returns {PVEStorageStorageNodeNodesRrddata}
   */
  get rrddata() { return this.#rrddata == null ? (this.#rrddata = new PVEStorageStorageNodeNodesRrddata(this.#client, this.#node, this.#storage)) : this.#rrddata; }
  #upload;
  /**
   * Get StorageStorageNodeNodesUpload
   * @returns {PVEStorageStorageNodeNodesUpload}
   */
  get upload() { return this.#upload == null ? (this.#upload = new PVEStorageStorageNodeNodesUpload(this.#client, this.#node, this.#storage)) : this.#upload; }
  #downloadUrl;
  /**
   * Get StorageStorageNodeNodesDownloadUrl
   * @returns {PVEStorageStorageNodeNodesDownloadUrl}
   */
  get downloadUrl() { return this.#downloadUrl == null ? (this.#downloadUrl = new PVEStorageStorageNodeNodesDownloadUrl(this.#client, this.#node, this.#storage)) : this.#downloadUrl; }


  /**
  *
  * @returns {Result}
  */
  async diridx() {
    return await this.#client.get(`/nodes/${this.#node}/storage/${this.#storage}`);
  }

}
/**
 * Class PVEStorageStorageNodeNodesPrunebackups
 */
class PVEStorageStorageNodeNodesPrunebackups {
  #node;
  #storage;
  /** @type {PveClient} */
  #client;

  constructor(client, node, storage) {
    this.#client = client;
    this.#node = node;
    this.#storage = storage;
  }



  /**
  * Prune backups. Only those using the standard naming scheme are considered.
  * @param {string} prune_backups Use these retention options instead of those from the storage configuration.
  * @param {string} type Either 'qemu' or 'lxc'. Only consider backups for guests of this type.
  *   Enum: qemu,lxc
  * @param {int} vmid Only prune backups for this VM.
  * @returns {Result}
  */
  async delete_(prune_backups, type, vmid) {
    const parameters = {
      'prune-backups': prune_backups,
      'type': type,
      'vmid': vmid
    };
    return await this.#client.delete(`/nodes/${this.#node}/storage/${this.#storage}/prunebackups`, parameters);
  }
  /**
  * Get prune information for backups. NOTE: this is only a preview and might not be what a subsequent prune call does if backups are removed/added in the meantime.
  * @param {string} prune_backups Use these retention options instead of those from the storage configuration.
  * @param {string} type Either 'qemu' or 'lxc'. Only consider backups for guests of this type.
  *   Enum: qemu,lxc
  * @param {int} vmid Only consider backups for this guest.
  * @returns {Result}
  */
  async dryrun(prune_backups, type, vmid) {
    const parameters = {
      'prune-backups': prune_backups,
      'type': type,
      'vmid': vmid
    };
    return await this.#client.get(`/nodes/${this.#node}/storage/${this.#storage}/prunebackups`, parameters);
  }

}

/**
 * Class PVEStorageStorageNodeNodesContent
 */
class PVEStorageStorageNodeNodesContent {
  #node;
  #storage;
  /** @type {PveClient} */
  #client;

  constructor(client, node, storage) {
    this.#client = client;
    this.#node = node;
    this.#storage = storage;
  }


  /**
   * Get ItemContentStorageStorageNodeNodesVolume
   * @param volume
   * @returns {PVEItemContentStorageStorageNodeNodesVolume}
   */
  get(volume) { return new PVEItemContentStorageStorageNodeNodesVolume(this.#client, this.#node, this.#storage, volume); }

  /**
  * List storage content.
  * @param {string} content Only list content of this type.
  * @param {int} vmid Only list images for this VM
  * @returns {Result}
  */
  async index(content, vmid) {
    const parameters = {
      'content': content,
      'vmid': vmid
    };
    return await this.#client.get(`/nodes/${this.#node}/storage/${this.#storage}/content`, parameters);
  }
  /**
  * Allocate disk images.
  * @param {string} filename The name of the file to create.
  * @param {string} size Size in kilobyte (1024 bytes). Optional suffixes 'M' (megabyte, 1024K) and 'G' (gigabyte, 1024M)
  * @param {int} vmid Specify owner VM
  * @param {string} format
  *   Enum: raw,qcow2,subvol
  * @returns {Result}
  */
  async create(filename, size, vmid, format) {
    const parameters = {
      'filename': filename,
      'size': size,
      'vmid': vmid,
      'format': format
    };
    return await this.#client.create(`/nodes/${this.#node}/storage/${this.#storage}/content`, parameters);
  }

}
/**
 * Class PVEItemContentStorageStorageNodeNodesVolume
 */
class PVEItemContentStorageStorageNodeNodesVolume {
  #node;
  #storage;
  #volume;
  /** @type {PveClient} */
  #client;

  constructor(client, node, storage, volume) {
    this.#client = client;
    this.#node = node;
    this.#storage = storage;
    this.#volume = volume;
  }



  /**
  * Delete volume
  * @param {int} delay Time to wait for the task to finish. We return 'null' if the task finish within that time.
  * @returns {Result}
  */
  async delete_(delay) {
    const parameters = { 'delay': delay };
    return await this.#client.delete(`/nodes/${this.#node}/storage/${this.#storage}/content/${this.#volume}`, parameters);
  }
  /**
  * Get volume attributes
  * @returns {Result}
  */
  async info() {
    return await this.#client.get(`/nodes/${this.#node}/storage/${this.#storage}/content/${this.#volume}`);
  }
  /**
  * Copy a volume. This is experimental code - do not use.
  * @param {string} target Target volume identifier
  * @param {string} target_node Target node. Default is local node.
  * @returns {Result}
  */
  async copy(target, target_node) {
    const parameters = {
      'target': target,
      'target_node': target_node
    };
    return await this.#client.create(`/nodes/${this.#node}/storage/${this.#storage}/content/${this.#volume}`, parameters);
  }
  /**
  * Update volume attributes
  * @param {string} notes The new notes.
  * @param {bool} protected_ Protection status. Currently only supported for backups.
  * @returns {Result}
  */
  async updateattributes(notes, protected_) {
    const parameters = {
      'notes': notes,
      'protected': protected_
    };
    return await this.#client.set(`/nodes/${this.#node}/storage/${this.#storage}/content/${this.#volume}`, parameters);
  }

}

/**
 * Class PVEStorageStorageNodeNodesFileRestore
 */
class PVEStorageStorageNodeNodesFileRestore {
  #node;
  #storage;
  /** @type {PveClient} */
  #client;

  constructor(client, node, storage) {
    this.#client = client;
    this.#node = node;
    this.#storage = storage;
  }

  #list;
  /**
   * Get FileRestoreStorageStorageNodeNodesList
   * @returns {PVEFileRestoreStorageStorageNodeNodesList}
   */
  get list() { return this.#list == null ? (this.#list = new PVEFileRestoreStorageStorageNodeNodesList(this.#client, this.#node, this.#storage)) : this.#list; }
  #download;
  /**
   * Get FileRestoreStorageStorageNodeNodesDownload
   * @returns {PVEFileRestoreStorageStorageNodeNodesDownload}
   */
  get download() { return this.#download == null ? (this.#download = new PVEFileRestoreStorageStorageNodeNodesDownload(this.#client, this.#node, this.#storage)) : this.#download; }



}
/**
 * Class PVEFileRestoreStorageStorageNodeNodesList
 */
class PVEFileRestoreStorageStorageNodeNodesList {
  #node;
  #storage;
  /** @type {PveClient} */
  #client;

  constructor(client, node, storage) {
    this.#client = client;
    this.#node = node;
    this.#storage = storage;
  }



  /**
  * List files and directories for single file restore under the given path.
  * @param {string} filepath base64-path to the directory or file being listed, or "/".
  * @param {string} volume Backup volume ID or name. Currently only PBS snapshots are supported.
  * @returns {Result}
  */
  async list(filepath, volume) {
    const parameters = {
      'filepath': filepath,
      'volume': volume
    };
    return await this.#client.get(`/nodes/${this.#node}/storage/${this.#storage}/file-restore/list`, parameters);
  }

}

/**
 * Class PVEFileRestoreStorageStorageNodeNodesDownload
 */
class PVEFileRestoreStorageStorageNodeNodesDownload {
  #node;
  #storage;
  /** @type {PveClient} */
  #client;

  constructor(client, node, storage) {
    this.#client = client;
    this.#node = node;
    this.#storage = storage;
  }



  /**
  * Extract a file or directory (as zip archive) from a PBS backup.
  * @param {string} filepath base64-path to the directory or file to download.
  * @param {string} volume Backup volume ID or name. Currently only PBS snapshots are supported.
  * @returns {Result}
  */
  async download(filepath, volume) {
    const parameters = {
      'filepath': filepath,
      'volume': volume
    };
    return await this.#client.get(`/nodes/${this.#node}/storage/${this.#storage}/file-restore/download`, parameters);
  }

}

/**
 * Class PVEStorageStorageNodeNodesStatus
 */
class PVEStorageStorageNodeNodesStatus {
  #node;
  #storage;
  /** @type {PveClient} */
  #client;

  constructor(client, node, storage) {
    this.#client = client;
    this.#node = node;
    this.#storage = storage;
  }



  /**
  * Read storage status.
  * @returns {Result}
  */
  async readStatus() {
    return await this.#client.get(`/nodes/${this.#node}/storage/${this.#storage}/status`);
  }

}

/**
 * Class PVEStorageStorageNodeNodesRrd
 */
class PVEStorageStorageNodeNodesRrd {
  #node;
  #storage;
  /** @type {PveClient} */
  #client;

  constructor(client, node, storage) {
    this.#client = client;
    this.#node = node;
    this.#storage = storage;
  }



  /**
  * Read storage RRD statistics (returns PNG).
  * @param {string} ds The list of datasources you want to display.
  * @param {string} timeframe Specify the time frame you are interested in.
  *   Enum: hour,day,week,month,year
  * @param {string} cf The RRD consolidation function
  *   Enum: AVERAGE,MAX
  * @returns {Result}
  */
  async rrd(ds, timeframe, cf) {
    const parameters = {
      'ds': ds,
      'timeframe': timeframe,
      'cf': cf
    };
    return await this.#client.get(`/nodes/${this.#node}/storage/${this.#storage}/rrd`, parameters);
  }

}

/**
 * Class PVEStorageStorageNodeNodesRrddata
 */
class PVEStorageStorageNodeNodesRrddata {
  #node;
  #storage;
  /** @type {PveClient} */
  #client;

  constructor(client, node, storage) {
    this.#client = client;
    this.#node = node;
    this.#storage = storage;
  }



  /**
  * Read storage RRD statistics.
  * @param {string} timeframe Specify the time frame you are interested in.
  *   Enum: hour,day,week,month,year
  * @param {string} cf The RRD consolidation function
  *   Enum: AVERAGE,MAX
  * @returns {Result}
  */
  async rrddata(timeframe, cf) {
    const parameters = {
      'timeframe': timeframe,
      'cf': cf
    };
    return await this.#client.get(`/nodes/${this.#node}/storage/${this.#storage}/rrddata`, parameters);
  }

}

/**
 * Class PVEStorageStorageNodeNodesUpload
 */
class PVEStorageStorageNodeNodesUpload {
  #node;
  #storage;
  /** @type {PveClient} */
  #client;

  constructor(client, node, storage) {
    this.#client = client;
    this.#node = node;
    this.#storage = storage;
  }



  /**
  * Upload templates and ISO images.
  * @param {string} content Content type.
  *   Enum: iso,vztmpl
  * @param {string} filename The name of the file to create. Caution: This will be normalized!
  * @param {string} checksum The expected checksum of the file.
  * @param {string} checksum_algorithm The algorithm to calculate the checksum of the file.
  *   Enum: md5,sha1,sha224,sha256,sha384,sha512
  * @param {string} tmpfilename The source file name. This parameter is usually set by the REST handler. You can only overwrite it when connecting to the trusted port on localhost.
  * @returns {Result}
  */
  async upload(content, filename, checksum, checksum_algorithm, tmpfilename) {
    const parameters = {
      'content': content,
      'filename': filename,
      'checksum': checksum,
      'checksum-algorithm': checksum_algorithm,
      'tmpfilename': tmpfilename
    };
    return await this.#client.create(`/nodes/${this.#node}/storage/${this.#storage}/upload`, parameters);
  }

}

/**
 * Class PVEStorageStorageNodeNodesDownloadUrl
 */
class PVEStorageStorageNodeNodesDownloadUrl {
  #node;
  #storage;
  /** @type {PveClient} */
  #client;

  constructor(client, node, storage) {
    this.#client = client;
    this.#node = node;
    this.#storage = storage;
  }



  /**
  * Download templates and ISO images by using an URL.
  * @param {string} content Content type.
  *   Enum: iso,vztmpl
  * @param {string} filename The name of the file to create. Caution: This will be normalized!
  * @param {string} url The URL to download the file from.
  * @param {string} checksum The expected checksum of the file.
  * @param {string} checksum_algorithm The algorithm to calculate the checksum of the file.
  *   Enum: md5,sha1,sha224,sha256,sha384,sha512
  * @param {bool} verify_certificates If false, no SSL/TLS certificates will be verified.
  * @returns {Result}
  */
  async downloadUrl(content, filename, url, checksum, checksum_algorithm, verify_certificates) {
    const parameters = {
      'content': content,
      'filename': filename,
      'url': url,
      'checksum': checksum,
      'checksum-algorithm': checksum_algorithm,
      'verify-certificates': verify_certificates
    };
    return await this.#client.create(`/nodes/${this.#node}/storage/${this.#storage}/download-url`, parameters);
  }

}

/**
 * Class PVENodeNodesDisks
 */
class PVENodeNodesDisks {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }

  #lvm;
  /**
   * Get DisksNodeNodesLvm
   * @returns {PVEDisksNodeNodesLvm}
   */
  get lvm() { return this.#lvm == null ? (this.#lvm = new PVEDisksNodeNodesLvm(this.#client, this.#node)) : this.#lvm; }
  #lvmthin;
  /**
   * Get DisksNodeNodesLvmthin
   * @returns {PVEDisksNodeNodesLvmthin}
   */
  get lvmthin() { return this.#lvmthin == null ? (this.#lvmthin = new PVEDisksNodeNodesLvmthin(this.#client, this.#node)) : this.#lvmthin; }
  #directory;
  /**
   * Get DisksNodeNodesDirectory
   * @returns {PVEDisksNodeNodesDirectory}
   */
  get directory() { return this.#directory == null ? (this.#directory = new PVEDisksNodeNodesDirectory(this.#client, this.#node)) : this.#directory; }
  #zfs;
  /**
   * Get DisksNodeNodesZfs
   * @returns {PVEDisksNodeNodesZfs}
   */
  get zfs() { return this.#zfs == null ? (this.#zfs = new PVEDisksNodeNodesZfs(this.#client, this.#node)) : this.#zfs; }
  #list;
  /**
   * Get DisksNodeNodesList
   * @returns {PVEDisksNodeNodesList}
   */
  get list() { return this.#list == null ? (this.#list = new PVEDisksNodeNodesList(this.#client, this.#node)) : this.#list; }
  #smart;
  /**
   * Get DisksNodeNodesSmart
   * @returns {PVEDisksNodeNodesSmart}
   */
  get smart() { return this.#smart == null ? (this.#smart = new PVEDisksNodeNodesSmart(this.#client, this.#node)) : this.#smart; }
  #initgpt;
  /**
   * Get DisksNodeNodesInitgpt
   * @returns {PVEDisksNodeNodesInitgpt}
   */
  get initgpt() { return this.#initgpt == null ? (this.#initgpt = new PVEDisksNodeNodesInitgpt(this.#client, this.#node)) : this.#initgpt; }
  #wipedisk;
  /**
   * Get DisksNodeNodesWipedisk
   * @returns {PVEDisksNodeNodesWipedisk}
   */
  get wipedisk() { return this.#wipedisk == null ? (this.#wipedisk = new PVEDisksNodeNodesWipedisk(this.#client, this.#node)) : this.#wipedisk; }


  /**
  * Node index.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/nodes/${this.#node}/disks`);
  }

}
/**
 * Class PVEDisksNodeNodesLvm
 */
class PVEDisksNodeNodesLvm {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }


  /**
   * Get ItemLvmDisksNodeNodesName
   * @param name
   * @returns {PVEItemLvmDisksNodeNodesName}
   */
  get(name) { return new PVEItemLvmDisksNodeNodesName(this.#client, this.#node, name); }

  /**
  * List LVM Volume Groups
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/nodes/${this.#node}/disks/lvm`);
  }
  /**
  * Create an LVM Volume Group
  * @param {string} device The block device you want to create the volume group on
  * @param {string} name The storage identifier.
  * @param {bool} add_storage Configure storage using the Volume Group
  * @returns {Result}
  */
  async create(device, name, add_storage) {
    const parameters = {
      'device': device,
      'name': name,
      'add_storage': add_storage
    };
    return await this.#client.create(`/nodes/${this.#node}/disks/lvm`, parameters);
  }

}
/**
 * Class PVEItemLvmDisksNodeNodesName
 */
class PVEItemLvmDisksNodeNodesName {
  #node;
  #name;
  /** @type {PveClient} */
  #client;

  constructor(client, node, name) {
    this.#client = client;
    this.#node = node;
    this.#name = name;
  }



  /**
  * Remove an LVM Volume Group.
  * @param {bool} cleanup_config Marks associated storage(s) as not available on this node anymore or removes them from the configuration (if configured for this node only).
  * @param {bool} cleanup_disks Also wipe disks so they can be repurposed afterwards.
  * @returns {Result}
  */
  async delete_(cleanup_config, cleanup_disks) {
    const parameters = {
      'cleanup-config': cleanup_config,
      'cleanup-disks': cleanup_disks
    };
    return await this.#client.delete(`/nodes/${this.#node}/disks/lvm/${this.#name}`, parameters);
  }

}

/**
 * Class PVEDisksNodeNodesLvmthin
 */
class PVEDisksNodeNodesLvmthin {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }


  /**
   * Get ItemLvmthinDisksNodeNodesName
   * @param name
   * @returns {PVEItemLvmthinDisksNodeNodesName}
   */
  get(name) { return new PVEItemLvmthinDisksNodeNodesName(this.#client, this.#node, name); }

  /**
  * List LVM thinpools
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/nodes/${this.#node}/disks/lvmthin`);
  }
  /**
  * Create an LVM thinpool
  * @param {string} device The block device you want to create the thinpool on.
  * @param {string} name The storage identifier.
  * @param {bool} add_storage Configure storage using the thinpool.
  * @returns {Result}
  */
  async create(device, name, add_storage) {
    const parameters = {
      'device': device,
      'name': name,
      'add_storage': add_storage
    };
    return await this.#client.create(`/nodes/${this.#node}/disks/lvmthin`, parameters);
  }

}
/**
 * Class PVEItemLvmthinDisksNodeNodesName
 */
class PVEItemLvmthinDisksNodeNodesName {
  #node;
  #name;
  /** @type {PveClient} */
  #client;

  constructor(client, node, name) {
    this.#client = client;
    this.#node = node;
    this.#name = name;
  }



  /**
  * Remove an LVM thin pool.
  * @param {string} volume_group The storage identifier.
  * @param {bool} cleanup_config Marks associated storage(s) as not available on this node anymore or removes them from the configuration (if configured for this node only).
  * @param {bool} cleanup_disks Also wipe disks so they can be repurposed afterwards.
  * @returns {Result}
  */
  async delete_(volume_group, cleanup_config, cleanup_disks) {
    const parameters = {
      'volume-group': volume_group,
      'cleanup-config': cleanup_config,
      'cleanup-disks': cleanup_disks
    };
    return await this.#client.delete(`/nodes/${this.#node}/disks/lvmthin/${this.#name}`, parameters);
  }

}

/**
 * Class PVEDisksNodeNodesDirectory
 */
class PVEDisksNodeNodesDirectory {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }


  /**
   * Get ItemDirectoryDisksNodeNodesName
   * @param name
   * @returns {PVEItemDirectoryDisksNodeNodesName}
   */
  get(name) { return new PVEItemDirectoryDisksNodeNodesName(this.#client, this.#node, name); }

  /**
  * PVE Managed Directory storages.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/nodes/${this.#node}/disks/directory`);
  }
  /**
  * Create a Filesystem on an unused disk. Will be mounted under '/mnt/pve/NAME'.
  * @param {string} device The block device you want to create the filesystem on.
  * @param {string} name The storage identifier.
  * @param {bool} add_storage Configure storage using the directory.
  * @param {string} filesystem The desired filesystem.
  *   Enum: ext4,xfs
  * @returns {Result}
  */
  async create(device, name, add_storage, filesystem) {
    const parameters = {
      'device': device,
      'name': name,
      'add_storage': add_storage,
      'filesystem': filesystem
    };
    return await this.#client.create(`/nodes/${this.#node}/disks/directory`, parameters);
  }

}
/**
 * Class PVEItemDirectoryDisksNodeNodesName
 */
class PVEItemDirectoryDisksNodeNodesName {
  #node;
  #name;
  /** @type {PveClient} */
  #client;

  constructor(client, node, name) {
    this.#client = client;
    this.#node = node;
    this.#name = name;
  }



  /**
  * Unmounts the storage and removes the mount unit.
  * @param {bool} cleanup_config Marks associated storage(s) as not available on this node anymore or removes them from the configuration (if configured for this node only).
  * @param {bool} cleanup_disks Also wipe disk so it can be repurposed afterwards.
  * @returns {Result}
  */
  async delete_(cleanup_config, cleanup_disks) {
    const parameters = {
      'cleanup-config': cleanup_config,
      'cleanup-disks': cleanup_disks
    };
    return await this.#client.delete(`/nodes/${this.#node}/disks/directory/${this.#name}`, parameters);
  }

}

/**
 * Class PVEDisksNodeNodesZfs
 */
class PVEDisksNodeNodesZfs {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }


  /**
   * Get ItemZfsDisksNodeNodesName
   * @param name
   * @returns {PVEItemZfsDisksNodeNodesName}
   */
  get(name) { return new PVEItemZfsDisksNodeNodesName(this.#client, this.#node, name); }

  /**
  * List Zpools.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/nodes/${this.#node}/disks/zfs`);
  }
  /**
  * Create a ZFS pool.
  * @param {string} devices The block devices you want to create the zpool on.
  * @param {string} name The storage identifier.
  * @param {string} raidlevel The RAID level to use.
  *   Enum: single,mirror,raid10,raidz,raidz2,raidz3
  * @param {bool} add_storage Configure storage using the zpool.
  * @param {int} ashift Pool sector size exponent.
  * @param {string} compression The compression algorithm to use.
  *   Enum: on,off,gzip,lz4,lzjb,zle,zstd
  * @returns {Result}
  */
  async create(devices, name, raidlevel, add_storage, ashift, compression) {
    const parameters = {
      'devices': devices,
      'name': name,
      'raidlevel': raidlevel,
      'add_storage': add_storage,
      'ashift': ashift,
      'compression': compression
    };
    return await this.#client.create(`/nodes/${this.#node}/disks/zfs`, parameters);
  }

}
/**
 * Class PVEItemZfsDisksNodeNodesName
 */
class PVEItemZfsDisksNodeNodesName {
  #node;
  #name;
  /** @type {PveClient} */
  #client;

  constructor(client, node, name) {
    this.#client = client;
    this.#node = node;
    this.#name = name;
  }



  /**
  * Destroy a ZFS pool.
  * @param {bool} cleanup_config Marks associated storage(s) as not available on this node anymore or removes them from the configuration (if configured for this node only).
  * @param {bool} cleanup_disks Also wipe disks so they can be repurposed afterwards.
  * @returns {Result}
  */
  async delete_(cleanup_config, cleanup_disks) {
    const parameters = {
      'cleanup-config': cleanup_config,
      'cleanup-disks': cleanup_disks
    };
    return await this.#client.delete(`/nodes/${this.#node}/disks/zfs/${this.#name}`, parameters);
  }
  /**
  * Get details about a zpool.
  * @returns {Result}
  */
  async detail() {
    return await this.#client.get(`/nodes/${this.#node}/disks/zfs/${this.#name}`);
  }

}

/**
 * Class PVEDisksNodeNodesList
 */
class PVEDisksNodeNodesList {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * List local disks.
  * @param {bool} include_partitions Also include partitions.
  * @param {bool} skipsmart Skip smart checks.
  * @param {string} type Only list specific types of disks.
  *   Enum: unused,journal_disks
  * @returns {Result}
  */
  async list(include_partitions, skipsmart, type) {
    const parameters = {
      'include-partitions': include_partitions,
      'skipsmart': skipsmart,
      'type': type
    };
    return await this.#client.get(`/nodes/${this.#node}/disks/list`, parameters);
  }

}

/**
 * Class PVEDisksNodeNodesSmart
 */
class PVEDisksNodeNodesSmart {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Get SMART Health of a disk.
  * @param {string} disk Block device name
  * @param {bool} healthonly If true returns only the health status
  * @returns {Result}
  */
  async smart(disk, healthonly) {
    const parameters = {
      'disk': disk,
      'healthonly': healthonly
    };
    return await this.#client.get(`/nodes/${this.#node}/disks/smart`, parameters);
  }

}

/**
 * Class PVEDisksNodeNodesInitgpt
 */
class PVEDisksNodeNodesInitgpt {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Initialize Disk with GPT
  * @param {string} disk Block device name
  * @param {string} uuid UUID for the GPT table
  * @returns {Result}
  */
  async initgpt(disk, uuid) {
    const parameters = {
      'disk': disk,
      'uuid': uuid
    };
    return await this.#client.create(`/nodes/${this.#node}/disks/initgpt`, parameters);
  }

}

/**
 * Class PVEDisksNodeNodesWipedisk
 */
class PVEDisksNodeNodesWipedisk {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Wipe a disk or partition.
  * @param {string} disk Block device name
  * @returns {Result}
  */
  async wipeDisk(disk) {
    const parameters = { 'disk': disk };
    return await this.#client.set(`/nodes/${this.#node}/disks/wipedisk`, parameters);
  }

}

/**
 * Class PVENodeNodesApt
 */
class PVENodeNodesApt {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }

  #update;
  /**
   * Get AptNodeNodesUpdate
   * @returns {PVEAptNodeNodesUpdate}
   */
  get update() { return this.#update == null ? (this.#update = new PVEAptNodeNodesUpdate(this.#client, this.#node)) : this.#update; }
  #changelog;
  /**
   * Get AptNodeNodesChangelog
   * @returns {PVEAptNodeNodesChangelog}
   */
  get changelog() { return this.#changelog == null ? (this.#changelog = new PVEAptNodeNodesChangelog(this.#client, this.#node)) : this.#changelog; }
  #repositories;
  /**
   * Get AptNodeNodesRepositories
   * @returns {PVEAptNodeNodesRepositories}
   */
  get repositories() { return this.#repositories == null ? (this.#repositories = new PVEAptNodeNodesRepositories(this.#client, this.#node)) : this.#repositories; }
  #versions;
  /**
   * Get AptNodeNodesVersions
   * @returns {PVEAptNodeNodesVersions}
   */
  get versions() { return this.#versions == null ? (this.#versions = new PVEAptNodeNodesVersions(this.#client, this.#node)) : this.#versions; }


  /**
  * Directory index for apt (Advanced Package Tool).
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/nodes/${this.#node}/apt`);
  }

}
/**
 * Class PVEAptNodeNodesUpdate
 */
class PVEAptNodeNodesUpdate {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * List available updates.
  * @returns {Result}
  */
  async listUpdates() {
    return await this.#client.get(`/nodes/${this.#node}/apt/update`);
  }
  /**
  * This is used to resynchronize the package index files from their sources (apt-get update).
  * @param {bool} notify Send notification mail about new packages (to email address specified for user 'root@pam').
  * @param {bool} quiet Only produces output suitable for logging, omitting progress indicators.
  * @returns {Result}
  */
  async updateDatabase(notify, quiet) {
    const parameters = {
      'notify': notify,
      'quiet': quiet
    };
    return await this.#client.create(`/nodes/${this.#node}/apt/update`, parameters);
  }

}

/**
 * Class PVEAptNodeNodesChangelog
 */
class PVEAptNodeNodesChangelog {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Get package changelogs.
  * @param {string} name Package name.
  * @param {string} version Package version.
  * @returns {Result}
  */
  async changelog(name, version) {
    const parameters = {
      'name': name,
      'version': version
    };
    return await this.#client.get(`/nodes/${this.#node}/apt/changelog`, parameters);
  }

}

/**
 * Class PVEAptNodeNodesRepositories
 */
class PVEAptNodeNodesRepositories {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Get APT repository information.
  * @returns {Result}
  */
  async repositories() {
    return await this.#client.get(`/nodes/${this.#node}/apt/repositories`);
  }
  /**
  * Change the properties of a repository. Currently only allows enabling/disabling.
  * @param {int} index Index within the file (starting from 0).
  * @param {string} path Path to the containing file.
  * @param {string} digest Digest to detect modifications.
  * @param {bool} enabled Whether the repository should be enabled or not.
  * @returns {Result}
  */
  async changeRepository(index, path, digest, enabled) {
    const parameters = {
      'index': index,
      'path': path,
      'digest': digest,
      'enabled': enabled
    };
    return await this.#client.create(`/nodes/${this.#node}/apt/repositories`, parameters);
  }
  /**
  * Add a standard repository to the configuration
  * @param {string} handle Handle that identifies a repository.
  * @param {string} digest Digest to detect modifications.
  * @returns {Result}
  */
  async addRepository(handle, digest) {
    const parameters = {
      'handle': handle,
      'digest': digest
    };
    return await this.#client.set(`/nodes/${this.#node}/apt/repositories`, parameters);
  }

}

/**
 * Class PVEAptNodeNodesVersions
 */
class PVEAptNodeNodesVersions {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Get package information for important Proxmox packages.
  * @returns {Result}
  */
  async versions() {
    return await this.#client.get(`/nodes/${this.#node}/apt/versions`);
  }

}

/**
 * Class PVENodeNodesFirewall
 */
class PVENodeNodesFirewall {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }

  #rules;
  /**
   * Get FirewallNodeNodesRules
   * @returns {PVEFirewallNodeNodesRules}
   */
  get rules() { return this.#rules == null ? (this.#rules = new PVEFirewallNodeNodesRules(this.#client, this.#node)) : this.#rules; }
  #options;
  /**
   * Get FirewallNodeNodesOptions
   * @returns {PVEFirewallNodeNodesOptions}
   */
  get options() { return this.#options == null ? (this.#options = new PVEFirewallNodeNodesOptions(this.#client, this.#node)) : this.#options; }
  #log;
  /**
   * Get FirewallNodeNodesLog
   * @returns {PVEFirewallNodeNodesLog}
   */
  get log() { return this.#log == null ? (this.#log = new PVEFirewallNodeNodesLog(this.#client, this.#node)) : this.#log; }


  /**
  * Directory index.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/nodes/${this.#node}/firewall`);
  }

}
/**
 * Class PVEFirewallNodeNodesRules
 */
class PVEFirewallNodeNodesRules {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }


  /**
   * Get ItemRulesFirewallNodeNodesPos
   * @param pos
   * @returns {PVEItemRulesFirewallNodeNodesPos}
   */
  get(pos) { return new PVEItemRulesFirewallNodeNodesPos(this.#client, this.#node, pos); }

  /**
  * List rules.
  * @returns {Result}
  */
  async getRules() {
    return await this.#client.get(`/nodes/${this.#node}/firewall/rules`);
  }
  /**
  * Create new rule.
  * @param {string} action Rule action ('ACCEPT', 'DROP', 'REJECT') or security group name.
  * @param {string} type Rule type.
  *   Enum: in,out,group
  * @param {string} comment Descriptive comment.
  * @param {string} dest Restrict packet destination address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {string} dport Restrict TCP/UDP destination port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
  * @param {int} enable Flag to enable/disable a rule.
  * @param {string} icmp_type Specify icmp-type. Only valid if proto equals 'icmp'.
  * @param {string} iface Network interface name. You have to use network configuration key names for VMs and containers ('net\d+'). Host related rules can use arbitrary strings.
  * @param {string} log Log level for firewall rule.
  *   Enum: emerg,alert,crit,err,warning,notice,info,debug,nolog
  * @param {string} macro Use predefined standard macro.
  * @param {int} pos Update rule at position &amp;lt;pos&amp;gt;.
  * @param {string} proto IP protocol. You can use protocol names ('tcp'/'udp') or simple numbers, as defined in '/etc/protocols'.
  * @param {string} source Restrict packet source address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
  * @param {string} sport Restrict TCP/UDP source port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
  * @returns {Result}
  */
  async createRule(action, type, comment, dest, digest, dport, enable, icmp_type, iface, log, macro, pos, proto, source, sport) {
    const parameters = {
      'action': action,
      'type': type,
      'comment': comment,
      'dest': dest,
      'digest': digest,
      'dport': dport,
      'enable': enable,
      'icmp-type': icmp_type,
      'iface': iface,
      'log': log,
      'macro': macro,
      'pos': pos,
      'proto': proto,
      'source': source,
      'sport': sport
    };
    return await this.#client.create(`/nodes/${this.#node}/firewall/rules`, parameters);
  }

}
/**
 * Class PVEItemRulesFirewallNodeNodesPos
 */
class PVEItemRulesFirewallNodeNodesPos {
  #node;
  #pos;
  /** @type {PveClient} */
  #client;

  constructor(client, node, pos) {
    this.#client = client;
    this.#node = node;
    this.#pos = pos;
  }



  /**
  * Delete rule.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @returns {Result}
  */
  async deleteRule(digest) {
    const parameters = { 'digest': digest };
    return await this.#client.delete(`/nodes/${this.#node}/firewall/rules/${this.#pos}`, parameters);
  }
  /**
  * Get single rule data.
  * @returns {Result}
  */
  async getRule() {
    return await this.#client.get(`/nodes/${this.#node}/firewall/rules/${this.#pos}`);
  }
  /**
  * Modify rule data.
  * @param {string} action Rule action ('ACCEPT', 'DROP', 'REJECT') or security group name.
  * @param {string} comment Descriptive comment.
  * @param {string} delete_ A list of settings you want to delete.
  * @param {string} dest Restrict packet destination address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {string} dport Restrict TCP/UDP destination port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
  * @param {int} enable Flag to enable/disable a rule.
  * @param {string} icmp_type Specify icmp-type. Only valid if proto equals 'icmp'.
  * @param {string} iface Network interface name. You have to use network configuration key names for VMs and containers ('net\d+'). Host related rules can use arbitrary strings.
  * @param {string} log Log level for firewall rule.
  *   Enum: emerg,alert,crit,err,warning,notice,info,debug,nolog
  * @param {string} macro Use predefined standard macro.
  * @param {int} moveto Move rule to new position &amp;lt;moveto&amp;gt;. Other arguments are ignored.
  * @param {string} proto IP protocol. You can use protocol names ('tcp'/'udp') or simple numbers, as defined in '/etc/protocols'.
  * @param {string} source Restrict packet source address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
  * @param {string} sport Restrict TCP/UDP source port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
  * @param {string} type Rule type.
  *   Enum: in,out,group
  * @returns {Result}
  */
  async updateRule(action, comment, delete_, dest, digest, dport, enable, icmp_type, iface, log, macro, moveto, proto, source, sport, type) {
    const parameters = {
      'action': action,
      'comment': comment,
      'delete': delete_,
      'dest': dest,
      'digest': digest,
      'dport': dport,
      'enable': enable,
      'icmp-type': icmp_type,
      'iface': iface,
      'log': log,
      'macro': macro,
      'moveto': moveto,
      'proto': proto,
      'source': source,
      'sport': sport,
      'type': type
    };
    return await this.#client.set(`/nodes/${this.#node}/firewall/rules/${this.#pos}`, parameters);
  }

}

/**
 * Class PVEFirewallNodeNodesOptions
 */
class PVEFirewallNodeNodesOptions {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Get host firewall options.
  * @returns {Result}
  */
  async getOptions() {
    return await this.#client.get(`/nodes/${this.#node}/firewall/options`);
  }
  /**
  * Set Firewall options.
  * @param {string} delete_ A list of settings you want to delete.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {bool} enable Enable host firewall rules.
  * @param {string} log_level_in Log level for incoming traffic.
  *   Enum: emerg,alert,crit,err,warning,notice,info,debug,nolog
  * @param {string} log_level_out Log level for outgoing traffic.
  *   Enum: emerg,alert,crit,err,warning,notice,info,debug,nolog
  * @param {bool} log_nf_conntrack Enable logging of conntrack information.
  * @param {bool} ndp Enable NDP (Neighbor Discovery Protocol).
  * @param {bool} nf_conntrack_allow_invalid Allow invalid packets on connection tracking.
  * @param {int} nf_conntrack_max Maximum number of tracked connections.
  * @param {int} nf_conntrack_tcp_timeout_established Conntrack established timeout.
  * @param {int} nf_conntrack_tcp_timeout_syn_recv Conntrack syn recv timeout.
  * @param {bool} nosmurfs Enable SMURFS filter.
  * @param {bool} protection_synflood Enable synflood protection
  * @param {int} protection_synflood_burst Synflood protection rate burst by ip src.
  * @param {int} protection_synflood_rate Synflood protection rate syn/sec by ip src.
  * @param {string} smurf_log_level Log level for SMURFS filter.
  *   Enum: emerg,alert,crit,err,warning,notice,info,debug,nolog
  * @param {string} tcp_flags_log_level Log level for illegal tcp flags filter.
  *   Enum: emerg,alert,crit,err,warning,notice,info,debug,nolog
  * @param {bool} tcpflags Filter illegal combinations of TCP flags.
  * @returns {Result}
  */
  async setOptions(delete_, digest, enable, log_level_in, log_level_out, log_nf_conntrack, ndp, nf_conntrack_allow_invalid, nf_conntrack_max, nf_conntrack_tcp_timeout_established, nf_conntrack_tcp_timeout_syn_recv, nosmurfs, protection_synflood, protection_synflood_burst, protection_synflood_rate, smurf_log_level, tcp_flags_log_level, tcpflags) {
    const parameters = {
      'delete': delete_,
      'digest': digest,
      'enable': enable,
      'log_level_in': log_level_in,
      'log_level_out': log_level_out,
      'log_nf_conntrack': log_nf_conntrack,
      'ndp': ndp,
      'nf_conntrack_allow_invalid': nf_conntrack_allow_invalid,
      'nf_conntrack_max': nf_conntrack_max,
      'nf_conntrack_tcp_timeout_established': nf_conntrack_tcp_timeout_established,
      'nf_conntrack_tcp_timeout_syn_recv': nf_conntrack_tcp_timeout_syn_recv,
      'nosmurfs': nosmurfs,
      'protection_synflood': protection_synflood,
      'protection_synflood_burst': protection_synflood_burst,
      'protection_synflood_rate': protection_synflood_rate,
      'smurf_log_level': smurf_log_level,
      'tcp_flags_log_level': tcp_flags_log_level,
      'tcpflags': tcpflags
    };
    return await this.#client.set(`/nodes/${this.#node}/firewall/options`, parameters);
  }

}

/**
 * Class PVEFirewallNodeNodesLog
 */
class PVEFirewallNodeNodesLog {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Read firewall log
  * @param {int} limit
  * @param {int} start
  * @returns {Result}
  */
  async log(limit, start) {
    const parameters = {
      'limit': limit,
      'start': start
    };
    return await this.#client.get(`/nodes/${this.#node}/firewall/log`, parameters);
  }

}

/**
 * Class PVENodeNodesReplication
 */
class PVENodeNodesReplication {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }


  /**
   * Get ItemReplicationNodeNodesId
   * @param id
   * @returns {PVEItemReplicationNodeNodesId}
   */
  get(id) { return new PVEItemReplicationNodeNodesId(this.#client, this.#node, id); }

  /**
  * List status of all replication jobs on this node.
  * @param {int} guest Only list replication jobs for this guest.
  * @returns {Result}
  */
  async status(guest) {
    const parameters = { 'guest': guest };
    return await this.#client.get(`/nodes/${this.#node}/replication`, parameters);
  }

}
/**
 * Class PVEItemReplicationNodeNodesId
 */
class PVEItemReplicationNodeNodesId {
  #node;
  #id;
  /** @type {PveClient} */
  #client;

  constructor(client, node, id) {
    this.#client = client;
    this.#node = node;
    this.#id = id;
  }

  #status;
  /**
   * Get IdReplicationNodeNodesStatus
   * @returns {PVEIdReplicationNodeNodesStatus}
   */
  get status() { return this.#status == null ? (this.#status = new PVEIdReplicationNodeNodesStatus(this.#client, this.#node, this.#id)) : this.#status; }
  #log;
  /**
   * Get IdReplicationNodeNodesLog
   * @returns {PVEIdReplicationNodeNodesLog}
   */
  get log() { return this.#log == null ? (this.#log = new PVEIdReplicationNodeNodesLog(this.#client, this.#node, this.#id)) : this.#log; }
  #scheduleNow;
  /**
   * Get IdReplicationNodeNodesScheduleNow
   * @returns {PVEIdReplicationNodeNodesScheduleNow}
   */
  get scheduleNow() { return this.#scheduleNow == null ? (this.#scheduleNow = new PVEIdReplicationNodeNodesScheduleNow(this.#client, this.#node, this.#id)) : this.#scheduleNow; }


  /**
  * Directory index.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/nodes/${this.#node}/replication/${this.#id}`);
  }

}
/**
 * Class PVEIdReplicationNodeNodesStatus
 */
class PVEIdReplicationNodeNodesStatus {
  #node;
  #id;
  /** @type {PveClient} */
  #client;

  constructor(client, node, id) {
    this.#client = client;
    this.#node = node;
    this.#id = id;
  }



  /**
  * Get replication job status.
  * @returns {Result}
  */
  async jobStatus() {
    return await this.#client.get(`/nodes/${this.#node}/replication/${this.#id}/status`);
  }

}

/**
 * Class PVEIdReplicationNodeNodesLog
 */
class PVEIdReplicationNodeNodesLog {
  #node;
  #id;
  /** @type {PveClient} */
  #client;

  constructor(client, node, id) {
    this.#client = client;
    this.#node = node;
    this.#id = id;
  }



  /**
  * Read replication job log.
  * @param {int} limit
  * @param {int} start
  * @returns {Result}
  */
  async readJobLog(limit, start) {
    const parameters = {
      'limit': limit,
      'start': start
    };
    return await this.#client.get(`/nodes/${this.#node}/replication/${this.#id}/log`, parameters);
  }

}

/**
 * Class PVEIdReplicationNodeNodesScheduleNow
 */
class PVEIdReplicationNodeNodesScheduleNow {
  #node;
  #id;
  /** @type {PveClient} */
  #client;

  constructor(client, node, id) {
    this.#client = client;
    this.#node = node;
    this.#id = id;
  }



  /**
  * Schedule replication job to start as soon as possible.
  * @returns {Result}
  */
  async scheduleNow() {
    return await this.#client.create(`/nodes/${this.#node}/replication/${this.#id}/schedule_now`);
  }

}

/**
 * Class PVENodeNodesCertificates
 */
class PVENodeNodesCertificates {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }

  #acme;
  /**
   * Get CertificatesNodeNodesAcme
   * @returns {PVECertificatesNodeNodesAcme}
   */
  get acme() { return this.#acme == null ? (this.#acme = new PVECertificatesNodeNodesAcme(this.#client, this.#node)) : this.#acme; }
  #info;
  /**
   * Get CertificatesNodeNodesInfo
   * @returns {PVECertificatesNodeNodesInfo}
   */
  get info() { return this.#info == null ? (this.#info = new PVECertificatesNodeNodesInfo(this.#client, this.#node)) : this.#info; }
  #custom;
  /**
   * Get CertificatesNodeNodesCustom
   * @returns {PVECertificatesNodeNodesCustom}
   */
  get custom() { return this.#custom == null ? (this.#custom = new PVECertificatesNodeNodesCustom(this.#client, this.#node)) : this.#custom; }


  /**
  * Node index.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/nodes/${this.#node}/certificates`);
  }

}
/**
 * Class PVECertificatesNodeNodesAcme
 */
class PVECertificatesNodeNodesAcme {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }

  #certificate;
  /**
   * Get AcmeCertificatesNodeNodesCertificate
   * @returns {PVEAcmeCertificatesNodeNodesCertificate}
   */
  get certificate() { return this.#certificate == null ? (this.#certificate = new PVEAcmeCertificatesNodeNodesCertificate(this.#client, this.#node)) : this.#certificate; }


  /**
  * ACME index.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/nodes/${this.#node}/certificates/acme`);
  }

}
/**
 * Class PVEAcmeCertificatesNodeNodesCertificate
 */
class PVEAcmeCertificatesNodeNodesCertificate {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Revoke existing certificate from CA.
  * @returns {Result}
  */
  async revokeCertificate() {
    return await this.#client.delete(`/nodes/${this.#node}/certificates/acme/certificate`);
  }
  /**
  * Order a new certificate from ACME-compatible CA.
  * @param {bool} force Overwrite existing custom certificate.
  * @returns {Result}
  */
  async newCertificate(force) {
    const parameters = { 'force': force };
    return await this.#client.create(`/nodes/${this.#node}/certificates/acme/certificate`, parameters);
  }
  /**
  * Renew existing certificate from CA.
  * @param {bool} force Force renewal even if expiry is more than 30 days away.
  * @returns {Result}
  */
  async renewCertificate(force) {
    const parameters = { 'force': force };
    return await this.#client.set(`/nodes/${this.#node}/certificates/acme/certificate`, parameters);
  }

}

/**
 * Class PVECertificatesNodeNodesInfo
 */
class PVECertificatesNodeNodesInfo {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Get information about node's certificates.
  * @returns {Result}
  */
  async info() {
    return await this.#client.get(`/nodes/${this.#node}/certificates/info`);
  }

}

/**
 * Class PVECertificatesNodeNodesCustom
 */
class PVECertificatesNodeNodesCustom {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * DELETE custom certificate chain and key.
  * @param {bool} restart Restart pveproxy.
  * @returns {Result}
  */
  async removeCustomCert(restart) {
    const parameters = { 'restart': restart };
    return await this.#client.delete(`/nodes/${this.#node}/certificates/custom`, parameters);
  }
  /**
  * Upload or update custom certificate chain and key.
  * @param {string} certificates PEM encoded certificate (chain).
  * @param {bool} force Overwrite existing custom or ACME certificate files.
  * @param {string} key PEM encoded private key.
  * @param {bool} restart Restart pveproxy.
  * @returns {Result}
  */
  async uploadCustomCert(certificates, force, key, restart) {
    const parameters = {
      'certificates': certificates,
      'force': force,
      'key': key,
      'restart': restart
    };
    return await this.#client.create(`/nodes/${this.#node}/certificates/custom`, parameters);
  }

}

/**
 * Class PVENodeNodesConfig
 */
class PVENodeNodesConfig {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Get node configuration options.
  * @param {string} property Return only a specific property from the node configuration.
  *   Enum: acme,acmedomain0,acmedomain1,acmedomain2,acmedomain3,acmedomain4,acmedomain5,description,startall-onboot-delay,wakeonlan
  * @returns {Result}
  */
  async getConfig(property) {
    const parameters = { 'property': property };
    return await this.#client.get(`/nodes/${this.#node}/config`, parameters);
  }
  /**
  * Set node configuration options.
  * @param {string} acme Node specific ACME settings.
  * @param {array} acmedomainN ACME domain and validation plugin
  * @param {string} delete_ A list of settings you want to delete.
  * @param {string} description Description for the Node. Shown in the web-interface node notes panel. This is saved as comment inside the configuration file.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {int} startall_onboot_delay Initial delay in seconds, before starting all the Virtual Guests with on-boot enabled.
  * @param {string} wakeonlan MAC address for wake on LAN
  * @returns {Result}
  */
  async setOptions(acme, acmedomainN, delete_, description, digest, startall_onboot_delay, wakeonlan) {
    const parameters = {
      'acme': acme,
      'delete': delete_,
      'description': description,
      'digest': digest,
      'startall-onboot-delay': startall_onboot_delay,
      'wakeonlan': wakeonlan
    };
    this.#client.addIndexedParameter(parameters, 'acmedomain', acmedomainN);
    return await this.#client.set(`/nodes/${this.#node}/config`, parameters);
  }

}

/**
 * Class PVENodeNodesSdn
 */
class PVENodeNodesSdn {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }

  #zones;
  /**
   * Get SdnNodeNodesZones
   * @returns {PVESdnNodeNodesZones}
   */
  get zones() { return this.#zones == null ? (this.#zones = new PVESdnNodeNodesZones(this.#client, this.#node)) : this.#zones; }


  /**
  * SDN index.
  * @returns {Result}
  */
  async sdnindex() {
    return await this.#client.get(`/nodes/${this.#node}/sdn`);
  }

}
/**
 * Class PVESdnNodeNodesZones
 */
class PVESdnNodeNodesZones {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }


  /**
   * Get ItemZonesSdnNodeNodesZone
   * @param zone
   * @returns {PVEItemZonesSdnNodeNodesZone}
   */
  get(zone) { return new PVEItemZonesSdnNodeNodesZone(this.#client, this.#node, zone); }

  /**
  * Get status for all zones.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/nodes/${this.#node}/sdn/zones`);
  }

}
/**
 * Class PVEItemZonesSdnNodeNodesZone
 */
class PVEItemZonesSdnNodeNodesZone {
  #node;
  #zone;
  /** @type {PveClient} */
  #client;

  constructor(client, node, zone) {
    this.#client = client;
    this.#node = node;
    this.#zone = zone;
  }

  #content;
  /**
   * Get ZoneZonesSdnNodeNodesContent
   * @returns {PVEZoneZonesSdnNodeNodesContent}
   */
  get content() { return this.#content == null ? (this.#content = new PVEZoneZonesSdnNodeNodesContent(this.#client, this.#node, this.#zone)) : this.#content; }


  /**
  *
  * @returns {Result}
  */
  async diridx() {
    return await this.#client.get(`/nodes/${this.#node}/sdn/zones/${this.#zone}`);
  }

}
/**
 * Class PVEZoneZonesSdnNodeNodesContent
 */
class PVEZoneZonesSdnNodeNodesContent {
  #node;
  #zone;
  /** @type {PveClient} */
  #client;

  constructor(client, node, zone) {
    this.#client = client;
    this.#node = node;
    this.#zone = zone;
  }



  /**
  * List zone content.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/nodes/${this.#node}/sdn/zones/${this.#zone}/content`);
  }

}

/**
 * Class PVENodeNodesVersion
 */
class PVENodeNodesVersion {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * API version details
  * @returns {Result}
  */
  async version() {
    return await this.#client.get(`/nodes/${this.#node}/version`);
  }

}

/**
 * Class PVENodeNodesStatus
 */
class PVENodeNodesStatus {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Read node status
  * @returns {Result}
  */
  async status() {
    return await this.#client.get(`/nodes/${this.#node}/status`);
  }
  /**
  * Reboot or shutdown a node.
  * @param {string} command Specify the command.
  *   Enum: reboot,shutdown
  * @returns {Result}
  */
  async nodeCmd(command) {
    const parameters = { 'command': command };
    return await this.#client.create(`/nodes/${this.#node}/status`, parameters);
  }

}

/**
 * Class PVENodeNodesNetstat
 */
class PVENodeNodesNetstat {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Read tap/vm network device interface counters
  * @returns {Result}
  */
  async netstat() {
    return await this.#client.get(`/nodes/${this.#node}/netstat`);
  }

}

/**
 * Class PVENodeNodesExecute
 */
class PVENodeNodesExecute {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Execute multiple commands in order.
  * @param {string} commands JSON encoded array of commands.
  * @returns {Result}
  */
  async execute(commands) {
    const parameters = { 'commands': commands };
    return await this.#client.create(`/nodes/${this.#node}/execute`, parameters);
  }

}

/**
 * Class PVENodeNodesWakeonlan
 */
class PVENodeNodesWakeonlan {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Try to wake a node via 'wake on LAN' network packet.
  * @returns {Result}
  */
  async wakeonlan() {
    return await this.#client.create(`/nodes/${this.#node}/wakeonlan`);
  }

}

/**
 * Class PVENodeNodesRrd
 */
class PVENodeNodesRrd {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Read node RRD statistics (returns PNG)
  * @param {string} ds The list of datasources you want to display.
  * @param {string} timeframe Specify the time frame you are interested in.
  *   Enum: hour,day,week,month,year
  * @param {string} cf The RRD consolidation function
  *   Enum: AVERAGE,MAX
  * @returns {Result}
  */
  async rrd(ds, timeframe, cf) {
    const parameters = {
      'ds': ds,
      'timeframe': timeframe,
      'cf': cf
    };
    return await this.#client.get(`/nodes/${this.#node}/rrd`, parameters);
  }

}

/**
 * Class PVENodeNodesRrddata
 */
class PVENodeNodesRrddata {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Read node RRD statistics
  * @param {string} timeframe Specify the time frame you are interested in.
  *   Enum: hour,day,week,month,year
  * @param {string} cf The RRD consolidation function
  *   Enum: AVERAGE,MAX
  * @returns {Result}
  */
  async rrddata(timeframe, cf) {
    const parameters = {
      'timeframe': timeframe,
      'cf': cf
    };
    return await this.#client.get(`/nodes/${this.#node}/rrddata`, parameters);
  }

}

/**
 * Class PVENodeNodesSyslog
 */
class PVENodeNodesSyslog {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Read system log
  * @param {int} limit
  * @param {string} service Service ID
  * @param {string} since Display all log since this date-time string.
  * @param {int} start
  * @param {string} until Display all log until this date-time string.
  * @returns {Result}
  */
  async syslog(limit, service, since, start, until) {
    const parameters = {
      'limit': limit,
      'service': service,
      'since': since,
      'start': start,
      'until': until
    };
    return await this.#client.get(`/nodes/${this.#node}/syslog`, parameters);
  }

}

/**
 * Class PVENodeNodesJournal
 */
class PVENodeNodesJournal {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Read Journal
  * @param {string} endcursor End before the given Cursor. Conflicts with 'until'
  * @param {int} lastentries Limit to the last X lines. Conflicts with a range.
  * @param {int} since Display all log since this UNIX epoch. Conflicts with 'startcursor'.
  * @param {string} startcursor Start after the given Cursor. Conflicts with 'since'
  * @param {int} until Display all log until this UNIX epoch. Conflicts with 'endcursor'.
  * @returns {Result}
  */
  async journal(endcursor, lastentries, since, startcursor, until) {
    const parameters = {
      'endcursor': endcursor,
      'lastentries': lastentries,
      'since': since,
      'startcursor': startcursor,
      'until': until
    };
    return await this.#client.get(`/nodes/${this.#node}/journal`, parameters);
  }

}

/**
 * Class PVENodeNodesVncshell
 */
class PVENodeNodesVncshell {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Creates a VNC Shell proxy.
  * @param {string} cmd Run specific command or default to login.
  *   Enum: ceph_install,upgrade,login
  * @param {string} cmd_opts Add parameters to a command. Encoded as null terminated strings.
  * @param {int} height sets the height of the console in pixels.
  * @param {bool} websocket use websocket instead of standard vnc.
  * @param {int} width sets the width of the console in pixels.
  * @returns {Result}
  */
  async vncshell(cmd, cmd_opts, height, websocket, width) {
    const parameters = {
      'cmd': cmd,
      'cmd-opts': cmd_opts,
      'height': height,
      'websocket': websocket,
      'width': width
    };
    return await this.#client.create(`/nodes/${this.#node}/vncshell`, parameters);
  }

}

/**
 * Class PVENodeNodesTermproxy
 */
class PVENodeNodesTermproxy {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Creates a VNC Shell proxy.
  * @param {string} cmd Run specific command or default to login.
  *   Enum: ceph_install,upgrade,login
  * @param {string} cmd_opts Add parameters to a command. Encoded as null terminated strings.
  * @returns {Result}
  */
  async termproxy(cmd, cmd_opts) {
    const parameters = {
      'cmd': cmd,
      'cmd-opts': cmd_opts
    };
    return await this.#client.create(`/nodes/${this.#node}/termproxy`, parameters);
  }

}

/**
 * Class PVENodeNodesVncwebsocket
 */
class PVENodeNodesVncwebsocket {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Opens a websocket for VNC traffic.
  * @param {int} port Port number returned by previous vncproxy call.
  * @param {string} vncticket Ticket from previous call to vncproxy.
  * @returns {Result}
  */
  async vncwebsocket(port, vncticket) {
    const parameters = {
      'port': port,
      'vncticket': vncticket
    };
    return await this.#client.get(`/nodes/${this.#node}/vncwebsocket`, parameters);
  }

}

/**
 * Class PVENodeNodesSpiceshell
 */
class PVENodeNodesSpiceshell {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Creates a SPICE shell.
  * @param {string} cmd Run specific command or default to login.
  *   Enum: ceph_install,upgrade,login
  * @param {string} cmd_opts Add parameters to a command. Encoded as null terminated strings.
  * @param {string} proxy SPICE proxy server. This can be used by the client to specify the proxy server. All nodes in a cluster runs 'spiceproxy', so it is up to the client to choose one. By default, we return the node where the VM is currently running. As reasonable setting is to use same node you use to connect to the API (This is window.location.hostname for the JS GUI).
  * @returns {Result}
  */
  async spiceshell(cmd, cmd_opts, proxy) {
    const parameters = {
      'cmd': cmd,
      'cmd-opts': cmd_opts,
      'proxy': proxy
    };
    return await this.#client.create(`/nodes/${this.#node}/spiceshell`, parameters);
  }

}

/**
 * Class PVENodeNodesDns
 */
class PVENodeNodesDns {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Read DNS settings.
  * @returns {Result}
  */
  async dns() {
    return await this.#client.get(`/nodes/${this.#node}/dns`);
  }
  /**
  * Write DNS settings.
  * @param {string} search Search domain for host-name lookup.
  * @param {string} dns1 First name server IP address.
  * @param {string} dns2 Second name server IP address.
  * @param {string} dns3 Third name server IP address.
  * @returns {Result}
  */
  async updateDns(search, dns1, dns2, dns3) {
    const parameters = {
      'search': search,
      'dns1': dns1,
      'dns2': dns2,
      'dns3': dns3
    };
    return await this.#client.set(`/nodes/${this.#node}/dns`, parameters);
  }

}

/**
 * Class PVENodeNodesTime
 */
class PVENodeNodesTime {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Read server time and time zone settings.
  * @returns {Result}
  */
  async time() {
    return await this.#client.get(`/nodes/${this.#node}/time`);
  }
  /**
  * Set time zone.
  * @param {string} timezone Time zone. The file '/usr/share/zoneinfo/zone.tab' contains the list of valid names.
  * @returns {Result}
  */
  async setTimezone(timezone) {
    const parameters = { 'timezone': timezone };
    return await this.#client.set(`/nodes/${this.#node}/time`, parameters);
  }

}

/**
 * Class PVENodeNodesAplinfo
 */
class PVENodeNodesAplinfo {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Get list of appliances.
  * @returns {Result}
  */
  async aplinfo() {
    return await this.#client.get(`/nodes/${this.#node}/aplinfo`);
  }
  /**
  * Download appliance templates.
  * @param {string} storage The storage where the template will be stored
  * @param {string} template The template which will downloaded
  * @returns {Result}
  */
  async aplDownload(storage, template) {
    const parameters = {
      'storage': storage,
      'template': template
    };
    return await this.#client.create(`/nodes/${this.#node}/aplinfo`, parameters);
  }

}

/**
 * Class PVENodeNodesQueryUrlMetadata
 */
class PVENodeNodesQueryUrlMetadata {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Query metadata of an URL: file size, file name and mime type.
  * @param {string} url The URL to query the metadata from.
  * @param {bool} verify_certificates If false, no SSL/TLS certificates will be verified.
  * @returns {Result}
  */
  async queryUrlMetadata(url, verify_certificates) {
    const parameters = {
      'url': url,
      'verify-certificates': verify_certificates
    };
    return await this.#client.get(`/nodes/${this.#node}/query-url-metadata`, parameters);
  }

}

/**
 * Class PVENodeNodesReport
 */
class PVENodeNodesReport {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Gather various systems information about a node
  * @returns {Result}
  */
  async report() {
    return await this.#client.get(`/nodes/${this.#node}/report`);
  }

}

/**
 * Class PVENodeNodesStartall
 */
class PVENodeNodesStartall {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Start all VMs and containers located on this node (by default only those with onboot=1).
  * @param {bool} force Issue start command even if virtual guest have 'onboot' not set or set to off.
  * @param {string} vms Only consider guests from this comma separated list of VMIDs.
  * @returns {Result}
  */
  async startall(force, vms) {
    const parameters = {
      'force': force,
      'vms': vms
    };
    return await this.#client.create(`/nodes/${this.#node}/startall`, parameters);
  }

}

/**
 * Class PVENodeNodesStopall
 */
class PVENodeNodesStopall {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Stop all VMs and Containers.
  * @param {string} vms Only consider Guests with these IDs.
  * @returns {Result}
  */
  async stopall(vms) {
    const parameters = { 'vms': vms };
    return await this.#client.create(`/nodes/${this.#node}/stopall`, parameters);
  }

}

/**
 * Class PVENodeNodesMigrateall
 */
class PVENodeNodesMigrateall {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Migrate all VMs and Containers.
  * @param {string} target Target node.
  * @param {int} maxworkers Maximal number of parallel migration job. If not set use 'max_workers' from datacenter.cfg, one of both must be set!
  * @param {string} vms Only consider Guests with these IDs.
  * @param {bool} with_local_disks Enable live storage migration for local disk
  * @returns {Result}
  */
  async migrateall(target, maxworkers, vms, with_local_disks) {
    const parameters = {
      'target': target,
      'maxworkers': maxworkers,
      'vms': vms,
      'with-local-disks': with_local_disks
    };
    return await this.#client.create(`/nodes/${this.#node}/migrateall`, parameters);
  }

}

/**
 * Class PVENodeNodesHosts
 */
class PVENodeNodesHosts {
  #node;
  /** @type {PveClient} */
  #client;

  constructor(client, node) {
    this.#client = client;
    this.#node = node;
  }



  /**
  * Get the content of /etc/hosts.
  * @returns {Result}
  */
  async getEtcHosts() {
    return await this.#client.get(`/nodes/${this.#node}/hosts`);
  }
  /**
  * Write /etc/hosts.
  * @param {string} data The target content of /etc/hosts.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @returns {Result}
  */
  async writeEtcHosts(data, digest) {
    const parameters = {
      'data': data,
      'digest': digest
    };
    return await this.#client.create(`/nodes/${this.#node}/hosts`, parameters);
  }

}

/**
 * Class PVEStorage
 */
class PVEStorage {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }


  /**
   * Get ItemStorageStorage
   * @param storage
   * @returns {PVEItemStorageStorage}
   */
  get(storage) { return new PVEItemStorageStorage(this.#client, storage); }

  /**
  * Storage index.
  * @param {string} type Only list storage of specific type
  *   Enum: btrfs,cephfs,cifs,dir,glusterfs,iscsi,iscsidirect,lvm,lvmthin,nfs,pbs,rbd,zfs,zfspool
  * @returns {Result}
  */
  async index(type) {
    const parameters = { 'type': type };
    return await this.#client.get(`/storage`, parameters);
  }
  /**
  * Create a new storage.
  * @param {string} storage The storage identifier.
  * @param {string} type Storage type.
  *   Enum: btrfs,cephfs,cifs,dir,glusterfs,iscsi,iscsidirect,lvm,lvmthin,nfs,pbs,rbd,zfs,zfspool
  * @param {string} authsupported Authsupported.
  * @param {string} base Base volume. This volume is automatically activated.
  * @param {string} blocksize block size
  * @param {string} bwlimit Set bandwidth/io limits various operations.
  * @param {string} comstar_hg host group for comstar views
  * @param {string} comstar_tg target group for comstar views
  * @param {string} content Allowed content types.  NOTE: the value 'rootdir' is used for Containers, and value 'images' for VMs.
  * @param {string} datastore Proxmox Backup Server datastore name.
  * @param {bool} disable Flag to disable the storage.
  * @param {string} domain CIFS domain.
  * @param {string} encryption_key Encryption key. Use 'autogen' to generate one automatically without passphrase.
  * @param {string} export_ NFS export path.
  * @param {string} fingerprint Certificate SHA 256 fingerprint.
  * @param {string} format Default image format.
  * @param {string} fs_name The Ceph filesystem name.
  * @param {bool} fuse Mount CephFS through FUSE.
  * @param {string} is_mountpoint Assume the given path is an externally managed mountpoint and consider the storage offline if it is not mounted. Using a boolean (yes/no) value serves as a shortcut to using the target path in this field.
  * @param {string} iscsiprovider iscsi provider
  * @param {string} keyring Client keyring contents (for external clusters).
  * @param {bool} krbd Always access rbd through krbd kernel module.
  * @param {string} lio_tpg target portal group for Linux LIO targets
  * @param {string} master_pubkey Base64-encoded, PEM-formatted public RSA key. Used to encrypt a copy of the encryption-key which will be added to each encrypted backup.
  * @param {int} maxfiles Deprecated: use 'prune-backups' instead. Maximal number of backup files per VM. Use '0' for unlimited.
  * @param {bool} mkdir Create the directory if it doesn't exist.
  * @param {string} monhost IP addresses of monitors (for external clusters).
  * @param {string} mountpoint mount point
  * @param {string} namespace RBD Namespace.
  * @param {bool} nocow Set the NOCOW flag on files. Disables data checksumming and causes data errors to be unrecoverable from while allowing direct I/O. Only use this if data does not need to be any more safe than on a single ext4 formatted disk with no underlying raid system.
  * @param {string} nodes List of cluster node names.
  * @param {bool} nowritecache disable write caching on the target
  * @param {string} options NFS mount options (see 'man nfs')
  * @param {string} password Password for accessing the share/datastore.
  * @param {string} path File system path.
  * @param {string} pool Pool.
  * @param {int} port For non default port.
  * @param {string} portal iSCSI portal (IP or DNS name with optional port).
  * @param {string} preallocation Preallocation mode for raw and qcow2 images. Using 'metadata' on raw images results in preallocation=off.
  *   Enum: off,metadata,falloc,full
  * @param {string} prune_backups The retention options with shorter intervals are processed first with --keep-last being the very first one. Each option covers a specific period of time. We say that backups within this period are covered by this option. The next option does not take care of already covered backups and only considers older backups.
  * @param {bool} saferemove Zero-out data when removing LVs.
  * @param {string} saferemove_throughput Wipe throughput (cstream -t parameter value).
  * @param {string} server Server IP or DNS name.
  * @param {string} server2 Backup volfile server IP or DNS name.
  * @param {string} share CIFS share.
  * @param {bool} shared Mark storage as shared.
  * @param {string} smbversion SMB protocol version. 'default' if not set, negotiates the highest SMB2+ version supported by both the client and server.
  *   Enum: default,2.0,2.1,3,3.0,3.11
  * @param {bool} sparse use sparse volumes
  * @param {string} subdir Subdir to mount.
  * @param {bool} tagged_only Only use logical volumes tagged with 'pve-vm-ID'.
  * @param {string} target iSCSI target.
  * @param {string} thinpool LVM thin pool LV name.
  * @param {string} transport Gluster transport: tcp or rdma
  *   Enum: tcp,rdma,unix
  * @param {string} username RBD Id.
  * @param {string} vgname Volume group name.
  * @param {string} volume Glusterfs Volume.
  * @returns {Result}
  */
  async create(storage, type, authsupported, base, blocksize, bwlimit, comstar_hg, comstar_tg, content, datastore, disable, domain, encryption_key, export_, fingerprint, format, fs_name, fuse, is_mountpoint, iscsiprovider, keyring, krbd, lio_tpg, master_pubkey, maxfiles, mkdir, monhost, mountpoint, namespace, nocow, nodes, nowritecache, options, password, path, pool, port, portal, preallocation, prune_backups, saferemove, saferemove_throughput, server, server2, share, shared, smbversion, sparse, subdir, tagged_only, target, thinpool, transport, username, vgname, volume) {
    const parameters = {
      'storage': storage,
      'type': type,
      'authsupported': authsupported,
      'base': base,
      'blocksize': blocksize,
      'bwlimit': bwlimit,
      'comstar_hg': comstar_hg,
      'comstar_tg': comstar_tg,
      'content': content,
      'datastore': datastore,
      'disable': disable,
      'domain': domain,
      'encryption-key': encryption_key,
      'export': export_,
      'fingerprint': fingerprint,
      'format': format,
      'fs-name': fs_name,
      'fuse': fuse,
      'is_mountpoint': is_mountpoint,
      'iscsiprovider': iscsiprovider,
      'keyring': keyring,
      'krbd': krbd,
      'lio_tpg': lio_tpg,
      'master-pubkey': master_pubkey,
      'maxfiles': maxfiles,
      'mkdir': mkdir,
      'monhost': monhost,
      'mountpoint': mountpoint,
      'namespace': namespace,
      'nocow': nocow,
      'nodes': nodes,
      'nowritecache': nowritecache,
      'options': options,
      'password': password,
      'path': path,
      'pool': pool,
      'port': port,
      'portal': portal,
      'preallocation': preallocation,
      'prune-backups': prune_backups,
      'saferemove': saferemove,
      'saferemove_throughput': saferemove_throughput,
      'server': server,
      'server2': server2,
      'share': share,
      'shared': shared,
      'smbversion': smbversion,
      'sparse': sparse,
      'subdir': subdir,
      'tagged_only': tagged_only,
      'target': target,
      'thinpool': thinpool,
      'transport': transport,
      'username': username,
      'vgname': vgname,
      'volume': volume
    };
    return await this.#client.create(`/storage`, parameters);
  }

}
/**
 * Class PVEItemStorageStorage
 */
class PVEItemStorageStorage {
  #storage;
  /** @type {PveClient} */
  #client;

  constructor(client, storage) {
    this.#client = client;
    this.#storage = storage;
  }



  /**
  * Delete storage configuration.
  * @returns {Result}
  */
  async delete_() {
    return await this.#client.delete(`/storage/${this.#storage}`);
  }
  /**
  * Read storage configuration.
  * @returns {Result}
  */
  async read() {
    return await this.#client.get(`/storage/${this.#storage}`);
  }
  /**
  * Update storage configuration.
  * @param {string} blocksize block size
  * @param {string} bwlimit Set bandwidth/io limits various operations.
  * @param {string} comstar_hg host group for comstar views
  * @param {string} comstar_tg target group for comstar views
  * @param {string} content Allowed content types.  NOTE: the value 'rootdir' is used for Containers, and value 'images' for VMs.
  * @param {string} delete_ A list of settings you want to delete.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {bool} disable Flag to disable the storage.
  * @param {string} domain CIFS domain.
  * @param {string} encryption_key Encryption key. Use 'autogen' to generate one automatically without passphrase.
  * @param {string} fingerprint Certificate SHA 256 fingerprint.
  * @param {string} format Default image format.
  * @param {string} fs_name The Ceph filesystem name.
  * @param {bool} fuse Mount CephFS through FUSE.
  * @param {string} is_mountpoint Assume the given path is an externally managed mountpoint and consider the storage offline if it is not mounted. Using a boolean (yes/no) value serves as a shortcut to using the target path in this field.
  * @param {string} keyring Client keyring contents (for external clusters).
  * @param {bool} krbd Always access rbd through krbd kernel module.
  * @param {string} lio_tpg target portal group for Linux LIO targets
  * @param {string} master_pubkey Base64-encoded, PEM-formatted public RSA key. Used to encrypt a copy of the encryption-key which will be added to each encrypted backup.
  * @param {int} maxfiles Deprecated: use 'prune-backups' instead. Maximal number of backup files per VM. Use '0' for unlimited.
  * @param {bool} mkdir Create the directory if it doesn't exist.
  * @param {string} monhost IP addresses of monitors (for external clusters).
  * @param {string} mountpoint mount point
  * @param {string} namespace RBD Namespace.
  * @param {bool} nocow Set the NOCOW flag on files. Disables data checksumming and causes data errors to be unrecoverable from while allowing direct I/O. Only use this if data does not need to be any more safe than on a single ext4 formatted disk with no underlying raid system.
  * @param {string} nodes List of cluster node names.
  * @param {bool} nowritecache disable write caching on the target
  * @param {string} options NFS mount options (see 'man nfs')
  * @param {string} password Password for accessing the share/datastore.
  * @param {string} pool Pool.
  * @param {int} port For non default port.
  * @param {string} preallocation Preallocation mode for raw and qcow2 images. Using 'metadata' on raw images results in preallocation=off.
  *   Enum: off,metadata,falloc,full
  * @param {string} prune_backups The retention options with shorter intervals are processed first with --keep-last being the very first one. Each option covers a specific period of time. We say that backups within this period are covered by this option. The next option does not take care of already covered backups and only considers older backups.
  * @param {bool} saferemove Zero-out data when removing LVs.
  * @param {string} saferemove_throughput Wipe throughput (cstream -t parameter value).
  * @param {string} server Server IP or DNS name.
  * @param {string} server2 Backup volfile server IP or DNS name.
  * @param {bool} shared Mark storage as shared.
  * @param {string} smbversion SMB protocol version. 'default' if not set, negotiates the highest SMB2+ version supported by both the client and server.
  *   Enum: default,2.0,2.1,3,3.0,3.11
  * @param {bool} sparse use sparse volumes
  * @param {string} subdir Subdir to mount.
  * @param {bool} tagged_only Only use logical volumes tagged with 'pve-vm-ID'.
  * @param {string} transport Gluster transport: tcp or rdma
  *   Enum: tcp,rdma,unix
  * @param {string} username RBD Id.
  * @returns {Result}
  */
  async update(blocksize, bwlimit, comstar_hg, comstar_tg, content, delete_, digest, disable, domain, encryption_key, fingerprint, format, fs_name, fuse, is_mountpoint, keyring, krbd, lio_tpg, master_pubkey, maxfiles, mkdir, monhost, mountpoint, namespace, nocow, nodes, nowritecache, options, password, pool, port, preallocation, prune_backups, saferemove, saferemove_throughput, server, server2, shared, smbversion, sparse, subdir, tagged_only, transport, username) {
    const parameters = {
      'blocksize': blocksize,
      'bwlimit': bwlimit,
      'comstar_hg': comstar_hg,
      'comstar_tg': comstar_tg,
      'content': content,
      'delete': delete_,
      'digest': digest,
      'disable': disable,
      'domain': domain,
      'encryption-key': encryption_key,
      'fingerprint': fingerprint,
      'format': format,
      'fs-name': fs_name,
      'fuse': fuse,
      'is_mountpoint': is_mountpoint,
      'keyring': keyring,
      'krbd': krbd,
      'lio_tpg': lio_tpg,
      'master-pubkey': master_pubkey,
      'maxfiles': maxfiles,
      'mkdir': mkdir,
      'monhost': monhost,
      'mountpoint': mountpoint,
      'namespace': namespace,
      'nocow': nocow,
      'nodes': nodes,
      'nowritecache': nowritecache,
      'options': options,
      'password': password,
      'pool': pool,
      'port': port,
      'preallocation': preallocation,
      'prune-backups': prune_backups,
      'saferemove': saferemove,
      'saferemove_throughput': saferemove_throughput,
      'server': server,
      'server2': server2,
      'shared': shared,
      'smbversion': smbversion,
      'sparse': sparse,
      'subdir': subdir,
      'tagged_only': tagged_only,
      'transport': transport,
      'username': username
    };
    return await this.#client.set(`/storage/${this.#storage}`, parameters);
  }

}

/**
 * Class PVEAccess
 */
class PVEAccess {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }

  #users;
  /**
   * Get AccessUsers
   * @returns {PVEAccessUsers}
   */
  get users() { return this.#users == null ? (this.#users = new PVEAccessUsers(this.#client)) : this.#users; }
  #groups;
  /**
   * Get AccessGroups
   * @returns {PVEAccessGroups}
   */
  get groups() { return this.#groups == null ? (this.#groups = new PVEAccessGroups(this.#client)) : this.#groups; }
  #roles;
  /**
   * Get AccessRoles
   * @returns {PVEAccessRoles}
   */
  get roles() { return this.#roles == null ? (this.#roles = new PVEAccessRoles(this.#client)) : this.#roles; }
  #acl;
  /**
   * Get AccessAcl
   * @returns {PVEAccessAcl}
   */
  get acl() { return this.#acl == null ? (this.#acl = new PVEAccessAcl(this.#client)) : this.#acl; }
  #domains;
  /**
   * Get AccessDomains
   * @returns {PVEAccessDomains}
   */
  get domains() { return this.#domains == null ? (this.#domains = new PVEAccessDomains(this.#client)) : this.#domains; }
  #openid;
  /**
   * Get AccessOpenid
   * @returns {PVEAccessOpenid}
   */
  get openid() { return this.#openid == null ? (this.#openid = new PVEAccessOpenid(this.#client)) : this.#openid; }
  #tfa;
  /**
   * Get AccessTfa
   * @returns {PVEAccessTfa}
   */
  get tfa() { return this.#tfa == null ? (this.#tfa = new PVEAccessTfa(this.#client)) : this.#tfa; }
  #ticket;
  /**
   * Get AccessTicket
   * @returns {PVEAccessTicket}
   */
  get ticket() { return this.#ticket == null ? (this.#ticket = new PVEAccessTicket(this.#client)) : this.#ticket; }
  #password;
  /**
   * Get AccessPassword
   * @returns {PVEAccessPassword}
   */
  get password() { return this.#password == null ? (this.#password = new PVEAccessPassword(this.#client)) : this.#password; }
  #permissions;
  /**
   * Get AccessPermissions
   * @returns {PVEAccessPermissions}
   */
  get permissions() { return this.#permissions == null ? (this.#permissions = new PVEAccessPermissions(this.#client)) : this.#permissions; }


  /**
  * Directory index.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/access`);
  }

}
/**
 * Class PVEAccessUsers
 */
class PVEAccessUsers {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }


  /**
   * Get ItemUsersAccessUserid
   * @param userid
   * @returns {PVEItemUsersAccessUserid}
   */
  get(userid) { return new PVEItemUsersAccessUserid(this.#client, userid); }

  /**
  * User index.
  * @param {bool} enabled Optional filter for enable property.
  * @param {bool} full Include group and token information.
  * @returns {Result}
  */
  async index(enabled, full) {
    const parameters = {
      'enabled': enabled,
      'full': full
    };
    return await this.#client.get(`/access/users`, parameters);
  }
  /**
  * Create new user.
  * @param {string} userid User ID
  * @param {string} comment
  * @param {string} email
  * @param {bool} enable Enable the account (default). You can set this to '0' to disable the account
  * @param {int} expire Account expiration date (seconds since epoch). '0' means no expiration date.
  * @param {string} firstname
  * @param {string} groups
  * @param {string} keys Keys for two factor auth (yubico).
  * @param {string} lastname
  * @param {string} password Initial password.
  * @returns {Result}
  */
  async createUser(userid, comment, email, enable, expire, firstname, groups, keys, lastname, password) {
    const parameters = {
      'userid': userid,
      'comment': comment,
      'email': email,
      'enable': enable,
      'expire': expire,
      'firstname': firstname,
      'groups': groups,
      'keys': keys,
      'lastname': lastname,
      'password': password
    };
    return await this.#client.create(`/access/users`, parameters);
  }

}
/**
 * Class PVEItemUsersAccessUserid
 */
class PVEItemUsersAccessUserid {
  #userid;
  /** @type {PveClient} */
  #client;

  constructor(client, userid) {
    this.#client = client;
    this.#userid = userid;
  }

  #tfa;
  /**
   * Get UseridUsersAccessTfa
   * @returns {PVEUseridUsersAccessTfa}
   */
  get tfa() { return this.#tfa == null ? (this.#tfa = new PVEUseridUsersAccessTfa(this.#client, this.#userid)) : this.#tfa; }
  #token;
  /**
   * Get UseridUsersAccessToken
   * @returns {PVEUseridUsersAccessToken}
   */
  get token() { return this.#token == null ? (this.#token = new PVEUseridUsersAccessToken(this.#client, this.#userid)) : this.#token; }


  /**
  * Delete user.
  * @returns {Result}
  */
  async deleteUser() {
    return await this.#client.delete(`/access/users/${this.#userid}`);
  }
  /**
  * Get user configuration.
  * @returns {Result}
  */
  async readUser() {
    return await this.#client.get(`/access/users/${this.#userid}`);
  }
  /**
  * Update user configuration.
  * @param {bool} append
  * @param {string} comment
  * @param {string} email
  * @param {bool} enable Enable the account (default). You can set this to '0' to disable the account
  * @param {int} expire Account expiration date (seconds since epoch). '0' means no expiration date.
  * @param {string} firstname
  * @param {string} groups
  * @param {string} keys Keys for two factor auth (yubico).
  * @param {string} lastname
  * @returns {Result}
  */
  async updateUser(append, comment, email, enable, expire, firstname, groups, keys, lastname) {
    const parameters = {
      'append': append,
      'comment': comment,
      'email': email,
      'enable': enable,
      'expire': expire,
      'firstname': firstname,
      'groups': groups,
      'keys': keys,
      'lastname': lastname
    };
    return await this.#client.set(`/access/users/${this.#userid}`, parameters);
  }

}
/**
 * Class PVEUseridUsersAccessTfa
 */
class PVEUseridUsersAccessTfa {
  #userid;
  /** @type {PveClient} */
  #client;

  constructor(client, userid) {
    this.#client = client;
    this.#userid = userid;
  }



  /**
  * Get user TFA types (Personal and Realm).
  * @param {bool} multiple Request all entries as an array.
  * @returns {Result}
  */
  async readUserTfaType(multiple) {
    const parameters = { 'multiple': multiple };
    return await this.#client.get(`/access/users/${this.#userid}/tfa`, parameters);
  }

}

/**
 * Class PVEUseridUsersAccessToken
 */
class PVEUseridUsersAccessToken {
  #userid;
  /** @type {PveClient} */
  #client;

  constructor(client, userid) {
    this.#client = client;
    this.#userid = userid;
  }


  /**
   * Get ItemTokenUseridUsersAccessTokenid
   * @param tokenid
   * @returns {PVEItemTokenUseridUsersAccessTokenid}
   */
  get(tokenid) { return new PVEItemTokenUseridUsersAccessTokenid(this.#client, this.#userid, tokenid); }

  /**
  * Get user API tokens.
  * @returns {Result}
  */
  async tokenIndex() {
    return await this.#client.get(`/access/users/${this.#userid}/token`);
  }

}
/**
 * Class PVEItemTokenUseridUsersAccessTokenid
 */
class PVEItemTokenUseridUsersAccessTokenid {
  #userid;
  #tokenid;
  /** @type {PveClient} */
  #client;

  constructor(client, userid, tokenid) {
    this.#client = client;
    this.#userid = userid;
    this.#tokenid = tokenid;
  }



  /**
  * Remove API token for a specific user.
  * @returns {Result}
  */
  async removeToken() {
    return await this.#client.delete(`/access/users/${this.#userid}/token/${this.#tokenid}`);
  }
  /**
  * Get specific API token information.
  * @returns {Result}
  */
  async readToken() {
    return await this.#client.get(`/access/users/${this.#userid}/token/${this.#tokenid}`);
  }
  /**
  * Generate a new API token for a specific user. NOTE: returns API token value, which needs to be stored as it cannot be retrieved afterwards!
  * @param {string} comment
  * @param {int} expire API token expiration date (seconds since epoch). '0' means no expiration date.
  * @param {bool} privsep Restrict API token privileges with separate ACLs (default), or give full privileges of corresponding user.
  * @returns {Result}
  */
  async generateToken(comment, expire, privsep) {
    const parameters = {
      'comment': comment,
      'expire': expire,
      'privsep': privsep
    };
    return await this.#client.create(`/access/users/${this.#userid}/token/${this.#tokenid}`, parameters);
  }
  /**
  * Update API token for a specific user.
  * @param {string} comment
  * @param {int} expire API token expiration date (seconds since epoch). '0' means no expiration date.
  * @param {bool} privsep Restrict API token privileges with separate ACLs (default), or give full privileges of corresponding user.
  * @returns {Result}
  */
  async updateTokenInfo(comment, expire, privsep) {
    const parameters = {
      'comment': comment,
      'expire': expire,
      'privsep': privsep
    };
    return await this.#client.set(`/access/users/${this.#userid}/token/${this.#tokenid}`, parameters);
  }

}

/**
 * Class PVEAccessGroups
 */
class PVEAccessGroups {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }


  /**
   * Get ItemGroupsAccessGroupid
   * @param groupid
   * @returns {PVEItemGroupsAccessGroupid}
   */
  get(groupid) { return new PVEItemGroupsAccessGroupid(this.#client, groupid); }

  /**
  * Group index.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/access/groups`);
  }
  /**
  * Create new group.
  * @param {string} groupid
  * @param {string} comment
  * @returns {Result}
  */
  async createGroup(groupid, comment) {
    const parameters = {
      'groupid': groupid,
      'comment': comment
    };
    return await this.#client.create(`/access/groups`, parameters);
  }

}
/**
 * Class PVEItemGroupsAccessGroupid
 */
class PVEItemGroupsAccessGroupid {
  #groupid;
  /** @type {PveClient} */
  #client;

  constructor(client, groupid) {
    this.#client = client;
    this.#groupid = groupid;
  }



  /**
  * Delete group.
  * @returns {Result}
  */
  async deleteGroup() {
    return await this.#client.delete(`/access/groups/${this.#groupid}`);
  }
  /**
  * Get group configuration.
  * @returns {Result}
  */
  async readGroup() {
    return await this.#client.get(`/access/groups/${this.#groupid}`);
  }
  /**
  * Update group data.
  * @param {string} comment
  * @returns {Result}
  */
  async updateGroup(comment) {
    const parameters = { 'comment': comment };
    return await this.#client.set(`/access/groups/${this.#groupid}`, parameters);
  }

}

/**
 * Class PVEAccessRoles
 */
class PVEAccessRoles {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }


  /**
   * Get ItemRolesAccessRoleid
   * @param roleid
   * @returns {PVEItemRolesAccessRoleid}
   */
  get(roleid) { return new PVEItemRolesAccessRoleid(this.#client, roleid); }

  /**
  * Role index.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/access/roles`);
  }
  /**
  * Create new role.
  * @param {string} roleid
  * @param {string} privs
  * @returns {Result}
  */
  async createRole(roleid, privs) {
    const parameters = {
      'roleid': roleid,
      'privs': privs
    };
    return await this.#client.create(`/access/roles`, parameters);
  }

}
/**
 * Class PVEItemRolesAccessRoleid
 */
class PVEItemRolesAccessRoleid {
  #roleid;
  /** @type {PveClient} */
  #client;

  constructor(client, roleid) {
    this.#client = client;
    this.#roleid = roleid;
  }



  /**
  * Delete role.
  * @returns {Result}
  */
  async deleteRole() {
    return await this.#client.delete(`/access/roles/${this.#roleid}`);
  }
  /**
  * Get role configuration.
  * @returns {Result}
  */
  async readRole() {
    return await this.#client.get(`/access/roles/${this.#roleid}`);
  }
  /**
  * Update an existing role.
  * @param {bool} append
  * @param {string} privs
  * @returns {Result}
  */
  async updateRole(append, privs) {
    const parameters = {
      'append': append,
      'privs': privs
    };
    return await this.#client.set(`/access/roles/${this.#roleid}`, parameters);
  }

}

/**
 * Class PVEAccessAcl
 */
class PVEAccessAcl {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }



  /**
  * Get Access Control List (ACLs).
  * @returns {Result}
  */
  async readAcl() {
    return await this.#client.get(`/access/acl`);
  }
  /**
  * Update Access Control List (add or remove permissions).
  * @param {string} path Access control path
  * @param {string} roles List of roles.
  * @param {bool} delete_ Remove permissions (instead of adding it).
  * @param {string} groups List of groups.
  * @param {bool} propagate Allow to propagate (inherit) permissions.
  * @param {string} tokens List of API tokens.
  * @param {string} users List of users.
  * @returns {Result}
  */
  async updateAcl(path, roles, delete_, groups, propagate, tokens, users) {
    const parameters = {
      'path': path,
      'roles': roles,
      'delete': delete_,
      'groups': groups,
      'propagate': propagate,
      'tokens': tokens,
      'users': users
    };
    return await this.#client.set(`/access/acl`, parameters);
  }

}

/**
 * Class PVEAccessDomains
 */
class PVEAccessDomains {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }


  /**
   * Get ItemDomainsAccessRealm
   * @param realm
   * @returns {PVEItemDomainsAccessRealm}
   */
  get(realm) { return new PVEItemDomainsAccessRealm(this.#client, realm); }

  /**
  * Authentication domain index.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/access/domains`);
  }
  /**
  * Add an authentication server.
  * @param {string} realm Authentication domain ID
  * @param {string} type Realm type.
  *   Enum: ad,ldap,openid,pam,pve
  * @param {bool} autocreate Automatically create users if they do not exist.
  * @param {string} base_dn LDAP base domain name
  * @param {string} bind_dn LDAP bind domain name
  * @param {string} capath Path to the CA certificate store
  * @param {bool} case_sensitive username is case-sensitive
  * @param {string} cert Path to the client certificate
  * @param {string} certkey Path to the client certificate key
  * @param {string} client_id OpenID Client ID
  * @param {string} client_key OpenID Client Key
  * @param {string} comment Description.
  * @param {bool} default_ Use this as default realm
  * @param {string} domain AD domain name
  * @param {string} filter LDAP filter for user sync.
  * @param {string} group_classes The objectclasses for groups.
  * @param {string} group_dn LDAP base domain name for group sync. If not set, the base_dn will be used.
  * @param {string} group_filter LDAP filter for group sync.
  * @param {string} group_name_attr LDAP attribute representing a groups name. If not set or found, the first value of the DN will be used as name.
  * @param {string} issuer_url OpenID Issuer Url
  * @param {string} mode LDAP protocol mode.
  *   Enum: ldap,ldaps,ldap+starttls
  * @param {string} password LDAP bind password. Will be stored in '/etc/pve/priv/realm/&amp;lt;REALM&amp;gt;.pw'.
  * @param {int} port Server port.
  * @param {bool} secure Use secure LDAPS protocol. DEPRECATED: use 'mode' instead.
  * @param {string} server1 Server IP address (or DNS name)
  * @param {string} server2 Fallback Server IP address (or DNS name)
  * @param {string} sslversion LDAPS TLS/SSL version. It's not recommended to use version older than 1.2!
  *   Enum: tlsv1,tlsv1_1,tlsv1_2,tlsv1_3
  * @param {string} sync_defaults_options The default options for behavior of synchronizations.
  * @param {string} sync_attributes Comma separated list of key=value pairs for specifying which LDAP attributes map to which PVE user field. For example, to map the LDAP attribute 'mail' to PVEs 'email', write  'email=mail'. By default, each PVE user field is represented  by an LDAP attribute of the same name.
  * @param {string} tfa Use Two-factor authentication.
  * @param {string} user_attr LDAP user attribute name
  * @param {string} user_classes The objectclasses for users.
  * @param {string} username_claim OpenID claim used to generate the unique username.
  *   Enum: subject,username,email
  * @param {bool} verify Verify the server's SSL certificate
  * @returns {Result}
  */
  async create(realm, type, autocreate, base_dn, bind_dn, capath, case_sensitive, cert, certkey, client_id, client_key, comment, default_, domain, filter, group_classes, group_dn, group_filter, group_name_attr, issuer_url, mode, password, port, secure, server1, server2, sslversion, sync_defaults_options, sync_attributes, tfa, user_attr, user_classes, username_claim, verify) {
    const parameters = {
      'realm': realm,
      'type': type,
      'autocreate': autocreate,
      'base_dn': base_dn,
      'bind_dn': bind_dn,
      'capath': capath,
      'case-sensitive': case_sensitive,
      'cert': cert,
      'certkey': certkey,
      'client-id': client_id,
      'client-key': client_key,
      'comment': comment,
      'default': default_,
      'domain': domain,
      'filter': filter,
      'group_classes': group_classes,
      'group_dn': group_dn,
      'group_filter': group_filter,
      'group_name_attr': group_name_attr,
      'issuer-url': issuer_url,
      'mode': mode,
      'password': password,
      'port': port,
      'secure': secure,
      'server1': server1,
      'server2': server2,
      'sslversion': sslversion,
      'sync-defaults-options': sync_defaults_options,
      'sync_attributes': sync_attributes,
      'tfa': tfa,
      'user_attr': user_attr,
      'user_classes': user_classes,
      'username-claim': username_claim,
      'verify': verify
    };
    return await this.#client.create(`/access/domains`, parameters);
  }

}
/**
 * Class PVEItemDomainsAccessRealm
 */
class PVEItemDomainsAccessRealm {
  #realm;
  /** @type {PveClient} */
  #client;

  constructor(client, realm) {
    this.#client = client;
    this.#realm = realm;
  }

  #sync;
  /**
   * Get RealmDomainsAccessSync
   * @returns {PVERealmDomainsAccessSync}
   */
  get sync() { return this.#sync == null ? (this.#sync = new PVERealmDomainsAccessSync(this.#client, this.#realm)) : this.#sync; }


  /**
  * Delete an authentication server.
  * @returns {Result}
  */
  async delete_() {
    return await this.#client.delete(`/access/domains/${this.#realm}`);
  }
  /**
  * Get auth server configuration.
  * @returns {Result}
  */
  async read() {
    return await this.#client.get(`/access/domains/${this.#realm}`);
  }
  /**
  * Update authentication server settings.
  * @param {bool} autocreate Automatically create users if they do not exist.
  * @param {string} base_dn LDAP base domain name
  * @param {string} bind_dn LDAP bind domain name
  * @param {string} capath Path to the CA certificate store
  * @param {bool} case_sensitive username is case-sensitive
  * @param {string} cert Path to the client certificate
  * @param {string} certkey Path to the client certificate key
  * @param {string} client_id OpenID Client ID
  * @param {string} client_key OpenID Client Key
  * @param {string} comment Description.
  * @param {bool} default_ Use this as default realm
  * @param {string} delete_ A list of settings you want to delete.
  * @param {string} digest Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
  * @param {string} domain AD domain name
  * @param {string} filter LDAP filter for user sync.
  * @param {string} group_classes The objectclasses for groups.
  * @param {string} group_dn LDAP base domain name for group sync. If not set, the base_dn will be used.
  * @param {string} group_filter LDAP filter for group sync.
  * @param {string} group_name_attr LDAP attribute representing a groups name. If not set or found, the first value of the DN will be used as name.
  * @param {string} issuer_url OpenID Issuer Url
  * @param {string} mode LDAP protocol mode.
  *   Enum: ldap,ldaps,ldap+starttls
  * @param {string} password LDAP bind password. Will be stored in '/etc/pve/priv/realm/&amp;lt;REALM&amp;gt;.pw'.
  * @param {int} port Server port.
  * @param {bool} secure Use secure LDAPS protocol. DEPRECATED: use 'mode' instead.
  * @param {string} server1 Server IP address (or DNS name)
  * @param {string} server2 Fallback Server IP address (or DNS name)
  * @param {string} sslversion LDAPS TLS/SSL version. It's not recommended to use version older than 1.2!
  *   Enum: tlsv1,tlsv1_1,tlsv1_2,tlsv1_3
  * @param {string} sync_defaults_options The default options for behavior of synchronizations.
  * @param {string} sync_attributes Comma separated list of key=value pairs for specifying which LDAP attributes map to which PVE user field. For example, to map the LDAP attribute 'mail' to PVEs 'email', write  'email=mail'. By default, each PVE user field is represented  by an LDAP attribute of the same name.
  * @param {string} tfa Use Two-factor authentication.
  * @param {string} user_attr LDAP user attribute name
  * @param {string} user_classes The objectclasses for users.
  * @param {bool} verify Verify the server's SSL certificate
  * @returns {Result}
  */
  async update(autocreate, base_dn, bind_dn, capath, case_sensitive, cert, certkey, client_id, client_key, comment, default_, delete_, digest, domain, filter, group_classes, group_dn, group_filter, group_name_attr, issuer_url, mode, password, port, secure, server1, server2, sslversion, sync_defaults_options, sync_attributes, tfa, user_attr, user_classes, verify) {
    const parameters = {
      'autocreate': autocreate,
      'base_dn': base_dn,
      'bind_dn': bind_dn,
      'capath': capath,
      'case-sensitive': case_sensitive,
      'cert': cert,
      'certkey': certkey,
      'client-id': client_id,
      'client-key': client_key,
      'comment': comment,
      'default': default_,
      'delete': delete_,
      'digest': digest,
      'domain': domain,
      'filter': filter,
      'group_classes': group_classes,
      'group_dn': group_dn,
      'group_filter': group_filter,
      'group_name_attr': group_name_attr,
      'issuer-url': issuer_url,
      'mode': mode,
      'password': password,
      'port': port,
      'secure': secure,
      'server1': server1,
      'server2': server2,
      'sslversion': sslversion,
      'sync-defaults-options': sync_defaults_options,
      'sync_attributes': sync_attributes,
      'tfa': tfa,
      'user_attr': user_attr,
      'user_classes': user_classes,
      'verify': verify
    };
    return await this.#client.set(`/access/domains/${this.#realm}`, parameters);
  }

}
/**
 * Class PVERealmDomainsAccessSync
 */
class PVERealmDomainsAccessSync {
  #realm;
  /** @type {PveClient} */
  #client;

  constructor(client, realm) {
    this.#client = client;
    this.#realm = realm;
  }



  /**
  * Syncs users and/or groups from the configured LDAP to user.cfg. NOTE: Synced groups will have the name 'name-$realm', so make sure those groups do not exist to prevent overwriting.
  * @param {bool} dry_run If set, does not write anything.
  * @param {bool} enable_new Enable newly synced users immediately.
  * @param {bool} full If set, uses the LDAP Directory as source of truth, deleting users or groups not returned from the sync. Otherwise only syncs information which is not already present, and does not deletes or modifies anything else.
  * @param {bool} purge Remove ACLs for users or groups which were removed from the config during a sync.
  * @param {string} scope Select what to sync.
  *   Enum: users,groups,both
  * @returns {Result}
  */
  async sync(dry_run, enable_new, full, purge, scope) {
    const parameters = {
      'dry-run': dry_run,
      'enable-new': enable_new,
      'full': full,
      'purge': purge,
      'scope': scope
    };
    return await this.#client.create(`/access/domains/${this.#realm}/sync`, parameters);
  }

}

/**
 * Class PVEAccessOpenid
 */
class PVEAccessOpenid {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }

  #authUrl;
  /**
   * Get OpenidAccessAuthUrl
   * @returns {PVEOpenidAccessAuthUrl}
   */
  get authUrl() { return this.#authUrl == null ? (this.#authUrl = new PVEOpenidAccessAuthUrl(this.#client)) : this.#authUrl; }
  #login;
  /**
   * Get OpenidAccessLogin
   * @returns {PVEOpenidAccessLogin}
   */
  get login() { return this.#login == null ? (this.#login = new PVEOpenidAccessLogin(this.#client)) : this.#login; }


  /**
  * Directory index.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/access/openid`);
  }

}
/**
 * Class PVEOpenidAccessAuthUrl
 */
class PVEOpenidAccessAuthUrl {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }



  /**
  * Get the OpenId Authorization Url for the specified realm.
  * @param {string} realm Authentication domain ID
  * @param {string} redirect_url Redirection Url. The client should set this to the used server url (location.origin).
  * @returns {Result}
  */
  async authUrl(realm, redirect_url) {
    const parameters = {
      'realm': realm,
      'redirect-url': redirect_url
    };
    return await this.#client.create(`/access/openid/auth-url`, parameters);
  }

}

/**
 * Class PVEOpenidAccessLogin
 */
class PVEOpenidAccessLogin {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }



  /**
  *  Verify OpenID authorization code and create a ticket.
  * @param {string} code OpenId authorization code.
  * @param {string} redirect_url Redirection Url. The client should set this to the used server url (location.origin).
  * @param {string} state OpenId state.
  * @returns {Result}
  */
  async login(code, redirect_url, state) {
    const parameters = {
      'code': code,
      'redirect-url': redirect_url,
      'state': state
    };
    return await this.#client.create(`/access/openid/login`, parameters);
  }

}

/**
 * Class PVEAccessTfa
 */
class PVEAccessTfa {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }


  /**
   * Get ItemTfaAccessUserid
   * @param userid
   * @returns {PVEItemTfaAccessUserid}
   */
  get(userid) { return new PVEItemTfaAccessUserid(this.#client, userid); }

  /**
  * List TFA configurations of users.
  * @returns {Result}
  */
  async listTfa() {
    return await this.#client.get(`/access/tfa`);
  }
  /**
  * Finish a u2f challenge.
  * @param {string} response The response to the current authentication challenge.
  * @returns {Result}
  */
  async verifyTfa(response) {
    const parameters = { 'response': response };
    return await this.#client.create(`/access/tfa`, parameters);
  }

}
/**
 * Class PVEItemTfaAccessUserid
 */
class PVEItemTfaAccessUserid {
  #userid;
  /** @type {PveClient} */
  #client;

  constructor(client, userid) {
    this.#client = client;
    this.#userid = userid;
  }


  /**
   * Get ItemUseridTfaAccessId
   * @param id
   * @returns {PVEItemUseridTfaAccessId}
   */
  get(id) { return new PVEItemUseridTfaAccessId(this.#client, this.#userid, id); }

  /**
  * List TFA configurations of users.
  * @returns {Result}
  */
  async listUserTfa() {
    return await this.#client.get(`/access/tfa/${this.#userid}`);
  }
  /**
  * Add a TFA entry for a user.
  * @param {string} type TFA Entry Type.
  *   Enum: totp,u2f,webauthn,recovery,yubico
  * @param {string} challenge When responding to a u2f challenge: the original challenge string
  * @param {string} description A description to distinguish multiple entries from one another
  * @param {string} password The current password.
  * @param {string} totp A totp URI.
  * @param {string} value The current value for the provided totp URI, or a Webauthn/U2F challenge response
  * @returns {Result}
  */
  async addTfaEntry(type, challenge, description, password, totp, value) {
    const parameters = {
      'type': type,
      'challenge': challenge,
      'description': description,
      'password': password,
      'totp': totp,
      'value': value
    };
    return await this.#client.create(`/access/tfa/${this.#userid}`, parameters);
  }

}
/**
 * Class PVEItemUseridTfaAccessId
 */
class PVEItemUseridTfaAccessId {
  #userid;
  #id;
  /** @type {PveClient} */
  #client;

  constructor(client, userid, id) {
    this.#client = client;
    this.#userid = userid;
    this.#id = id;
  }



  /**
  * Delete a TFA entry by ID.
  * @param {string} password The current password.
  * @returns {Result}
  */
  async deleteTfa(password) {
    const parameters = { 'password': password };
    return await this.#client.delete(`/access/tfa/${this.#userid}/${this.#id}`, parameters);
  }
  /**
  * Fetch a requested TFA entry if present.
  * @returns {Result}
  */
  async getTfaEntry() {
    return await this.#client.get(`/access/tfa/${this.#userid}/${this.#id}`);
  }
  /**
  * Add a TFA entry for a user.
  * @param {string} description A description to distinguish multiple entries from one another
  * @param {bool} enable Whether the entry should be enabled for login.
  * @param {string} password The current password.
  * @returns {Result}
  */
  async updateTfaEntry(description, enable, password) {
    const parameters = {
      'description': description,
      'enable': enable,
      'password': password
    };
    return await this.#client.set(`/access/tfa/${this.#userid}/${this.#id}`, parameters);
  }

}

/**
 * Class PVEAccessTicket
 */
class PVEAccessTicket {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }



  /**
  * Dummy. Useful for formatters which want to provide a login page.
  * @returns {Result}
  */
  async getTicket() {
    return await this.#client.get(`/access/ticket`);
  }
  /**
  * Create or verify authentication ticket.
  * @param {string} password The secret password. This can also be a valid ticket.
  * @param {string} username User name
  * @param {bool} new_format With webauthn the format of half-authenticated tickts changed. New clients should pass 1 here and not worry about the old format. The old format is deprecated and will be retired with PVE-8.0
  * @param {string} otp One-time password for Two-factor authentication.
  * @param {string} path Verify ticket, and check if user have access 'privs' on 'path'
  * @param {string} privs Verify ticket, and check if user have access 'privs' on 'path'
  * @param {string} realm You can optionally pass the realm using this parameter. Normally the realm is simply added to the username &amp;lt;username&amp;gt;@&amp;lt;relam&amp;gt;.
  * @param {string} tfa_challenge The signed TFA challenge string the user wants to respond to.
  * @returns {Result}
  */
  async createTicket(password, username, new_format, otp, path, privs, realm, tfa_challenge) {
    const parameters = {
      'password': password,
      'username': username,
      'new-format': new_format,
      'otp': otp,
      'path': path,
      'privs': privs,
      'realm': realm,
      'tfa-challenge': tfa_challenge
    };
    return await this.#client.create(`/access/ticket`, parameters);
  }

}

/**
 * Class PVEAccessPassword
 */
class PVEAccessPassword {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }



  /**
  * Change user password.
  * @param {string} password The new password.
  * @param {string} userid User ID
  * @returns {Result}
  */
  async changePassword(password, userid) {
    const parameters = {
      'password': password,
      'userid': userid
    };
    return await this.#client.set(`/access/password`, parameters);
  }

}

/**
 * Class PVEAccessPermissions
 */
class PVEAccessPermissions {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }



  /**
  * Retrieve effective permissions of given user/token.
  * @param {string} path Only dump this specific path, not the whole tree.
  * @param {string} userid User ID or full API token ID
  * @returns {Result}
  */
  async permissions(path, userid) {
    const parameters = {
      'path': path,
      'userid': userid
    };
    return await this.#client.get(`/access/permissions`, parameters);
  }

}

/**
 * Class PVEPools
 */
class PVEPools {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }


  /**
   * Get ItemPoolsPoolid
   * @param poolid
   * @returns {PVEItemPoolsPoolid}
   */
  get(poolid) { return new PVEItemPoolsPoolid(this.#client, poolid); }

  /**
  * Pool index.
  * @returns {Result}
  */
  async index() {
    return await this.#client.get(`/pools`);
  }
  /**
  * Create new pool.
  * @param {string} poolid
  * @param {string} comment
  * @returns {Result}
  */
  async createPool(poolid, comment) {
    const parameters = {
      'poolid': poolid,
      'comment': comment
    };
    return await this.#client.create(`/pools`, parameters);
  }

}
/**
 * Class PVEItemPoolsPoolid
 */
class PVEItemPoolsPoolid {
  #poolid;
  /** @type {PveClient} */
  #client;

  constructor(client, poolid) {
    this.#client = client;
    this.#poolid = poolid;
  }



  /**
  * Delete pool.
  * @returns {Result}
  */
  async deletePool() {
    return await this.#client.delete(`/pools/${this.#poolid}`);
  }
  /**
  * Get pool configuration.
  * @returns {Result}
  */
  async readPool() {
    return await this.#client.get(`/pools/${this.#poolid}`);
  }
  /**
  * Update pool data.
  * @param {string} comment
  * @param {bool} delete_ Remove vms/storage (instead of adding it).
  * @param {string} storage List of storage IDs.
  * @param {string} vms List of virtual machines.
  * @returns {Result}
  */
  async updatePool(comment, delete_, storage, vms) {
    const parameters = {
      'comment': comment,
      'delete': delete_,
      'storage': storage,
      'vms': vms
    };
    return await this.#client.set(`/pools/${this.#poolid}`, parameters);
  }

}

/**
 * Class PVEVersion
 */
class PVEVersion {

  /** @type {PveClient} */
  #client;

  constructor(client) {
    this.#client = client;

  }



  /**
  * API version details, including some parts of the global datacenter config.
  * @returns {Result}
  */
  async version() {
    return await this.#client.get(`/version`);
  }

}



module.exports = { PveClient, PveClientBase, Result, ResponseType }