# <img src="https://raw.githubusercontent.com/Corsinvest/cv4pve-api-javascript/main/icon.svg" alt="" height="36" align="top"> cv4pve-api-javascript

```
   ______                _                      __
  / ____/___  __________(_)___ _   _____  _____/ /_
 / /   / __ \/ ___/ ___/ / __ \ | / / _ \/ ___/ __/
/ /___/ /_/ / /  (__  ) / / / / |/ /  __(__  ) /_
\____/\____/_/  /____/_/_/ /_/|___/\___/____/\__/

Proxmox VE API Client for JavaScript/Node.js (Made in Italy)
```

[![License](https://img.shields.io/github/license/Corsinvest/cv4pve-api-javascript.svg?style=flat-square)](https://github.com/Corsinvest/cv4pve-api-javascript/blob/main/LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-blue?style=flat-square&logo=nodedotjs)](https://nodejs.org/)
[![npm](https://img.shields.io/npm/v/@corsinvest/cv4pve-api-javascript?style=flat-square&logo=npm)](https://www.npmjs.com/package/@corsinvest/cv4pve-api-javascript)
[![npm](https://img.shields.io/npm/dt/@corsinvest/cv4pve-api-javascript?style=flat-square&logo=npm)](https://www.npmjs.com/package/@corsinvest/cv4pve-api-javascript)

> **The Proxmox VE API from JavaScript**: a Node.js client with a method for every endpoint of the Proxmox VE API, running in your application and talking only to the API.
>
> **[Documentation](https://corsinvest.github.io/cv4pve-api-javascript/)**

---

<p align="center">
  <img src="https://raw.githubusercontent.com/Corsinvest/cv4pve-api-javascript/main/docs/src/assets/javascript.svg" alt="JavaScript logo" width="70">
  &nbsp;&nbsp;
  <img src="https://raw.githubusercontent.com/Corsinvest/cv4pve-api-javascript/main/docs/src/assets/typescript.svg" alt="TypeScript logo" width="70">
</p>

## Why

An application that manages Proxmox VE (a customer portal, a scheduled job, a monitoring or billing tool) has to speak its REST API: tickets and tokens, paths, parameters, JSON, tasks that end later. Written by hand it is a layer of HTTP code to build and to keep up with every Proxmox VE release.

cv4pve-api-javascript is that layer, generated from the API itself. The calls follow the tree of the API, so the [Proxmox VE API viewer](https://pve.proxmox.com/pve-docs/api-viewer/) is also the reference of the client.

It **runs in your application and uses only the Proxmox VE API**: nothing to install on the nodes, no SSH.

---

## Features

- **The whole API**: a method for every endpoint and HTTP method, generated from the Proxmox VE API schema; `/nodes/{node}/qemu/{vmid}/config` is `client.nodes.get("pve01").qemu.get(100).config`.
- **One Result for every call**: the HTTP outcome and the Proxmox VE answer, as plain JavaScript objects. An answer with an error status does not throw.
- **API token or password**: with two-factor authentication, certificate validation and timeout.
- **Tasks**: start a backup, a clone or a migration, wait for its task and read whether it succeeded.
- **Raw calls**: GET, POST, PUT and DELETE on any path with an object of parameters, for the calls with many options and for endpoints newer than the library.
- **Promises and typings**: every call returns a promise; the TypeScript typings are in the package. Node.js 18 or later and one small dependency, on Windows, Linux and macOS.

---

## Quick start

```bash
npm install @corsinvest/cv4pve-api-javascript
```

```js
const { PveClient } = require("@corsinvest/cv4pve-api-javascript");

async function main() {
  // connect to any node of the cluster, with an API token
  const client = new PveClient("pve01");
  client.apiToken = "automation@pve!app=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

  // GET /nodes/{node}/qemu/{vmid}/status/current
  const result = await client.nodes.get("pve01").qemu.get(100).status.current.vmStatus();

  console.log(
    result.isSuccessStatusCode
      ? `VM ${result.response.data.vmid} is ${result.response.data.status}`
      : `${result.statusCode} ${result.reasonPhrase}`
  );
}

main();
```

With ES modules and TypeScript: `import { PveClient } from "@corsinvest/cv4pve-api-javascript";`.

What the token needs: [Permissions](https://corsinvest.github.io/cv4pve-api-javascript/permissions/).

The first two numbers of the version are the Proxmox VE version the client was generated from: 9.2.x is for Proxmox VE 9.2. Changes of each release: [CHANGELOG.md](https://github.com/Corsinvest/cv4pve-api-javascript/blob/main/CHANGELOG.md).

---

## Documentation

| | |
|---|---|
| [Getting started](https://corsinvest.github.io/cv4pve-api-javascript/getting-started/) | Install, connect, first calls |
| [Connection](https://corsinvest.github.io/cv4pve-api-javascript/connection/) | API token or password, two-factor authentication, certificates, timeout |
| [Permissions](https://corsinvest.github.io/cv4pve-api-javascript/permissions/) | The user, the token and the privileges an application needs |
| [Concepts](https://corsinvest.github.io/cv4pve-api-javascript/concepts/api-structure/) | API structure, results, indexed parameters, tasks, errors |
| [Examples](https://corsinvest.github.io/cv4pve-api-javascript/examples/common-tasks/) | Common tasks, creating a VM, bulk operations |
| [Troubleshooting](https://corsinvest.github.io/cv4pve-api-javascript/troubleshooting/) | Logging and the common errors |

---

## Development

```bash
# Offline tests: https.request is replaced by a fake, no cluster is needed
npm test

# Tests on a real Proxmox VE
npm run test:live

# Documentation site, from the docs folder
npm install
npm run dev
```

The live tests read the connection from the environment: `PVE_HOST`, `PVE_PORT` (default 8006), `PVE_API_TOKEN` and `PVE_TEST_VMID`. Without `PVE_HOST` and `PVE_API_TOKEN` every live test is skipped. They only read, except on the QEMU VM `PVE_TEST_VMID`: there they change and restore the description, set and remove a cloud-init `ipconfig` entry, and create and delete a snapshot. Without `PVE_TEST_VMID` those tests are skipped.

---

## Related tools

Prefer a command line? [cv4pve-cli](https://github.com/Corsinvest/cv4pve-cli) calls the same API from any shell. The same client for .NET: [cv4pve-api-dotnet](https://github.com/Corsinvest/cv4pve-api-dotnet). For Java: [cv4pve-api-java](https://github.com/Corsinvest/cv4pve-api-java). For PHP: [cv4pve-api-php](https://github.com/Corsinvest/cv4pve-api-php). From PowerShell: [cv4pve-api-powershell](https://github.com/Corsinvest/cv4pve-api-powershell). The whole suite: [corsinvest.it/cv4pve](https://www.corsinvest.it/en/cv4pve/).

---

## Support

Professional support and consulting available through [Corsinvest](https://www.corsinvest.it/en/cv4pve/).

---

**By developers, for developers.**

Part of [cv4pve](https://www.corsinvest.it/en/cv4pve/) suite | Made with ❤️ in Italy by [Corsinvest](https://www.corsinvest.it)

Proxmox® is a registered trademark of Proxmox Server Solutions GmbH. cv4pve is developed by Corsinvest and is not a Proxmox product.

Copyright © Corsinvest Srl
