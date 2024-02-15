# cv4pve-api-javascript

Proxmox VE Client API JavaScript

![GitHub release](https://img.shields.io/github/release/Corsinvest/cv4pve-api-javascript.svg) [![npm](https://img.shields.io/npm/dt/@corsinvest/cv4pve-api-javascript?logo=npm)](https://www.npmjs.com/package/@corsinvest/cv4pve-api-javascript)

[Proxmox VE Api](https://pve.proxmox.com/pve-docs/api-viewer/)

```text
   ______                _                      __
  / ____/___  __________(_)___ _   _____  _____/ /_
 / /   / __ \/ ___/ ___/ / __ \ | / / _ \/ ___/ __/
/ /___/ /_/ / /  (__  ) / / / / |/ /  __(__  ) /_
\____/\____/_/  /____/_/_/ /_/|___/\___/____/\__/

Corsinvest for Proxmox VE Api Client  (Made in Italy)
```

## Copyright and License

Copyright: Corsinvest Srl
For licensing details please visit [LICENSE](LICENSE)

## Commercial Support

This software is part of a suite of tools called cv4pve-tools. If you want commercial support, visit the [site](https://www.corsinvest.it/cv4pve)

## General

The client is generated from a JSON Api on Proxmox VE.

## Result

The result is class **Result** and contain methods:

* **response** returned from Proxmox VE (data,errors,...) JSON
* **responseInError** (bool) : Contains errors from Proxmox VE.
* **statusCode** (int) : Status code of the HTTP response.
* **reasonPhrase** (string): The reason phrase which typically is sent by servers together with the status code.
* **isSuccessStatusCode** (bool) : Gets a value that indicates if the HTTP response was successful.

## Main features

* Easy to learn
* Method named
* Implementation respect the [Api structure of Proxmox VE](https://pve.proxmox.com/pve-docs/api-viewer/)
* Full method generated from documentation
* Comment any method and parameters
* Parameters indexed eg [n] is structured in array index and value
* Tree structure
  * await client.nodes.get('pve1').qemu.vmlist().response
* Return data Proxmox VE
* Debug show information
* Return result
  * Request
  * Response
  * Status
* Last result action
* Wait task finish task
  * waitForTaskToFinish
  * taskIsRunning
  * getExitStatusTask
* Method directly access
  * get
  * set
  * create
  * delete
* Login return bool if access
* Return Result class more information
* Minimal dependency library
* ClientBase lite function
* Form Proxmox VE 6.2 support Api Token for user
* Login with One-time password for Two-factor authentication

## Api token

From version 6.2 of Proxmox VE is possible to use [Api token](https://pve.proxmox.com/pve-docs/pveum-plain.html).
This feature permit execute Api without using user and password.
If using **Privilege Separation** when create api token remember specify in permission.
Format USER@REALM!TOKENID=UUID

## Usage

```javascript
const pve = require('./src');

async function foo() {
    var client = new pve.PveClient('10.92.90.101', 8006);
    //client.logEnabled = true;
    //client.apiToken = '';

    var login = await client.login('root', process.env.PVE_PASSWORD, 'pam');
    if (login) {
        console.log((await client.get('/version')).response);
        console.log((await client.version.version()).response);

        console.log((await client.get('/nodes')).response);
        console.log((await client.nodes.index()).response);

        console.log((await client.get('/nodes/cv-pve01/qemu')).response);
        console.log((await client.nodes.get('cv-pve01').qemu.vmlist(0)).response);

        console.log((await client.get('/nodes/cv-pve01/qemu/103/config/')).response);
        console.log((await client.nodes.get('cv-pve01').qemu.get(103).config.vmConfig()).response);

        console.log((await client.get('/nodes/cv-pve01/qemu/103/snapshot/')).response);
        console.log((await client.nodes.get('cv-pve01').qemu.get(103).snapshot.snapshotList()).response);
    }
}
```
