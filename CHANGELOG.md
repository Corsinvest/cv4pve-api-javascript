# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
The major and minor version follow Proxmox VE (9.2.x targets Proxmox VE 9.2); the patch number can include breaking changes, listed under "Changed (breaking)".

Versions before 9.2.1 are described in the [GitHub releases](https://github.com/Corsinvest/cv4pve-api-javascript/releases).

## [9.2.1] - 2026-10-05

### Added
- Api: Ceph health mute, `cluster.ceph.healthMute`: `healthMuteIndex()` and `get(code).healthMute(value, sticky, ttl)` ([#22](https://github.com/Corsinvest/cv4pve-api-javascript/pull/22))
- Api: Ceph rolling restart, `restartBulk` on `/cluster/ceph/restart-bulk` and `/nodes/{node}/ceph/restart-bulk` ([#22](https://github.com/Corsinvest/cv4pve-api-javascript/pull/22))
- Api: Ceph releases, `releases()` on `/nodes/{node}/ceph/releases` ([#22](https://github.com/Corsinvest/cv4pve-api-javascript/pull/22))
- Api: `/nodes/{node}/journal` `journal` has the new filters `identifiers`, `kernel`, `priority`, `service`, `structured`, `unit`, `units` ([#22](https://github.com/Corsinvest/cv4pve-api-javascript/pull/22))
- `validateCertificate` property (default `false`): the certificate of the node could not be validated at all ([#21](https://github.com/Corsinvest/cv4pve-api-javascript/pull/21))
- `PveResultException`, exported: thrown when the status of a task cannot be read and when a login needs a second factor and no code is given ([#20](https://github.com/Corsinvest/cv4pve-api-javascript/pull/20))
- A timeout rejects with `code` `ETIMEDOUT` ([#21](https://github.com/Corsinvest/cv4pve-api-javascript/pull/21))
- Tests: offline tests of the base client in `test/base.test.js` and of the generated client in `test/generated.test.js` (`https.request` replaced by a fake, no cluster needed), run by the build workflow with `npm test`; tests on a real Proxmox VE in `test/live.test.js`, run with `npm run test:live` (`PVE_HOST`, `PVE_API_TOKEN`, `PVE_TEST_VMID`). The old manual script `test.js` is removed ([#21](https://github.com/Corsinvest/cv4pve-api-javascript/pull/21), [#22](https://github.com/Corsinvest/cv4pve-api-javascript/pull/22))

### Changed (breaking)
- The parameters of these methods changed position. A call that passes them by position has to be updated ([#22](https://github.com/Corsinvest/cv4pve-api-javascript/pull/22)):
  - `nodes.get(node).journal.journal`: the new filters are placed among the old parameters, now `(endcursor, identifiers, kernel, lastentries, priority, service, since, startcursor, structured, unit, units, until)`
  - `cluster.ha.rules.createRule`: now `(rule, type, resources, affinity, comment, disable, nodes, strict)`, it was `(resources, rule, type, ...)`
  - `cluster.ha.rules.get(rule).updateRule`: now `(type, delete_, digest, affinity, comment, disable, nodes, resources, strict)`
- The value of the path is no longer a parameter of the method, it is taken from the indexer ([#22](https://github.com/Corsinvest/cv4pve-api-javascript/pull/22)):
  - `route_map_id` of `listRouteMapEntriesForRouteMap`, `getRouteMapEntry`, `updateRouteMapEntry` and `deleteRouteMapEntry` under `cluster.sdn.routeMaps.entries.get(route_map_id)`
  - `pci_id_or_mapping` of `pciIndex` and `mdevscan` under `nodes.get(node).hardware.pci.get(pci_id_or_mapping)`
- `timeout` refuses a negative value or a value that is not a number with a `RangeError`: a string such as `"1000"` was accepted. `0` still means no limit ([#22](https://github.com/Corsinvest/cv4pve-api-javascript/pull/22))
- Parameters that JSON cannot encode (`NaN`, `Infinity`, a function, a `Symbol`, a `BigInt`, a circular reference) reject with a `TypeError` before any request. `NaN` and `Infinity` were sent as `null`, a function and a `Symbol` were dropped silently ([#22](https://github.com/Corsinvest/cv4pve-api-javascript/pull/22))
- A login that needs a second factor and has no code throws `PveResultException`: it returned `true` with a ticket that could not be used ([#20](https://github.com/Corsinvest/cv4pve-api-javascript/pull/20))
- A body that is not JSON (the page of a proxy, another service on that port) no longer rejects: the call resolves with a `Result` that keeps the HTTP status (a success becomes 502) and shows the start of the body in `reasonPhrase` ([#21](https://github.com/Corsinvest/cv4pve-api-javascript/pull/21))
- `getExitStatusTask` returns `null` for a task still running, it was `undefined` ([#21](https://github.com/Corsinvest/cv4pve-api-javascript/pull/21))
- `taskIsRunning` and `getExitStatusTask` throw `PveResultException` with the HTTP status and the Proxmox VE error when the status of the task cannot be read, instead of a `TypeError` ([#20](https://github.com/Corsinvest/cv4pve-api-javascript/pull/20))

### Changed
- Indexed parameters (`netN`, `scsiN`, ...) are typed `Object<number, string>` instead of `Array`: with the old typings a TypeScript call that passed `{0: "..."}` was a type error ([#22](https://github.com/Corsinvest/cv4pve-api-javascript/pull/22))
- `waitForTaskToFinish` makes one check at a time and returns `true` when the task is finished, also when the last check came after the timeout ([#20](https://github.com/Corsinvest/cv4pve-api-javascript/pull/20))
- Workflows: permissions and job timeouts declared; the package is published with Node 22, required by the latest npm ([#19](https://github.com/Corsinvest/cv4pve-api-javascript/pull/19), [#23](https://github.com/Corsinvest/cv4pve-api-javascript/pull/23))

### Fixed
- Indexed parameters were never sent: `addIndexedParameter` read the parameters instead of the values, so `createVm` with `netN` sent `netvmid` and no `net0`. It affected `netN`, `scsiN`, `ideN`, `sataN`, `virtioN`, `mpN`, `linkN` and every other indexed parameter ([#22](https://github.com/Corsinvest/cv4pve-api-javascript/pull/22))
- Login with a second factor never worked on Proxmox VE 7 and later: the response to the challenge is now sent in a second call with `tfa-challenge`; a code without a type is sent as `totp:<code>` ([#20](https://github.com/Corsinvest/cv4pve-api-javascript/pull/20))
- `login("user@realm", password)` sent the realm `pam` with the full name as user: the realm is read from the part after the last `@` ([#21](https://github.com/Corsinvest/cv4pve-api-javascript/pull/21))
- A failed login kept the ticket of the previous one, and an answer without a ticket was reported as a successful login ([#21](https://github.com/Corsinvest/cv4pve-api-javascript/pull/21))
- Debug log: the ticket and the CSRF token of the login answer, the value of a new API token, `tfa-challenge` and the query string of GET and DELETE requests were printed in clear ([#20](https://github.com/Corsinvest/cv4pve-api-javascript/pull/20), [#21](https://github.com/Corsinvest/cv4pve-api-javascript/pull/21))
- Crash on a body that is the literal `null`: the promise never settled ([#21](https://github.com/Corsinvest/cv4pve-api-javascript/pull/21))
- A task id that is not valid (null, empty, not a UPID) gave a `TypeError`: now a `PveResultException` before any request ([#21](https://github.com/Corsinvest/cv4pve-api-javascript/pull/21))
- PNG response type was not usable: the request goes to `/api2/png`, the bytes are returned as a data URI, an error answer keeps its status and reason, login and task status are always read as JSON ([#21](https://github.com/Corsinvest/cv4pve-api-javascript/pull/21))
- `Result.methodType` was always `undefined` ([#21](https://github.com/Corsinvest/cv4pve-api-javascript/pull/21))
