/*
 * SPDX-FileCopyrightText: Copyright Corsinvest Srl
 * SPDX-License-Identifier: MIT
 */

// Tests on a real Proxmox VE. Connection from the environment: PVE_HOST, PVE_PORT (default 8006),
// PVE_API_TOKEN, PVE_TEST_VMID. They only read, except on the QEMU test VM PVE_TEST_VMID, where
// they change the description and create and delete a snapshot. Without PVE_HOST and
// PVE_API_TOKEN every test is skipped; without PVE_TEST_VMID the tests on the VM are skipped.
// Run with: npm run test:live

const test = require("node:test");
const assert = require("node:assert/strict");
const { PveClient, PveResultException, ResponseType, Result } = require("../src/index.js");

const host = process.env.PVE_HOST;
const apiToken = process.env.PVE_API_TOKEN;
const testVmId = process.env.PVE_TEST_VMID;
const skip = host && apiToken ? false : "PVE_HOST and PVE_API_TOKEN not set";

function newClient(token = apiToken) {
  const client = new PveClient(host, Number(process.env.PVE_PORT) || 8006);
  client.timeout = 10000;
  client.apiToken = token;
  return client;
}

const client = newClient();

function ok(result) {
  assert.ok(
    result.isSuccessStatusCode,
    `${result.statusCode} ${result.reasonPhrase} ${result.requestResource}`
  );
  assert.equal(result.responseInError, false, JSON.stringify(result.response?.errors));
  return result;
}

async function runTask(result) {
  const upid = ok(result).response.data;
  assert.match(String(upid), /^UPID:/, "not a task");
  // false when the time ran out with the task still running
  assert.equal(await client.waitForTaskToFinish(upid, 500, 120000), true, `task still running`);
  assert.equal(await client.getExitStatusTask(upid), "OK");
  return upid;
}

async function firstNode() {
  return ok(await client.nodes.index()).response.data[0].node;
}

/** The test VM, or null (and the test is skipped) when PVE_TEST_VMID is not a QEMU VM. */
async function testVm(t) {
  let node = null;
  if (testVmId) {
    for (const vm of ok(await client.cluster.resources.resources("vm")).response.data) {
      if (String(vm.vmid) === String(testVmId) && vm.type === "qemu") {
        node = vm.node;
      }
    }
  }
  if (node === null) {
    t.skip("PVE_TEST_VMID not set or not a QEMU VM of the cluster");
    return null;
  }
  return { node, vm: client.nodes.get(node).qemu.get(testVmId) };
}

test("version", { skip }, async () => {
  const data = ok(await client.version.version()).response.data;

  assert.match(data.version, /^\d+\.\d+/);
  assert.ok(data.release, "release is missing");
});

test("nodes and their status", { skip }, async () => {
  const nodes = ok(await client.nodes.index()).response.data;
  assert.ok(nodes.length > 0, "no nodes");

  for (const node of nodes) {
    if (node.status === "online") {
      const status = ok(await client.nodes.get(node.node).status.status()).response.data;
      assert.ok(status.uptime > 0, `uptime of ${node.node}`);
    }
  }
});

test("cluster resources filtered by type", { skip }, async () => {
  for (const resource of ok(await client.cluster.resources.resources("vm")).response.data) {
    assert.ok(["qemu", "lxc"].includes(resource.type), resource.type);
  }
});

test("qemu list of every node", { skip }, async () => {
  for (const node of ok(await client.nodes.index()).response.data) {
    if (node.status === "online") {
      for (const vm of ok(await client.nodes.get(node.node).qemu.vmlist()).response.data) {
        assert.ok(vm.vmid > 0, "vmid");
      }
    }
  }
});

test("a resource that does not exist is an error", { skip }, async () => {
  const result = await client.nodes.get("node-that-does-not-exist").qemu.vmlist();

  assert.equal(result.isSuccessStatusCode, false);
  assert.ok(result.statusCode >= 400, String(result.statusCode));
});

test("a wrong API token is rejected", { skip }, async () => {
  const other = newClient("root@pam!none=00000000-0000-0000-0000-000000000000");

  assert.equal((await other.nodes.index()).statusCode, 401);
});

test("the reason of an error is the message of Proxmox VE", { skip }, async () => {
  const result = await client.get(`/nodes/${await firstNode()}/qemu/999999/config`);

  assert.equal(result.isSuccessStatusCode, false);
  assert.match(result.reasonPhrase, /does not exist/);
  assert.equal(result.responseInError, false);
});

test("a refused parameter is listed in the errors", { skip }, async (t) => {
  const target = await testVm(t);
  if (!target) return;

  const result = await client.set(`/nodes/${target.node}/qemu/${testVmId}/config`, {
    memory: "abc",
  });

  assert.equal(result.statusCode, 400);
  assert.equal(result.responseInError, true);
  assert.ok("memory" in result.response.errors, JSON.stringify(result.response.errors));
});

test("the chart of a node is a PNG image", { skip }, async () => {
  const node = await firstNode();
  const png = newClient();
  png.responseType = ResponseType.PNG;

  const result = await png.nodes.get(node).rrd.rrd("cpu", "hour");

  assert.ok(result.isSuccessStatusCode, `${result.statusCode} ${result.reasonPhrase}`);
  const prefix = "data:image/png;base64,";
  assert.ok(result.response.startsWith(prefix), "not a data URI");
  // signature of a PNG file
  const bytes = Buffer.from(result.response.substring(prefix.length), "base64");
  assert.deepEqual([...bytes.subarray(0, 4)], [0x89, 0x50, 0x4e, 0x47]);
});

test("a self-signed certificate is refused when validated", { skip }, async (t) => {
  const strict = newClient();
  strict.validateCertificate = true;

  let result;
  try {
    result = await strict.version.version();
  } catch (error) {
    // no answer: the request rejects with the error of Node
    assert.equal(typeof error.code, "string", error.message);
    assert.notEqual(error.code, "ETIMEDOUT");
    return;
  }
  assert.ok(result.isSuccessStatusCode, `${result.statusCode} ${result.reasonPhrase}`);
  t.skip("the node has a trusted certificate");
});

test("test VM: configuration and status", { skip }, async (t) => {
  const target = await testVm(t);
  if (!target) return;

  assert.ok(ok(await target.vm.config.vmConfig()).response.data.digest, "digest is missing");
  assert.equal(
    String(ok(await target.vm.status.current.vmStatus()).response.data.vmid),
    String(testVmId)
  );
});

test("test VM: the description is changed and restored", { skip }, async (t) => {
  const target = await testVm(t);
  if (!target) return;

  const resource = `/nodes/${target.node}/qemu/${testVmId}/config`;
  const read = async () => ok(await target.vm.config.vmConfig()).response.data.description ?? "";
  const before = await read();
  const value = `cv4pve-api-javascript live test ${Date.now()} àèì`;

  try {
    ok(await client.set(resource, { description: value }));
    assert.equal((await read()).trim(), value);
  } finally {
    ok(
      before === ""
        ? await client.set(resource, { delete: "description" })
        : await client.set(resource, { description: before })
    );
  }

  assert.equal(await read(), before);
});

test("test VM: an indexed parameter is set and removed", { skip }, async (t) => {
  const target = await testVm(t);
  if (!target) return;

  const { vm } = target;
  const config = async () => ok(await vm.config.vmConfig()).response.data;
  // a free ipconfigN: text of the configuration, no device is added to the VM
  const before = await config();
  let index = 0;
  while (`ipconfig${index}` in before) index++;
  const key = `ipconfig${index}`;

  // updateVm has about ninety parameters: ipconfigN is placed by its name
  const names = vm.config.updateVm
    .toString()
    .match(/\(([^)]*)\)/)[1]
    .split(",")
    .map((name) => name.trim());
  assert.ok(names.includes("ipconfigN"), "updateVm has no parameter ipconfigN");
  const values = { ipconfigN: { [index]: "ip=dhcp" } };

  try {
    ok(await vm.config.updateVm(...names.map((name) => values[name])));
    assert.equal((await config())[key], "ip=dhcp");
  } finally {
    ok(await client.set(`/nodes/${target.node}/qemu/${testVmId}/config`, { delete: key }));
  }

  assert.equal(key in (await config()), false);
});

test("test VM: a snapshot is created, updated and deleted", { skip }, async (t) => {
  const target = await testVm(t);
  if (!target) return;

  const { vm } = target;
  const name = "livetest" + Date.now();
  const listed = async () =>
    ok(await vm.snapshot.snapshotList()).response.data.some((snapshot) => snapshot.name === name);

  const upid = await runTask(
    await vm.snapshot.snapshot(name, "created by cv4pve-api-javascript", false)
  );
  try {
    assert.equal(await client.taskIsRunning(upid), false);
    assert.equal(await listed(), true, "snapshot not listed");

    ok(
      await vm.snapshot.get(name).config.updateSnapshotConfig("updated by cv4pve-api-javascript")
    );
    const config = ok(await vm.snapshot.get(name).config.getSnapshotConfig()).response.data;
    assert.equal(config.description.trim(), "updated by cv4pve-api-javascript");
  } finally {
    // DELETE with a parameter in the query string
    await runTask(await vm.snapshot.get(name).delsnapshot(false));
  }

  assert.equal(await listed(), false);
});

test("a task that does not exist cannot be read", { skip }, async () => {
  const upid = `UPID:${await firstNode()}:00000001:00000001:00000001:qmstart:999999:root@pam:`;

  await assert.rejects(
    () => client.taskIsRunning(upid),
    (error) =>
      error instanceof PveResultException &&
      error.result instanceof Result &&
      error.message.startsWith(`Read status of task '${upid}' failed`)
  );
});
