/*
 * SPDX-FileCopyrightText: Copyright Corsinvest Srl
 * SPDX-License-Identifier: MIT
 */

// Compiled by test/typings.test.js, never run: the calls a TypeScript user writes must compile,
// and the wrong ones must not. A line marked @ts-expect-error fails the test when it compiles.

import { PveClient, PveResultException, ResponseType, Result } from "../../dist/src/index";

async function usage(client: PveClient) {
  // connection
  client.apiToken = "automation@pve!app=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
  client.timeout = 30000;
  client.validateCertificate = true;
  client.logEnabled = false;
  client.responseType = ResponseType.JSON;
  const logged: boolean = await client.login("root@pam", "password");
  await client.login("root", "password", "pam", "123456");

  // the optional parameters can be left out
  const vm = client.nodes.get("pve01").qemu.get(100);
  const result: Result = await client.cluster.resources.resources();
  await client.cluster.resources.resources("vm");
  await vm.status.start.vmStart();
  await vm.status.shutdown.vmShutdown(undefined, undefined, undefined, 120);
  await vm.snapshot.snapshot("before-update");
  await vm.snapshot.snapshot("before-update", "Before the update", true);
  await vm.snapshot.get("before-update").delsnapshot();
  await vm.destroyVm(undefined, true);
  await client.nodes.get("pve01").qemu.createVm(100);
  await client.nodes.get("pve01").lxc.get(200).config.vmConfig();
  await vm.clone.cloneVm(121, undefined, undefined, undefined, true, "web02");

  // an indexed parameter is an object by index
  const names = { 0: "model=virtio,bridge=vmbr0" };
  const parameters = {};
  client.addIndexedParameter(parameters, "net", names);

  // raw calls
  await client.get("/version");
  await client.set("/nodes/pve01/qemu/100/config", { cores: 4, "force-cpu": "host" });
  await client.create("/nodes/pve01/qemu/100/status/start");
  await client.delete("/nodes/pve01/qemu/100/snapshot/before-update", { force: true });

  // the result
  const status: number = result.statusCode;
  const reason: string = result.reasonPhrase;
  const success: boolean = result.isSuccessStatusCode;
  const inError: boolean = result.responseInError;
  const error: string = result.error;
  const data = result.response.data;
  const last: Result = client.lastResult;

  // tasks
  const upid = "UPID:pve01:0012A3F4:05C1B2D3:6720F1A0:qmstart:100:root@pam:";
  const finished: boolean = await client.waitForTaskToFinish(upid, 1000, 60000);
  const running: boolean = await client.taskIsRunning(upid);
  const exitStatus: string | null = await client.getExitStatusTask(upid);
  const node: string = PveClient.getNodeFromTask(upid);

  try {
    await client.taskIsRunning(upid);
  } catch (e) {
    if (e instanceof PveResultException) {
      const failed: Result | null = e.result;
    }
  }

  // what must not compile

  // @ts-expect-error a required parameter is missing
  await vm.snapshot.snapshot();

  // @ts-expect-error the parameters are positional: an object is not the first one
  await vm.config.updateVm({ memory: 4096 });

  // @ts-expect-error a number is not a string
  await vm.snapshot.snapshot(100);

  // @ts-expect-error the method does not exist
  await vm.status.start.start();
}
