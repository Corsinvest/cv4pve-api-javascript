/*
 * SPDX-FileCopyrightText: Copyright Corsinvest Srl
 * SPDX-License-Identifier: MIT
 */

// The TypeScript typings of the package (dist/) come from the JSDoc of src/. This test builds
// them as `npm run prepare` does, then compiles test/typings/usage.ts, the calls of a TypeScript
// user, against them: nothing is run. Run with: npm test

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const root = path.join(__dirname, "..");

function tsc(...args) {
  const compiled = spawnSync(process.execPath, [require.resolve("typescript/bin/tsc"), ...args], {
    cwd: root,
    encoding: "utf8",
  });
  assert.equal(compiled.status, 0, "\n" + compiled.stdout + compiled.stderr);
}

test("the calls of a TypeScript user compile, the wrong ones do not", () => {
  // the typings, as they are published
  tsc();

  tsc(
    "--noEmit",
    "--strict",
    "--target",
    "ES2022",
    "--module",
    "commonjs",
    "--moduleResolution",
    "node",
    path.join("test", "typings", "usage.ts")
  );
});
