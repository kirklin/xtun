// Runs the device tests on this Mac. Builds as the current user, then asks for the
// administrator password once and runs the tests as root.
//
//   node scripts/macos.ts

import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..");

/// The test programs that run on real interfaces.
const suites = ["device", "tap"];

function build(): string[] {
  const cargo = `${process.env.HOME}/.cargo/bin/cargo`;
  const targets = suites.flatMap((suite) => ["--test", suite]);
  const listing = spawnSync(
    cargo,
    ["test", "--release", "--features", "async-io,futures", ...targets, "--no-run", "--message-format=json"],
    { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, cwd: repo },
  );
  if (listing.status !== 0) {
    throw new Error(`building the tests failed:\n${listing.stderr}`);
  }
  const artifacts = listing.stdout.trim().split("\n").map((line) => JSON.parse(line));
  return suites.map((suite) => {
    const found = artifacts.find((message) => message.reason === "compiler-artifact" && message.target?.name === suite && message.executable);
    if (!found) {
      throw new Error(`the test program ${suite} was not built`);
    }
    return found.executable as string;
  });
}

/// The part that runs as root: the tests, one program after another. Returns whether every
/// test passed.
function privileged(tests: string[]): boolean {
  let passed = true;
  for (const test of tests) {
    passed = spawnSync(test, ["--ignored", "--test-threads=1", "--nocapture"], { stdio: "inherit", cwd: repo }).status === 0 && passed;
  }
  return passed;
}

function main(): void {
  const [mode, ...rest] = process.argv.slice(2);
  if (mode === "--privileged") {
    process.exit(privileged(rest) ? 0 : 1);
  }
  const tests = build();
  console.log("built; the tests run as root and ask for the password");
  const result = spawnSync("sudo", [process.execPath, fileURLToPath(import.meta.url), "--privileged", ...tests], { stdio: "inherit" });
  process.exit(result.status ?? 1);
}

main();
