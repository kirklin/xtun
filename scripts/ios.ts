// Runs the tests built for the iOS Simulator on this Mac: the unit tests inside a simulated
// iPhone, and the device tests on real utun interfaces. Needs Xcode with an iOS runtime, and
// the source of Rust's standard library (`rustup component add rust-src`), from which the
// standard library for the simulator is built.
//
//   node scripts/ios.ts            unit tests and device tests
//   node scripts/ios.ts <filter>   only the device tests whose names contain <filter>
//
// A program in a simulator runs as the user, who may not make a utun interface. The device
// tests therefore run as root, as programs of the simulator's runtime outside a simulated
// iPhone: the script asks for the administrator password once for them.

import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { features } from "./linux.ts";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..");
export const target = process.arch === "arm64" ? "aarch64-apple-ios-sim" : "x86_64-apple-ios";

interface Run {
  code: number;
  out: string;
  err: string;
}

function run(command: string, args: string[], options: { cwd?: string; env?: NodeJS.ProcessEnv } = {}): Run {
  const result = spawnSync(command, args, { encoding: "utf8", maxBuffer: 256 * 1024 * 1024, ...options });
  if (result.error) {
    throw result.error;
  }
  return { code: result.status ?? -1, out: (result.stdout ?? "").trim(), err: (result.stderr ?? "").trim() };
}

function must(command: string, args: string[]): string {
  const result = run(command, args);
  if (result.code !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed:\n${result.out}\n${result.err}`);
  }
  return result.out;
}

/// Builds the test programs: the unit tests, and the device tests last.
function build(): { units: string[]; devices: string } {
  const rustup = `${process.env.HOME}/.cargo/bin`;
  // The compiler of rustup comes first: it builds the standard library from its source, which
  // a stable compiler does only when told that it may.
  const env = { ...process.env, PATH: `${rustup}:${process.env.PATH}`, RUSTC_BOOTSTRAP: "1" };
  const programs: string[] = [];
  const builds = [
    ["-p", "xtun-wire", "--lib"],
    [...features.split(" "), "--lib"],
    [...features.split(" "), "--test", "device"],
  ];
  for (const selection of builds) {
    const listing = run(
      `${rustup}/cargo`,
      ["test", "--release", "-Zbuild-std", "--target", target, ...selection, "--no-run", "--message-format=json"],
      { cwd: repo, env },
    );
    if (listing.code !== 0) {
      throw new Error(`building the tests failed:\n${listing.err}`);
    }
    for (const line of listing.out.split("\n")) {
      const message = JSON.parse(line);
      if (message.reason === "compiler-artifact" && message.executable) {
        programs.push(message.executable as string);
      }
    }
  }
  const devices = programs.pop();
  if (devices === undefined || programs.length !== 2) {
    throw new Error("the test programs were not built");
  }
  return { units: programs, devices };
}

export interface Runtime {
  name: string;
  identifier: string;
  version: string;
  /// Where the runtime's own system files are.
  runtimeRoot: string;
  platform: string;
  isAvailable: boolean;
}

/// The newest iOS runtime that is installed.
export function runtime(): Runtime {
  const all = JSON.parse(must("xcrun", ["simctl", "list", "runtimes", "-j"])).runtimes as Runtime[];
  const usable = all
    .filter((one) => one.platform === "iOS" && one.isAvailable)
    .sort((a, b) => a.version.localeCompare(b.version, undefined, { numeric: true }));
  if (usable.length === 0) {
    throw new Error("Xcode has no iOS runtime");
  }
  return usable[usable.length - 1];
}

/// Runs the unit tests inside a simulated iPhone of the runtime, which is started for them
/// unless it runs already. Returns whether all passed.
export function inSimulator(chosen: Runtime, programs: string[]): boolean {
  const devices = JSON.parse(must("xcrun", ["simctl", "list", "devices", "-j"])).devices[chosen.identifier] as {
    udid: string;
    name: string;
    state: string;
    isAvailable: boolean;
  }[];
  const phone = devices.find((one) => one.isAvailable && one.name.startsWith("iPhone"));
  if (phone === undefined) {
    throw new Error(`${chosen.name} has no iPhone to simulate`);
  }
  const started = phone.state !== "Booted";
  if (started) {
    must("xcrun", ["simctl", "boot", phone.udid]);
  }
  must("xcrun", ["simctl", "bootstatus", phone.udid]);
  console.log(`${phone.name}, ${chosen.name}`);
  let passed = true;
  try {
    for (const program of programs) {
      passed = spawnSync("xcrun", ["simctl", "spawn", phone.udid, program], { stdio: "inherit" }).status === 0 && passed;
    }
  } finally {
    if (started) {
      must("xcrun", ["simctl", "shutdown", phone.udid]);
    }
  }
  return passed;
}

function main(): void {
  const [mode, ...rest] = process.argv.slice(2);
  if (mode === "--privileged") {
    // A program of the simulator finds its system libraries under the runtime's files. The
    // system's own tools, which the tests call, take no notice of the variable.
    const [root, program, filter] = rest;
    const status = spawnSync(program, ["--ignored", "--test-threads=1", "--nocapture", ...(filter === "" ? [] : [filter])], {
      stdio: "inherit",
      cwd: repo,
      env: { ...process.env, DYLD_ROOT_PATH: root },
    }).status;
    process.exit(status ?? 1);
  }
  const filter = mode ?? "";
  const { units, devices } = build();
  const chosen = runtime();
  const unitsPassed = filter !== "" || inSimulator(chosen, units);
  console.log("built; the device tests run as root and ask for the password");
  const result = spawnSync("sudo", [process.execPath, fileURLToPath(import.meta.url), "--privileged", chosen.runtimeRoot, devices, filter], {
    stdio: "inherit",
  });
  process.exit(result.status === 0 && unitsPassed ? 0 : 1);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
