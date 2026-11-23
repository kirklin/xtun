// Runs the tests on an Android emulator, as root: the unit tests, and the device tests on real
// TUN and TAP interfaces. Needs the Android SDK with its emulator, a system image with Google
// APIs for this machine's processor, which lets the shell be root, and the NDK; builds with the
// Rust target for Android.
//
//   node scripts/android.ts            unit tests and device tests
//   node scripts/android.ts <filter>   only the device tests whose names contain <filter>
//
// The script makes the virtual device `xtun_test` once, starts it without a window and stops it
// when the run ends. An application reaches its interface through the network the system made
// for it; the tests reach theirs through the main routing table, which a rule puts first while
// they run, and which holds the IPv6 routes of new interfaces for that long.

import { spawn, spawnSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { features } from "./linux.ts";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..");
const sdk = process.env.ANDROID_HOME ?? `${process.env.HOME}/Library/Android/sdk`;
const adb = resolve(sdk, "platform-tools/adb");
const arm = process.arch === "arm64";
const abi = arm ? "arm64-v8a" : "x86_64";
const target = arm ? "aarch64-linux-android" : "x86_64-linux-android";
/// The oldest Android the programs run on.
const api = 24;
const device = "xtun_test";
/// The emulator's console port, which names it to adb.
const port = 5584;
const serial = `emulator-${port}`;
const guest = "/data/local/tmp/xtun";
/// The test programs that run on real interfaces.
const suites = ["device", "tap"];

interface Run {
  code: number;
  out: string;
  err: string;
}

function run(command: string, args: string[], options: { cwd?: string; input?: string; env?: NodeJS.ProcessEnv } = {}): Run {
  const result = spawnSync(command, args, { encoding: "utf8", maxBuffer: 256 * 1024 * 1024, ...options });
  if (result.error) {
    throw result.error;
  }
  return { code: result.status ?? -1, out: (result.stdout ?? "").trim(), err: (result.stderr ?? "").trim() };
}

function must(command: string, args: string[], options: { cwd?: string; input?: string; env?: NodeJS.ProcessEnv } = {}): string {
  const result = run(command, args, options);
  if (result.code !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed:\n${result.out}\n${result.err}`);
  }
  return result.out;
}

function sleep(seconds: number): void {
  spawnSync("sleep", [String(seconds)]);
}

/// The newest directory of `parent`, by version.
function newest(parent: string): string {
  const names = readdirSync(parent).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
  if (names.length === 0) {
    throw new Error(`nothing in ${parent}`);
  }
  return resolve(parent, names[names.length - 1]);
}

/// The C compiler of the NDK that links programs for the target.
function linker(): string {
  const prebuilt = resolve(newest(resolve(sdk, "ndk")), "toolchains/llvm/prebuilt");
  const tools = resolve(prebuilt, readdirSync(prebuilt)[0], "bin");
  const found = resolve(tools, `${target}${api}-clang`);
  if (!existsSync(found)) {
    throw new Error(`the NDK has no ${found}`);
  }
  return found;
}

/// The newest system image with Google APIs for this processor: its shell may be root, which
/// the shell of an image with the Play Store may not.
function systemImage(): string {
  const images = resolve(sdk, "system-images");
  const platforms = readdirSync(images)
    .filter((platform) => existsSync(resolve(images, platform, "google_apis", abi)))
    .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
  if (platforms.length === 0) {
    throw new Error(`no system image with Google APIs for ${abi} in ${images}`);
  }
  return `system-images;${platforms[platforms.length - 1]};google_apis;${abi}`;
}

/// Builds the test programs and returns where they are.
function build(): string[] {
  const rustup = `${process.env.HOME}/.cargo/bin`;
  const cargo = `${rustup}/cargo`;
  const variable = `CARGO_TARGET_${target.toUpperCase().replaceAll("-", "_")}_LINKER`;
  // The compiler of rustup comes first: only it has the target.
  const env = { ...process.env, PATH: `${rustup}:${process.env.PATH}`, [variable]: linker() };
  const programs: string[] = [];
  const builds = [
    ["-p", "xtun-wire", "--lib"],
    [...features.split(" "), "--lib"],
    [...features.split(" "), ...suites.flatMap((suite) => ["--test", suite])],
  ];
  for (const selection of builds) {
    const listing = run(cargo, ["test", "--release", "--target", target, ...selection, "--no-run", "--message-format=json"], { cwd: repo, env });
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
  return programs;
}

function shell(command: string): Run {
  return run(adb, ["-s", serial, "shell", command]);
}

/// Waits until no emulator runs the virtual device: one that is shutting down still holds it.
function waitUntilGone(): void {
  // The bracket keeps the pattern from matching pgrep itself.
  const alive = () => run("pgrep", ["-f", `[-]avd ${device}`]).code === 0;
  for (let i = 0; i < 120 && alive(); i += 1) {
    sleep(0.5);
  }
  if (alive()) {
    throw new Error(`an emulator of ${device} did not end in a minute`);
  }
}

/// Starts the emulator unless it runs already, and waits until the system is up with a root
/// shell. Returns whether it was started here.
function boot(): boolean {
  const running = must(adb, ["devices"]).includes(serial);
  if (!running) {
    // A run that just stopped the emulator may not have let go of the virtual device yet.
    waitUntilGone();
    const tools = resolve(sdk, "cmdline-tools/latest/bin");
    if (!must(resolve(sdk, "emulator/emulator"), ["-list-avds"]).split("\n").includes(device)) {
      const image = systemImage();
      console.log(`making the virtual device ${device} from ${image}`);
      // The answer declines a hardware profile of our own.
      must(resolve(tools, "avdmanager"), ["create", "avd", "--name", device, "--package", image, "--device", "pixel_6"], { input: "no\n" });
    }
    const emulator = spawn(
      resolve(sdk, "emulator/emulator"),
      ["-avd", device, "-port", String(port), "-no-window", "-no-audio", "-no-boot-anim", "-no-snapshot"],
      { stdio: "ignore", detached: true },
    );
    emulator.unref();
  }
  const booted = () => shell("getprop sys.boot_completed").out === "1";
  for (let i = 0; i < 300 && !booted(); i += 1) {
    sleep(1);
  }
  if (!booted()) {
    throw new Error("the emulator did not start in five minutes");
  }
  // adbd restarts as root; right after the system comes up it may refuse the request, which is
  // made again until the shell is root.
  for (let i = 0; i < 60 && shell("id -u").out !== "0"; i += 1) {
    run(adb, ["-s", serial, "root"]);
    run(adb, ["-s", serial, "wait-for-device"]);
    sleep(0.5);
  }
  if (shell("id -u").out !== "0") {
    throw new Error("the emulator's shell is not root");
  }
  return !running;
}

function main(): void {
  const filter = process.argv[2] ?? "";
  const programs = build();
  const started = boot();
  let status = 0;
  try {
    console.log(`Android ${shell("getprop ro.build.version.release").out}, ${shell("uname -rm").out}`);
    must(adb, ["-s", serial, "shell", `rm -rf ${guest} && mkdir -p ${guest}`]);
    for (const program of programs) {
      must(adb, ["-s", serial, "push", program, `${guest}/`]);
    }
    const rules = ["ip rule", "ip -6 rule"];
    // Android keeps the IPv6 routes of each interface in a table of the interface's own; with
    // 0 a new interface has them in the main table, as its IPv4 routes are.
    const table = "/proc/sys/net/ipv6/conf/default/accept_ra_rt_table";
    const lines = [
      `cd ${guest}`,
      "export TMPDIR=/data/local/tmp",
      ...rules.map((rule) => `${rule} add pref 1 lookup main`),
      `table=$(cat ${table})`,
      `echo 0 > ${table}`,
      "status=0",
    ];
    for (const program of programs) {
      const name = program.split("/").pop() as string;
      const onDevices = suites.some((suite) => name.startsWith(`${suite}-`));
      if (onDevices) {
        lines.push(`./${name} --ignored --test-threads=1 --nocapture ${filter} || status=1`);
      } else if (filter === "") {
        lines.push(`./${name} || status=1`);
      }
    }
    lines.push(`echo $table > ${table}`, ...rules.map((rule) => `${rule} del pref 1`), "exit $status");
    status = spawnSync(adb, ["-s", serial, "shell", lines.join("\n")], { stdio: "inherit" }).status ?? 1;
  } finally {
    if (started) {
      run(adb, ["-s", serial, "emu", "kill"]);
      waitUntilGone();
    }
  }
  process.exit(status);
}

main();
