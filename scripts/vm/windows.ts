// Runs the tests on a Windows machine over SSH: the unit tests, and the device tests on real
// Wintun and TAP-Windows adapters. The machine has an SSH server that lets the key of
// `scripts/vm/common.ts` in as an administrator, a Rust toolchain and the Microsoft C++ build
// tools; this script brings the rest along: `wintun.dll`, the TAP-Windows6 driver, which it adds
// to the driver store once, and the source tree with its dependencies.
//
//   node scripts/vm/windows.ts <user@address> [filter]
//
// While the tests run, a firewall rule lets inbound traffic to the test subnets through, so that
// a connection through an adapter reaches its listener; the rule goes when the run ends.

import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import process from "node:process";

import { features } from "../linux.ts";
import { download, home, key, must, run, sourceArchive } from "./common.ts";

const wintun = {
  url: "https://www.wintun.net/builds/wintun-0.14.1.zip",
  // As www.wintun.net lists it.
  sha256: "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51",
};
const tapWindows = {
  url: "https://github.com/OpenVPN/tap-windows6/releases/download/9.27.0/dist.win10.zip",
  // The release lists no digest: this is the digest of the file that release served.
  sha256: "36e2609b7ceefedcb978ce5c48caf9e0e5af83423717c4e2e3c1d7ebca8f62a5",
};
/// The name of the firewall rule that the run adds and removes.
const rule = "xtun-tests";
/// The addresses of the test subnets in `tests/windows.rs`.
const testAddresses = "10.160.0.0/11,fd00::/8";

function sshArgs(target: string): string[] {
  return [
    "-i", key().secret,
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "LogLevel=ERROR",
    "-o", "ConnectTimeout=8",
    "-o", "ServerAliveInterval=30",
    "-o", "IdentitiesOnly=yes",
    "-o", "BatchMode=yes",
    target,
  ];
}

/// Runs a command line of `cmd.exe` in the guest; it has to succeed.
function sshMust(target: string, command: string, input?: Buffer): string {
  const result = run("ssh", [...sshArgs(target), command], { input });
  if (result.code !== 0) {
    throw new Error(`in the guest, ${command} failed:\n${result.out}\n${result.err}`);
  }
  return result.out;
}

/// Runs a command line of `cmd.exe` in the guest, showing what it prints as it comes. Returns
/// its status.
function sshShown(target: string, command: string): number {
  return spawnSync("ssh", [...sshArgs(target), command], { stdio: "inherit" }).status ?? -1;
}

/// Runs PowerShell in the guest; it has to succeed.
function powershell(target: string, script: string): string {
  return sshMust(target, `powershell -NoProfile -NonInteractive -Command "${script}"`);
}

/// A command line of `cmd.exe` that empties `directory` and unpacks the archive on standard input
/// into it. Without the parentheses, `if` would take everything after its condition as its own.
function fresh(directory: string): string {
  return `(if exist "${directory}" rmdir /s /q "${directory}") & mkdir "${directory}" && tar -xf - -C "${directory}"`;
}

/// `wintun.dll` for the guest's processor and the TAP-Windows6 driver, as one archive.
function payload(directory: string, arch: "arm64" | "amd64"): Buffer {
  const wintunZip = resolve(directory, "wintun-0.14.1.zip");
  const tapZip = resolve(directory, "tap-windows6-9.27.0-dist.win10.zip");
  download(wintun.url, wintunZip, wintun.sha256);
  download(tapWindows.url, tapZip, tapWindows.sha256);
  const staging = resolve(directory, "payload");
  rmSync(staging, { recursive: true, force: true });
  mkdirSync(resolve(staging, "tap"), { recursive: true });
  must("unzip", ["-q", "-j", "-o", wintunZip, `wintun/bin/${arch}/wintun.dll`, "-d", staging]);
  must("unzip", ["-q", "-j", "-o", tapZip, `dist.win10/${arch}/OemVista.inf`, `dist.win10/${arch}/tap0901.cat`, `dist.win10/${arch}/tap0901.sys`, "-d", resolve(staging, "tap")]);
  const archive = resolve(directory, "payload.tar");
  must("tar", ["-cf", archive, "--no-xattrs", "--no-mac-metadata", "-C", staging, "wintun.dll", "tap"]);
  return readFileSync(archive);
}

/// A Windows machine reached over SSH, and where a run keeps its files there.
interface Guest {
  target: string;
  arch: "arm64" | "amd64";
  /// The source tree with its dependencies.
  source: string;
  /// `wintun.dll` and the files of the TAP-Windows6 driver.
  tools: string;
  /// What cargo builds. Kept between runs, so that a run builds only what changed.
  targetDir: string;
}

/// The machine at `target`, as `user@address`.
function guest(target: string | undefined, usage: string): Guest {
  if (target === undefined || !target.includes("@")) {
    throw new Error(`usage: ${usage}`);
  }
  const profile = sshMust(target, "echo %USERPROFILE%").trim();
  const arch = sshMust(target, "echo %PROCESSOR_ARCHITECTURE%").trim() === "ARM64" ? "arm64" : "amd64";
  console.log(`${target}: ${profile}, ${arch}; ${sshMust(target, "rustc --version").trim()}`);
  return { target, arch, source: `${profile}\\xtun-test`, tools: `${profile}\\xtun-vm`, targetDir: `${profile}\\xtun-target` };
}

/// Puts `wintun.dll` and the files of the TAP-Windows6 driver into the guest.
function pushTools(machine: Guest): void {
  sshMust(machine.target, fresh(machine.tools), payload(home("windows"), machine.arch));
}

/// Puts the source tree and its dependencies into the guest, replacing what is there.
function pushSource(machine: Guest): void {
  sshMust(machine.target, fresh(machine.source), sourceArchive());
}

/// The start of a command line of `cmd.exe` that runs cargo in the guest's source tree.
function inSource(machine: Guest): string {
  return `cd /d "${machine.source}" && set CARGO_TARGET_DIR=${machine.targetDir}&& `;
}

/// Runs `action` while a firewall rule lets inbound traffic to `addresses` through, so that a
/// connection through an adapter reaches its listener. The rule goes when the action ends.
function withFirewall<T>(machine: Guest, addresses: string, action: () => T): T {
  powershell(machine.target, `Remove-NetFirewallRule -Name ${rule} -ErrorAction SilentlyContinue; ` +
    `New-NetFirewallRule -Name ${rule} -DisplayName ${rule} -Direction Inbound -Action Allow -Profile Any -LocalAddress ${addresses} | Out-Null`);
  try {
    return action();
  } finally {
    powershell(machine.target, `Remove-NetFirewallRule -Name ${rule}`);
  }
}

function main(): void {
  const [target, filter = ""] = process.argv.slice(2);
  const machine = guest(target, "node scripts/vm/windows.ts <user@address> [filter]");
  pushTools(machine);
  const drivers = sshMust(machine.target, "pnputil /enum-drivers");
  if (!/oemvista\.inf/i.test(drivers)) {
    console.log("adding the TAP-Windows6 driver to the driver store");
    sshMust(machine.target, `pnputil /add-driver "${machine.tools}\\tap\\OemVista.inf" /install`);
  }
  pushSource(machine);
  const status = withFirewall(machine, testAddresses, () => {
    const cargo = `${inSource(machine)}set XTUN_WINTUN=${machine.tools}\\wintun.dll&& `;
    const unit = filter === ""
      ? `cargo test --release --offline -p xtun-wire --lib && cargo test --release --offline ${features} --lib && `
      : "";
    return sshShown(
      machine.target,
      `${cargo}${unit}cargo test --release --offline --no-fail-fast ${features} --test windows -- --ignored --test-threads=1 --nocapture ${filter}`,
    );
  });
  process.exit(status);
}

main();
