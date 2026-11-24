// Runs the tests on real OpenBSD interfaces inside a virtual machine.
//
//   node scripts/vm/openbsd.ts            unit tests of the wire crate and device tests
//   node scripts/vm/openbsd.ts <filter>   only the device tests whose names contain <filter>

import { existsSync, renameSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import process from "node:process";
import { features } from "../linux.ts";
import {
  boot,
  download,
  drive,
  guestProxy,
  home,
  key,
  type Machine,
  must,
  openConsole,
  overlay,
  pushSource,
  serve,
  ssh,
  sshMust,
  sshShown,
  stop,
  type System,
  waitForExit,
  waitForSsh,
} from "./common.ts";

const release = "8.0";
const mirror = "https://cdn.openbsd.org/pub/OpenBSD";
/// The installer with the sets of the release on it, as the project publishes it.
const installer = {
  url: `${mirror}/${release}/arm64/install80.img`,
  sha256: "941a21c43cf5b4f58435f97e34541c125dedcda1461553246b551e79ca9a693f",
};
/// The port of this host that reaches the guest's SSH server.
const port = 2233;
const directory = home("openbsd");
const source = "/root/xtun";

/// One file system for everything, so that the toolchain and the build share the whole disk.
const layout = ["/\t8G-*\t100%", "swap\t2G", ""].join("\n");

/// What the installer asks and has no usable default for. The fresh disk is the first drive and
/// the installer's image the second; the sets come from that image, which the digest above
/// vouches for, so the installer goes on without their signature.
function answers(template: string): string {
  return [
    "System hostname = xtun",
    "Password for root account = *************",
    `Public ssh key for root account = ${key().open}`,
    "Start sshd(8) by default = yes",
    "Setup a user = no",
    "Allow root ssh login = prohibit-password",
    "What timezone are you in = UTC",
    "Which disk is the root disk = sd0",
    `URL to autopartitioning template for disklabel = ${template}`,
    "Location of sets = disk",
    "Is the disk partition already mounted = no",
    "Which disk contains the install media = sd1",
    `Pathname to the sets = ${release}/arm64`,
    "Set name(s) = -game* -x*",
    "Continue without verification = yes",
    "",
  ].join("\n");
}

/// Installs the release onto `disk`: the installer boots from its image, is told on the serial
/// console to install by itself and where its answers are, and restarts when it is done, which
/// ends the machine.
async function install(disk: string): Promise<void> {
  const image = resolve(directory, "install80.img");
  download(installer.url, image, installer.sha256);
  must("qemu-img", ["create", "-f", "qcow2", disk, "32G"]);
  const texts: Record<string, string> = { disklabel: layout };
  const served = await serve(texts);
  texts["install.conf"] = answers(served.url("disklabel"));
  const socket = resolve(directory, "console.sock");
  const machine = boot({
    arch: "aarch64",
    disk,
    port,
    log: resolve(directory, "install.log"),
    console: socket,
    extra: [...drive(image, "raw", true), "-no-reboot"],
  });
  try {
    const serial = await openConsole(socket);
    await serial.expect(/\(I\)nstall, \(U\)pgrade, \(A\)utoinstall or \(S\)hell\?/, 300);
    serial.send("a\n");
    await serial.expect(/Response file location\?/, 120);
    serial.send(`${served.url("install.conf")}\n`);
    await serial.expect(/CONGRATULATIONS!/, 1800);
    serial.close();
    if (!waitForExit(machine, 120)) {
      throw new Error("the installer did not restart the machine");
    }
  } finally {
    stop(machine);
    served.close();
    rmSync(socket, { force: true });
  }
}

/// Boots the installed system once, lets what it does on its first start finish, and adds the
/// Rust toolchain from the project's packages. Returns the version of the compiler.
function provision(disk: string): string {
  const log = resolve(directory, "provision.log");
  const machine = boot({ arch: "aarch64", disk, port, log });
  try {
    waitForSsh(port, 600, log);
    sshMust(port, "until pgrep -qx getty; do sleep 1; done");
    sshMust(port, `echo ${mirror} > /etc/installurl`);
    const proxy = guestProxy();
    const through = proxy === undefined ? "" : `env http_proxy=${proxy} https_proxy=${proxy} `;
    if (sshShown(port, `${through}pkg_add -I rust`) !== 0) {
      throw new Error("installing the Rust toolchain failed");
    }
    const rust = sshMust(port, "rustc --version && cargo --version");
    sshMust(port, "while pgrep -qf '[r]eorder_kernel'; do sleep 1; done");
    ssh(port, "shutdown -p now");
    if (!waitForExit(machine, 180)) {
      throw new Error("the guest did not power off");
    }
    return rust;
  } finally {
    stop(machine);
  }
}

/// The machine every run starts from: the release installed, root let in with the key, and a
/// Rust toolchain. Made once.
async function prepared(): Promise<string> {
  const image = resolve(directory, "prepared.qcow2");
  if (!existsSync(image)) {
    const disk = resolve(directory, "installing.qcow2");
    rmSync(disk, { force: true });
    console.log(`installing OpenBSD ${release}`);
    await install(disk);
    console.log(`prepared with ${provision(disk).replace("\n", ", ")}`);
    renameSync(disk, image);
  }
  return image;
}

function machine(disk: string, log: string): Machine {
  return { arch: "aarch64", disk, port, log };
}

export const system: System = { directory, port, prepare: prepared, machine, bootSeconds: 300, shell: "" };

async function main(): Promise<void> {
  const filter = process.argv[2] ?? "";
  const disk = resolve(directory, "run.qcow2");
  overlay(await prepared(), disk);
  const log = resolve(directory, "run.log");
  const guest = boot(machine(disk, log));
  let status = 1;
  try {
    waitForSsh(port, system.bootSeconds, log);
    pushSource(port, source);
    const script = [
      "set -e",
      `cd ${source}`,
      "uname -srm",
      filter === "" ? "cargo test --release --offline -p xtun-wire --lib" : "true",
      `cargo test --release --offline --no-fail-fast ${features} --test device --test tap -- --ignored --test-threads=1 --nocapture ${filter}`,
    ].join("\n");
    status = sshShown(port, script);
  } finally {
    stop(guest);
    rmSync(disk, { force: true });
  }
  process.exit(status);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  await main();
}
