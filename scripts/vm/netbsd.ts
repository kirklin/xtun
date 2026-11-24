// Runs the tests on real NetBSD interfaces inside a virtual machine.
//
//   node scripts/vm/netbsd.ts            unit tests of the wire crate and device tests
//   node scripts/vm/netbsd.ts <filter>   the same, with only the device tests whose names contain <filter>

import { existsSync, renameSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import process from "node:process";
import { features } from "../linux.ts";
import {
  boot,
  type Console,
  download,
  guestProxy,
  home,
  key,
  type Machine,
  must,
  openConsole,
  overlay,
  pushSource,
  ssh,
  sshMust,
  sshShown,
  stop,
  type System,
  waitForExit,
  waitForSsh,
} from "./common.ts";

const directory = home("netbsd");
/// The live image of the release for 64-bit ARM machines with UEFI, as NetBSD publishes it.
const image = {
  url: "https://cdn.netbsd.org/pub/NetBSD/NetBSD-11.1/evbarm-aarch64/binary/gzimg/arm64.img.gz",
  sha512: "c5f05c5997c351d2eb30916e17248202851d1a649cbff068348620a1c62c59837a9fa6cce5ae734221a9c24743ab88d3cb7e30506cd648b26a3d3e8ee518e379",
};
/// The binary packages pkgsrc builds for the release, where the Rust toolchain comes from.
const packages = "https://cdn.netbsd.org/pub/pkgsrc/packages/NetBSD/aarch64/11.0_2026Q3/All";
/// The image with root's key and the toolchain in it, which every run starts from.
const prepared = resolve(directory, "prepared.qcow2");
const log = resolve(directory, "console.log");
/// The port of this host that reaches the guest's SSH server.
const port = 2232;
/// Where the source tree goes in the guest.
const source = "/root/xtun";
/// sshd gives a command only the directories of users' programs; the tools that the tests and the
/// preparation call are in the system's ones.
const path = "PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/pkg/sbin:/usr/pkg/bin";

/// The network device comes without its control queue. NetBSD's driver waits for the answer to
/// a command on that queue with the lock of the network code held, and when it misses the
/// answer's interrupt, soft interrupts pile up behind the lock until the kernel panics over them
/// (NetBSD PR kern/58715). Without the queue the driver sends no commands.
const network = ["-global", "virtio-net-pci.ctrl_vq=off"];

function machine(disk: string, console?: string): Machine {
  return { arch: "aarch64", disk, port, log, memory: 8192, console, extra: network };
}

/// Types `command` at root's shell on the console and waits until it has succeeded.
async function typed(serial: Console, command: string, seconds: number): Promise<void> {
  serial.send(`${command}; echo "status=$?"\n`);
  const [, status] = await serial.expect(/status=(\d+)/, seconds);
  if (status !== "0") {
    throw new Error(`on the console, ${command} ended with the status ${status}`);
  }
}

/// Logs in as root on the console, whose password is empty in the live image, and installs the
/// key. The image runs sshd, which lets root in with a key.
async function admit(socket: string): Promise<void> {
  const serial = await openConsole(socket);
  await serial.expect(/^login: /m, 600);
  serial.send("root\n");
  await serial.expect(/# /, 60);
  await typed(serial, `mkdir -p -m 700 /root/.ssh && echo '${key().open}' > /root/.ssh/authorized_keys`, 30);
  serial.close();
}

/// Makes the prepared image: the live image on a larger disk, which it grows its file system
/// into when it first boots, with root's key and the Rust toolchain of pkgsrc.
async function prepare(): Promise<void> {
  const archive = resolve(directory, "arm64.img.gz");
  const raw = resolve(directory, "arm64.img");
  const building = resolve(directory, "building.qcow2");
  download(image.url, archive, image.sha512, "sha512");
  must("gunzip", ["--keep", "--force", archive]);
  must("qemu-img", ["convert", "-f", "raw", "-O", "qcow2", raw, building]);
  rmSync(raw);
  must("qemu-img", ["resize", building, "24G"]);
  const socket = resolve(directory, "console");
  const guest = boot(machine(building, socket));
  try {
    await admit(socket);
    waitForSsh(port, 120, log);
    const proxy = guestProxy();
    const through = proxy === undefined ? "" : `http_proxy=${proxy} https_proxy=${proxy}`;
    if (sshShown(port, `env ${path} PKG_PATH=${packages} ${through} pkg_add rust`) !== 0) {
      throw new Error("installing the Rust toolchain failed");
    }
    console.log(sshMust(port, `env ${path} sh -c 'uname -srm && cargo --version && rustc --version && cc --version'`));
    ssh(port, `env ${path} shutdown -p now`);
    if (!waitForExit(guest, 180)) {
      throw new Error("the guest did not power off");
    }
  } finally {
    stop(guest);
    rmSync(socket, { force: true });
  }
  renameSync(building, prepared);
}

export const system: System = {
  directory,
  port,
  prepare: async () => {
    if (!existsSync(prepared)) {
      await prepare();
    }
    return prepared;
  },
  machine: (disk, log) => ({ ...machine(disk), log }),
  bootSeconds: 300,
  shell: `export ${path} && `,
};

/// Runs the tests in a machine that starts from the prepared image and is thrown away.
function test(filter: string): number {
  const disk = resolve(directory, "run.qcow2");
  overlay(prepared, disk);
  const guest = boot(machine(disk));
  try {
    waitForSsh(port, 300, log);
    pushSource(port, source);
    const script = [
      `cd ${source}`,
      `export ${path}`,
      "uname -srm",
      "cargo test --release --offline -p xtun-wire --lib",
      `cargo test --release --offline --no-fail-fast ${features} --test device --test tap -- --ignored --test-threads=1 --nocapture ${filter === "" ? "" : `'${filter}'`}`,
    ].join(" && ");
    return sshShown(port, script);
  } finally {
    stop(guest);
    rmSync(disk, { force: true });
  }
}

async function main(): Promise<void> {
  const filter = process.argv[2] ?? "";
  if (!existsSync(prepared)) {
    await prepare();
  }
  process.exit(test(filter));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  await main();
}
