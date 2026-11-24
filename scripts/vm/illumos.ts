// Runs the tests on real illumos interfaces inside an OmniOS virtual machine. illumos has no
// arm64 release, so the machine is an x86_64 one that QEMU emulates: preparing it and every run
// take a long time.
//
//   node scripts/vm/illumos.ts            the wire crate's tests and the device tests
//   node scripts/vm/illumos.ts <filter>   the wire crate's tests and the device tests whose names contain <filter>

import { existsSync, renameSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import process from "node:process";
import { boot, download, drive, fatSeedDisk, guestProxy, home, key, type Machine, must, overlay, pushSource, ssh, sshMust, sshShown, stop, type System, waitForExit, waitForSsh } from "./common.ts";

/// The stable release of OmniOS.
const release = "r151060";
/// The official image that takes its first settings from a seed disk.
const image = `omnios-${release}.cloud.qcow2`;
const url = `https://downloads.omnios.org/media/${release}/${image}`;
/// The digest of the image, from `${image}.sha256` next to it.
const sha256 = "fbc636747d3e099d2c226c56648a0eabebbc7f1540a8ec9c99b67ceeb6f9b4c1";
/// The port of this host that reaches the guest's SSH server.
const port = 2234;
/// Every runtime and adapter, so that the tests cover them all.
const features = "--features async-io,futures";
/// The oldest Rust that builds the workspace.
const oldest = [1, 88];
const directory = home("illumos");
/// The machine with the key, the toolchain and the tun driver in it, which every run starts from.
const prepared = resolve(directory, "prepared.qcow2");
/// Where the guest keeps the source tree, and what it builds from it.
const source = "/root/xtun";
const target = "/root/target";
/// How long the guest may take to open SSH. An emulated machine boots in one to three minutes on
/// an idle host, and in several times that on a busy one.
const bootSeconds = 1800;
/// The four stages of cloud-init, as the services of the image.
const cloudInit = ["initlocal", "init", "modules", "final"].map((stage) => `svc:/system/cloud-init:${stage}`).join(" ");

/// What cloud-init does on the first boot: it lets root in with the key.
function firstBoot(): string {
  return ["#cloud-config", "disable_root: false", "ssh_authorized_keys:", `  - ${key().open}`, ""].join("\n");
}

/// What makes the machine ready for the tests, run in it as root. The packages come from
/// OmniOS's own repositories: Rust, which brings gcc to link with and the headers and start
/// files of the C library, and the driver behind `/dev/tun`, which the image has only the name
/// of. The last line turns cloud-init off: without its seed disk it would look for the metadata
/// service of a cloud for four minutes on every boot.
function provision(): string {
  const proxy = guestProxy();
  return [
    "set -e",
    proxy === undefined ? "" : `export http_proxy=${proxy} https_proxy=${proxy}`,
    "pkg install ooce/developer/rust driver/tuntap",
    "test -c /dev/tun",
    "gcc --version",
    "cargo --version",
    `svcadm disable ${cloudInit}`,
    "",
  ].join("\n");
}

/// Makes the machine the runs start from, unless it is there.
function prepare(): void {
  if (existsSync(prepared)) {
    return;
  }
  const base = resolve(directory, image);
  download(url, base, sha256);
  const disk = resolve(directory, "preparing.qcow2");
  overlay(base, disk);
  // The image grows its pool to the size of the disk on its first boot.
  must("qemu-img", ["resize", disk, "32G"]);
  const seed = resolve(directory, "seed.dmg");
  fatSeedDisk(seed, "xtun-illumos", firstBoot());
  const log = resolve(directory, "prepare.log");
  const machine = boot({ arch: "x86_64", disk, port, log, memory: 8192, extra: drive(seed, "raw", true) });
  try {
    waitForSsh(port, bootSeconds, log);
    sshMust(port, "cat > /root/provision.sh", provision());
    if (sshShown(port, "sh /root/provision.sh") !== 0) {
      throw new Error("preparing the machine failed");
    }
    const version = sshMust(port, "rustc --version");
    const [major, minor] = version.split(" ")[1].split(".").map(Number);
    if (major < oldest[0] || (major === oldest[0] && minor < oldest[1])) {
      throw new Error(`the packages have ${version}, older than ${oldest.join(".")}`);
    }
    sshMust(port, "rm /root/provision.sh");
    ssh(port, "shutdown -y -g 0 -i 5");
    if (!waitForExit(machine, 600)) {
      throw new Error("the machine did not power off");
    }
  } finally {
    stop(machine);
  }
  rmSync(seed);
  renameSync(disk, prepared);
}

function machine(disk: string, log: string): Machine {
  return { arch: "x86_64", disk, port, log, memory: 8192 };
}

export const system: System = {
  directory,
  port,
  prepare: async () => {
    prepare();
    return prepared;
  },
  machine,
  bootSeconds,
  shell: "",
};

/// Runs the tests in a machine that is thrown away afterwards. Returns their status. illumos has
/// TUN interfaces only, so the device tests are all there is to run on interfaces.
function test(filter: string): number {
  const disk = resolve(directory, "run.qcow2");
  overlay(prepared, disk);
  const log = resolve(directory, "run.log");
  const guest = boot(machine(disk, log));
  try {
    waitForSsh(port, bootSeconds, log);
    pushSource(port, source);
    const cargo = `cd ${source} && env CARGO_TARGET_DIR=${target} cargo test --release --offline`;
    sshShown(port, "uname -a && rustc --version");
    const wire = sshShown(port, `${cargo} -p xtun-wire --lib`);
    const device = sshShown(port, `${cargo} --no-fail-fast ${features} --test device -- --ignored --test-threads=1 --nocapture ${filter}`);
    return wire !== 0 ? wire : device;
  } finally {
    stop(guest);
    rmSync(disk, { force: true });
  }
}

function main(): void {
  const filter = process.argv[2] ?? "";
  prepare();
  process.exit(test(filter));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
