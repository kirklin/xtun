// Runs the tests on real FreeBSD interfaces inside a virtual machine.
//
//   node scripts/vm/freebsd.ts            the wire crate's tests and the device tests
//   node scripts/vm/freebsd.ts <filter>   the wire crate's tests and the device tests whose names contain <filter>

import { existsSync, renameSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import process from "node:process";
import { boot, download, drive, guestProxy, home, key, must, overlay, pushSource, seedDisk, ssh, sshMust, sshShown, stop, waitForExit, waitForSsh } from "./common.ts";

const release = "15.1-RELEASE";
/// The official image that takes its first settings from a seed disk.
const image = `FreeBSD-${release}-arm64-aarch64-BASIC-CLOUDINIT-ufs.qcow2`;
const url = `https://download.freebsd.org/releases/VM-IMAGES/${release}/aarch64/Latest/${image}.xz`;
/// The digest of the compressed image, from `CHECKSUM.SHA256` next to it.
const sha256 = "9722aea499610802de9a14bb645707fc4f6df49ff765cd9ce372b783c4693963";
/// The port of this host that reaches the guest's SSH server.
const port = 2231;
/// Every runtime and adapter, so that the tests cover them all.
const features = "--features async-io,futures";
/// The oldest Rust that builds the workspace.
const oldest = [1, 88];
const directory = home("freebsd");
/// The machine with the key and the toolchain in it, which every run starts from.
const prepared = resolve(directory, "prepared.qcow2");
/// Where the guest keeps the source tree, and what it builds from it.
const source = "/root/xtun";
const target = "/root/target";

/// What the image runs late in its first boot, before it starts its SSH server: it lets root in
/// with the key. By then the image has upgraded its base system to the newest patches of the
/// release and asked for a restart, which would cut off whoever had just logged in. The request
/// is taken back: the machine is powered off once it is prepared, and every run boots the
/// upgraded system.
function firstBoot(): string {
  return [
    "#!/bin/sh",
    "mkdir -p -m 700 /root/.ssh",
    `echo '${key().open}' > /root/.ssh/authorized_keys`,
    "chmod 600 /root/.ssh/authorized_keys",
    "echo 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config",
    "rm -f /firstboot-reboot",
    "",
  ].join("\n");
}

/// What makes the machine ready for the tests, run in it as root: the Rust toolchain from
/// FreeBSD's packages. The driver of tun and tap interfaces is part of the image's kernel, which
/// the last line checks.
function provision(): string {
  const proxy = guestProxy();
  return [
    "set -e",
    proxy === undefined ? "" : `export HTTP_PROXY=${proxy} HTTPS_PROXY=${proxy} http_proxy=${proxy} https_proxy=${proxy}`,
    "export ASSUME_ALWAYS_YES=yes",
    "pkg install rust",
    "pkg clean -a",
    "kldstat -q -m if_tuntap",
    "",
  ].join("\n");
}

/// Makes the machine the runs start from, unless it is there.
function prepare(): void {
  if (existsSync(prepared)) {
    return;
  }
  const packed = resolve(directory, `${image}.xz`);
  download(url, packed, sha256);
  const disk = resolve(directory, "preparing.qcow2");
  rmSync(disk, { force: true });
  must("xz", ["--decompress", "--keep", "--force", packed]);
  renameSync(resolve(directory, image), disk);
  // The image grows its file system to the size of the disk on its first boot.
  must("qemu-img", ["resize", disk, "24G"]);
  const seed = resolve(directory, "seed.iso");
  seedDisk(seed, "xtun-freebsd", firstBoot());
  const log = resolve(directory, "prepare.log");
  const machine = boot({ arch: "aarch64", disk, port, log, extra: drive(seed, "raw", true) });
  try {
    waitForSsh(port, 300, log);
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
    ssh(port, "shutdown -p now");
    if (!waitForExit(machine, 120)) {
      throw new Error("the machine did not power off");
    }
  } finally {
    stop(machine);
  }
  rmSync(seed);
  renameSync(disk, prepared);
}

/// Runs the tests in a machine that is thrown away afterwards. Returns their status.
function test(filter: string): number {
  const disk = resolve(directory, "run.qcow2");
  overlay(prepared, disk);
  const log = resolve(directory, "run.log");
  const machine = boot({ arch: "aarch64", disk, port, log });
  try {
    waitForSsh(port, 300, log);
    pushSource(port, source);
    const cargo = `cd ${source} && env CARGO_TARGET_DIR=${target} cargo test --release --offline`;
    sshShown(port, "uname -rm && rustc --version");
    const wire = sshShown(port, `${cargo} -p xtun-wire --lib`);
    const device = sshShown(port, `${cargo} --no-fail-fast ${features} --test device --test tap -- --ignored --test-threads=1 --nocapture ${filter}`);
    return wire !== 0 ? wire : device;
  } finally {
    stop(machine);
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
