// What the scripts that run the device tests in virtual machines share: images, QEMU, SSH into
// the guest, and getting the source tree with its dependencies there. A system's script says
// which image it boots, how it turns it into a machine with a Rust toolchain, and which tests it
// runs; everything lives under `target/vm`.

import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { type AddressInfo, connect, type Socket } from "node:net";
import { dirname, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
export const repo = resolve(here, "../..");
/// Images, keys and the vendored dependencies.
export const root = resolve(repo, "target/vm");
/// Where the firmware that comes with Homebrew's QEMU is.
const firmware = "/opt/homebrew/share/qemu";
/// The host as the guest sees it with QEMU's user networking.
export const host = "10.0.2.2";

export interface Run {
  code: number;
  out: string;
  err: string;
}

export function run(command: string, args: string[], options: { cwd?: string; input?: string | Buffer } = {}): Run {
  const result = spawnSync(command, args, { encoding: "utf8", maxBuffer: 256 * 1024 * 1024, ...options });
  if (result.error) {
    throw result.error;
  }
  return { code: result.status ?? -1, out: (result.stdout ?? "").trim(), err: (result.stderr ?? "").trim() };
}

/// Runs a command that has to succeed.
export function must(command: string, args: string[], options: { cwd?: string; input?: string | Buffer } = {}): string {
  const result = run(command, args, options);
  if (result.code !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed:\n${result.out}\n${result.err}`);
  }
  return result.out;
}

export function sleep(seconds: number): void {
  spawnSync("sleep", [String(seconds)]);
}

/// The directory of one system's files.
export function home(name: string): string {
  const directory = resolve(root, name);
  mkdirSync(directory, { recursive: true });
  return directory;
}

/// The proxy the host reaches the network through, as the guest reaches it, or nothing.
export function guestProxy(): string | undefined {
  const proxy = process.env.HTTPS_PROXY ?? process.env.https_proxy ?? process.env.HTTP_PROXY ?? process.env.http_proxy;
  return proxy?.replace(/\/\/(127\.0\.0\.1|localhost)(?=[:/]|$)/, `//${host}`);
}

/// Downloads `url` to `file` unless it is there, and checks it against `digest`, the hexadecimal
/// digest the project publishes for it: a SHA-256 digest unless `algorithm` says SHA-512.
export function download(url: string, file: string, digest: string, algorithm: "sha256" | "sha512" = "sha256"): void {
  if (!existsSync(file)) {
    const partial = `${file}.partial`;
    const fetched = spawnSync("curl", ["--fail", "--location", "--continue-at", "-", "--output", partial, url], { stdio: "inherit" });
    if (fetched.status !== 0) {
      throw new Error(`downloading ${url} failed`);
    }
    renameSync(partial, file);
  }
  const found = createHash(algorithm).update(readFileSync(file)).digest("hex");
  if (found !== digest) {
    throw new Error(`${file} has the ${algorithm} digest ${found}, not ${digest}`);
  }
}

/// A disk that keeps what is written to it apart from `base`, which stays as it is.
export function overlay(base: string, file: string): void {
  rmSync(file, { force: true });
  must("qemu-img", ["create", "-f", "qcow2", "-b", base, "-F", "qcow2", file]);
}

/// A disk that gives cloud-init its NoCloud data: an ISO 9660 volume named `cidata` holding
/// `meta-data`, which names the machine `name`, and `user-data`. `file` ends in `.iso`.
export function seedDisk(file: string, name: string, userData: string): void {
  seeded(file, name, userData, (staging) => {
    must("hdiutil", ["makehybrid", "-quiet", "-iso", "-joliet", "-default-volume-name", "cidata", "-o", file, staging]);
  });
}

/// The same NoCloud data on a FAT volume named `CIDATA`, a raw image; `file` ends in `.dmg`.
/// For illumos, whose cloud-init compares the volume name with everything that follows it in
/// its field: hdiutil fills the field of an ISO 9660 volume with zero bytes, a FAT volume has
/// the spaces that cloud-init allows there.
export function fatSeedDisk(file: string, name: string, userData: string): void {
  seeded(file, name, userData, (staging) => {
    must("hdiutil", ["create", "-quiet", "-srcfolder", staging, "-fs", "MS-DOS", "-volname", "CIDATA", "-layout", "NONE", "-format", "UDRW", "-o", file]);
  });
}

/// Puts the NoCloud data into a directory, has `make` turn the directory into `file`, and
/// removes the directory.
function seeded(file: string, name: string, userData: string, make: (staging: string) => void): void {
  const staging = `${file}.d`;
  rmSync(staging, { recursive: true, force: true });
  mkdirSync(staging, { recursive: true });
  writeFileSync(resolve(staging, "meta-data"), `instance-id: ${name}\nlocal-hostname: ${name}\n`);
  writeFileSync(resolve(staging, "user-data"), userData);
  rmSync(file, { force: true });
  make(staging);
  rmSync(staging, { recursive: true, force: true });
}

export interface Machine {
  arch: "aarch64" | "x86_64";
  /// The disk the machine boots from, a qcow2 image.
  disk: string;
  /// The port of the host that reaches the guest's SSH server.
  port: number;
  /// Where everything the guest prints on its serial console goes.
  log: string;
  /// A Unix socket that carries the serial console both ways, for `openConsole`. The machine
  /// starts once something has connected to it, so nothing the guest prints is missed.
  console?: string;
  /// Megabytes of memory.
  memory?: number;
  cpus?: number;
  /// Arguments for QEMU besides.
  extra?: string[];
}

/// QEMU's arguments for the serial console of a machine: its log, and its socket if it has one.
function serial(machine: Machine): string[] {
  if (machine.console === undefined) {
    return ["-serial", `file:${machine.log}`];
  }
  rmSync(machine.console, { force: true });
  return [
    "-chardev", `socket,id=console,path=${machine.console},server=on,wait=on,logfile=${machine.log},logappend=off`,
    "-serial", "chardev:console",
  ];
}

/// Starts a machine. An aarch64 guest runs on the host's processor; an x86_64 guest is emulated.
export function boot(machine: Machine): ChildProcess {
  // QEMU cannot forward a port that is taken, and the wait for SSH would then talk to whatever
  // has it.
  if (run("nc", ["-z", "127.0.0.1", String(machine.port)]).code === 0) {
    throw new Error(`something already listens on port ${machine.port} of this host`);
  }
  const platform =
    machine.arch === "aarch64"
      ? ["-machine", "virt", "-accel", "hvf", "-cpu", "host", "-bios", `${firmware}/edk2-aarch64-code.fd`]
      : ["-machine", "q35", "-accel", "tcg,thread=multi", "-cpu", "max"];
  const args = [
    ...platform,
    "-m", String(machine.memory ?? 4096),
    "-smp", String(machine.cpus ?? 8),
    "-display", "none",
    ...serial(machine),
    "-drive", `if=virtio,format=qcow2,file=${machine.disk}`,
    "-netdev", `user,id=net0,hostfwd=tcp:127.0.0.1:${machine.port}-:22`,
    "-device", "virtio-net-pci,netdev=net0",
    "-device", "virtio-rng-pci",
    ...(machine.extra ?? []),
  ];
  const child = spawn(`qemu-system-${machine.arch}`, args, { stdio: "inherit" });
  child.on("error", (error) => {
    throw error;
  });
  return child;
}

/// Whether a machine is still running. One that has ended stays in the process table until this
/// process collects it, which these scripts never get to do while they wait synchronously, so
/// its state is what tells.
export function running(child: ChildProcess): boolean {
  if (child.exitCode !== null || child.pid === undefined) {
    return false;
  }
  const state = run("ps", ["-o", "stat=", "-p", String(child.pid)]).out;
  return state !== "" && !state.startsWith("Z");
}

/// Waits until a machine has ended by itself, as it does after the guest powers off. Returns
/// whether it did within `seconds`.
export function waitForExit(child: ChildProcess, seconds: number): boolean {
  const deadline = Date.now() + seconds * 1000;
  while (running(child)) {
    if (Date.now() >= deadline) {
      return false;
    }
    sleep(1);
  }
  return true;
}

/// Stops a machine and waits until it is gone.
export function stop(child: ChildProcess): void {
  if (running(child)) {
    child.kill("SIGTERM");
    for (let i = 0; i < 100 && running(child); i += 1) {
      sleep(0.1);
    }
  }
}

/// The serial console of a machine, for a guest that has to be told by hand how to let SSH in.
export interface Console {
  /// Waits until the guest has printed something that matches `pattern` after what the call
  /// before matched, and returns the match.
  expect(pattern: RegExp, seconds: number): Promise<RegExpExecArray>;
  /// Types `text` into the guest.
  send(text: string): void;
  /// Lets go of the console. The guest keeps running, and what it prints still reaches its log.
  /// A console that is held has to be read, or the guest waits to print: let go of it before
  /// anything that waits synchronously.
  close(): void;
}

function connected(path: string): Promise<Socket> {
  return new Promise((done, fail) => {
    const socket = connect(path);
    socket.once("connect", () => done(socket));
    socket.once("error", fail);
  });
}

/// Connects to the serial console of a machine that `boot` has just started with `console`,
/// which is `path`.
export async function openConsole(path: string): Promise<Console> {
  const deadline = Date.now() + 30_000;
  let socket: Socket | undefined;
  while (socket === undefined) {
    try {
      socket = await connected(path);
    } catch (error) {
      if (Date.now() >= deadline) {
        throw error;
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  const line = socket;
  let printed = "";
  let ended = false;
  let wake = (): void => {};
  line.setEncoding("utf8");
  line.on("data", (text: string) => {
    printed += text;
    wake();
  });
  line.on("close", () => {
    ended = true;
    wake();
  });
  return {
    async expect(pattern, seconds) {
      const until = Date.now() + seconds * 1000;
      for (;;) {
        const match = pattern.exec(printed);
        if (match !== null) {
          printed = printed.slice(match.index + match[0].length);
          return match;
        }
        const left = until - Date.now();
        if (ended || left <= 0) {
          const tail = printed.split("\n").slice(-40).join("\n");
          const what = ended ? `went away before it printed ${pattern}` : `did not print ${pattern} within ${seconds} seconds`;
          throw new Error(`the guest ${what}; its console ended with:\n${tail}`);
        }
        await new Promise<void>((resolve) => {
          const timer = setTimeout(resolve, left);
          wake = () => {
            clearTimeout(timer);
            resolve();
          };
        });
      }
    },
    send(text) {
      line.write(text);
    },
    close() {
      line.destroy();
    },
  };
}

/// The arguments that give a machine one more drive after the disk it boots from, for `extra`.
export function drive(file: string, format: "raw" | "qcow2", readOnly: boolean): string[] {
  return ["-drive", `if=virtio,format=${format},file=${file}${readOnly ? ",readonly=on" : ""}`];
}

/// Texts the guest fetches over HTTP while the script waits for its console.
export interface Served {
  /// Where the guest finds the text named `name`.
  url(name: string): string;
  close(): void;
}

/// Serves `texts`, each under its name and as it is when it is asked for, to the guests of this
/// host. A text may be added once the address of another is known.
export async function serve(texts: Record<string, string>): Promise<Served> {
  const server = createServer((request, response) => {
    const name = new URL(request.url ?? "/", "http://localhost").pathname.slice(1);
    if (!Object.hasOwn(texts, name)) {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, { "content-type": "text/plain" }).end(texts[name]);
  });
  await new Promise<void>((listening) => server.listen(0, "127.0.0.1", listening));
  const { port } = server.address() as AddressInfo;
  return {
    url: (name) => `http://${host}:${port}/${name}`,
    close: () => {
      server.close();
    },
  };
}

/// The key the guests let in as root, made once.
export function key(): { secret: string; open: string } {
  const secret = resolve(root, "key");
  if (!existsSync(secret)) {
    mkdirSync(root, { recursive: true });
    must("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "xtun-vm", "-f", secret]);
  }
  return { secret, open: readFileSync(`${secret}.pub`, "utf8").trim() };
}

function sshArgs(port: number): string[] {
  return [
    "-i", key().secret,
    "-p", String(port),
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "LogLevel=ERROR",
    "-o", "ConnectTimeout=5",
    // Only this key, and a failure where ssh would ask for a password.
    "-o", "IdentitiesOnly=yes",
    "-o", "BatchMode=yes",
    "root@127.0.0.1",
  ];
}

/// Runs `command` in the guest as root.
export function ssh(port: number, command: string, input?: string | Buffer): Run {
  return run("ssh", [...sshArgs(port), command], { input });
}

/// Runs `command` in the guest as root, showing what it prints as it comes. Returns its status.
export function sshShown(port: number, command: string): number {
  return spawnSync("ssh", [...sshArgs(port), command], { stdio: "inherit" }).status ?? -1;
}

/// Runs a command in the guest that has to succeed.
export function sshMust(port: number, command: string, input?: string | Buffer): string {
  const result = ssh(port, command, input);
  if (result.code !== 0) {
    throw new Error(`in the guest, ${command} failed:\n${result.out}\n${result.err}`);
  }
  return result.out;
}

/// Waits until the guest's SSH server lets root in.
export function waitForSsh(port: number, seconds: number, log: string): void {
  const deadline = Date.now() + seconds * 1000;
  while (Date.now() < deadline) {
    if (ssh(port, "true").code === 0) {
      return;
    }
    sleep(2);
  }
  const tail = existsSync(log) ? readFileSync(log, "utf8").split("\n").slice(-40).join("\n") : "";
  throw new Error(`the guest did not open SSH within ${seconds} seconds; its console ended with:\n${tail}`);
}

/// The source tree as an archive: every file git knows or would add, and the dependencies of
/// the whole workspace vendored next to it, so that the guest builds without a network.
export function sourceArchive(): Buffer {
  // A directory of this process alone, so that the scripts of several systems can run at once.
  const staging = resolve(root, `source-${process.pid}`);
  rmSync(staging, { recursive: true, force: true });
  mkdirSync(resolve(staging, ".cargo"), { recursive: true });
  try {
    const vendor = resolve(staging, "vendor");
    const config = must("cargo", ["vendor", "--locked", "--versioned-dirs", vendor], { cwd: repo });
    writeFileSync(resolve(staging, ".cargo/config.toml"), config.replaceAll(vendor, "vendor"));
    const files = must("git", ["ls-files", "--cached", "--others", "--exclude-standard", "-z"], { cwd: repo })
      .split("\0")
      .filter((file) => file !== "" && existsSync(resolve(repo, file)));
    const list = resolve(staging, "files");
    writeFileSync(list, files.join("\0"));
    const archive = resolve(staging, "source.tar");
    // The attributes macOS keeps next to a file mean nothing to a guest, whose tar fails on them.
    const plain = ["--no-xattrs", "--no-mac-metadata"];
    must("tar", ["-cf", archive, ...plain, "--null", "-T", list], { cwd: repo });
    must("tar", ["-rf", archive, ...plain, "-C", staging, "vendor", ".cargo"]);
    return readFileSync(archive);
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
}

/// Puts the source tree and its dependencies into `directory` of the guest, replacing what is
/// there.
export function pushSource(port: number, directory: string): void {
  sshMust(port, `rm -rf ${directory} && mkdir -p ${directory} && tar -xf - -C ${directory}`, sourceArchive());
}
