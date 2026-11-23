// Measures xtun against tun-rs on a Windows machine over SSH, both on Wintun, with the
// reflector and the load of `bench/`. The machine is the one `scripts/vm/windows.ts` describes.
//
//   node scripts/vm/windows-bench.ts <user@address> [rounds] [filter]
//
// Round trips are those of a small datagram to a UDP echo behind the reflector, as the system's
// own ping counts whole milliseconds.

import { spawn } from "node:child_process";
import process from "node:process";

import { run, sleep } from "./common.ts";
import { type Guest, guest, inSource, powershell, pushSource, pushTools, sshArgs, sshMust, sshShown, withFirewall } from "./windows.ts";

/// The name both libraries give the reflector's interface.
const adapter = "bench0";
const local = "10.80.0.1";
const peer = "10.80.0.2";
/// The addresses of the reflector's subnets.
const benchAddresses = "10.80.0.0/24,fd80::/64";

/// A TCP rate that both libraries carry with room to spare on Wintun. Round trips under it
/// compare the libraries under the same load; at full speed each moves as much as it can.
const pacedGbit = 0.5;

/// The capacities of each Wintun ring to measure with, in MiB: what tun-rs takes by default, and
/// what xtun does. A flow at full speed keeps the ring full, and a datagram waits behind
/// everything in it, so both libraries are measured with both.
const ringsMib = [2, 8];

interface Result {
  up: number;
  down: number;
  udp: number;
  idle: number;
  paced: number;
  pacedTail: number;
  full: number;
  fullTail: number;
}

function percentile(values: number[], fraction: number): number {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * fraction))];
}

/// Runs a command line of `cmd.exe` in the guest whatever its status, and returns what it printed.
function ssh(machine: Guest, command: string): string {
  return run("ssh", [...sshArgs(machine.target), command]).out;
}

/// Starts a program in the guest that runs until it is stopped there. The session stays open
/// for as long as the program runs.
function hold(machine: Guest, command: string): void {
  spawn("ssh", [...sshArgs(machine.target), command], { stdio: "ignore" });
}

/// The reflectors that run in the guest, by process id.
function reflectors(machine: Guest): string {
  return powershell(machine.target, "(Get-Process reflect -ErrorAction SilentlyContinue | Sort-Object Id).Id -join ','").trim();
}

/// Starts the reflector in the guest and returns what stops it. The reflector closes its device
/// and ends when its standard input ends, which here is what a program of this machine prints:
/// killing that program ends the input.
function startReflector(machine: Guest, command: string): () => void {
  const before = reflectors(machine);
  const input = spawn("sleep", ["86400"], { stdio: ["ignore", "pipe", "ignore"] });
  spawn("ssh", [...sshArgs(machine.target), command], { stdio: [input.stdout, "ignore", "ignore"] });
  return () => {
    input.kill();
    for (let i = 0; i < 100; i += 1) {
      if (reflectors(machine) === before) {
        return;
      }
      sleep(0.1);
    }
    throw new Error("the reflector did not end");
  };
}

/// Stops by force what a run that broke off left behind, and waits for the reflector's
/// interface to go.
function stopLeftovers(machine: Guest): void {
  ssh(machine, "taskkill /F /IM load.exe /IM reflect.exe");
  for (let i = 0; i < 100; i += 1) {
    if (powershell(machine.target, `@(Get-NetAdapter -Name ${adapter} -ErrorAction SilentlyContinue).Count`).trim() === "0") {
      return;
    }
    sleep(0.1);
  }
  throw new Error(`the interface ${adapter} stays`);
}

function measure(machine: Guest, backend: string, ringMib: number): Result {
  // Every command line starts in the directory of the programs: one that started with a quoted
  // path would lose its first and last quote to `cmd.exe`.
  const there = `cd /d "${machine.targetDir}\\release" && `;
  const stopReflector = startReflector(
    machine,
    `${there}reflect.exe ${backend} pass --offload off --ring ${ringMib} > reflect.log 2>&1`,
  );
  try {
    return measureThrough(machine, backend, there);
  } finally {
    ssh(machine, "taskkill /F /IM load.exe");
    stopReflector();
  }
}

/// Measures through the reflector that was just started.
function measureThrough(machine: Guest, backend: string, there: string): Result {
  const load = "load.exe";
  let said = "";
  for (let i = 0; i < 200 && !/^ready/m.test(said); i += 1) {
    sleep(0.1);
    said = ssh(machine, `${there}type reflect.log`);
  }
  if (!/^ready/m.test(said)) {
    throw new Error(`the reflector over ${backend} did not start:\n${said}`);
  }
  // A listener binds only an address that Windows has finished checking.
  for (let i = 0; i < 100; i += 1) {
    if (powershell(machine.target, `(Get-NetIPAddress -IPAddress ${local} -ErrorAction SilentlyContinue).AddressState`).trim() === "Preferred") {
      break;
    }
    sleep(0.1);
  }
  hold(machine, `${there}${load} serve ${local}`);
  sleep(1);
  const number = (command: string) => {
    const out = sshMust(machine.target, `${there}${command}`).trim();
    const value = Number(out);
    if (out === "" || Number.isNaN(value)) {
      throw new Error(`${command} printed ${out}`);
    }
    return value;
  };
  const times = (out: string) => out.split(/\s+/).filter((word) => word !== "").map(Number);
  const idle = times(sshMust(machine.target, `${there}${load} echo ${peer} 100`));
  const up = number(`${load} up ${peer} 6`);
  const down = number(`${load} down ${peer} 6`);
  const udp = number(`${load} udp ${peer} 6 100`) / 1e6;
  // The round trips while one TCP flow runs to the peer, paced to `gbit` or as fast as it goes.
  // The flow starts two seconds before the first datagram and ends with the session.
  const echoUnder = (gbit?: number) => {
    const rate = gbit === undefined ? "" : ` ${gbit}`;
    const out = sshMust(
      machine.target,
      `${there}start /b "" ${load} up ${peer} 9${rate} > nul 2>&1 & ping -n 3 127.0.0.1 > nul & ${load} echo ${peer} 400`,
    );
    sleep(0.5);
    return times(out);
  };
  const paced = echoUnder(pacedGbit);
  const full = echoUnder();
  for (const [name, list] of [["idle", idle], ["paced", paced], ["full", full]] as const) {
    if (list.length === 0) {
      throw new Error(`no datagram came back over ${backend} (${name})`);
    }
  }
  return {
    up,
    down,
    udp,
    idle: percentile(idle, 0.5),
    paced: percentile(paced, 0.5),
    pacedTail: percentile(paced, 0.99),
    full: percentile(full, 0.5),
    fullTail: percentile(full, 0.99),
  };
}

function main(): void {
  const [target, rounds = "3", filter = ""] = process.argv.slice(2);
  const machine = guest(target, "node scripts/vm/windows-bench.ts <user@address> [rounds] [filter]");
  pushTools(machine);
  pushSource(machine);
  if (sshShown(machine.target, `${inSource(machine)}cargo build --release --offline -p xtun-bench`) !== 0) {
    throw new Error("building the reflector failed");
  }
  // Both libraries load the `wintun.dll` next to the program.
  sshMust(machine.target, `copy /y "${machine.tools}\\wintun.dll" "${machine.targetDir}\\release\\wintun.dll"`);
  stopLeftovers(machine);
  const all = new Map<string, Result[]>();
  withFirewall(machine, benchAddresses, () => {
    for (let round = 0; round < Number(rounds); round += 1) {
      for (const ringMib of ringsMib) {
        for (const backend of ["tun-rs", "xtun"]) {
          const name = `${ringMib} MiB rings | ${backend}`;
          if (!name.includes(filter)) {
            continue;
          }
          try {
            const result = measure(machine, backend, ringMib);
            all.set(name, [...(all.get(name) ?? []), result]);
            console.log(`round ${round + 1} ${name}: ${JSON.stringify(result)}`);
          } catch (error) {
            // A run that broke off counts for nothing: the medians are those of the others.
            const said = ssh(machine, `type "${machine.targetDir}\\release\\reflect.log"`);
            console.log(`round ${round + 1} ${name}: broke off: ${(error as Error).message.trim()}\nthe reflector said:\n${said}`);
          }
        }
      }
    }
  });
  console.log("\nmedians over the rounds that ran through; round trips are the median and the 99th percentile of each run");
  console.log(
    `rings | backend | rounds | TCP up Gbit/s | TCP down Gbit/s | UDP Mpps | round trip idle ms | at ${pacedGbit} Gbit/s ms | p99 ms | ` +
      "at full speed ms | p99 ms",
  );
  for (const [name, list] of all) {
    const pick = (key: keyof Result) => percentile(list.map((result) => result[key]), 0.5);
    console.log(
      `${name} | ${list.length} | ${pick("up").toFixed(2)} | ${pick("down").toFixed(2)} | ${pick("udp").toFixed(3)} | ` +
        `${pick("idle").toFixed(3)} | ${pick("paced").toFixed(3)} | ${pick("pacedTail").toFixed(3)} | ` +
        `${pick("full").toFixed(3)} | ${pick("fullTail").toFixed(3)}`,
    );
  }
  process.exit(0);
}

main();
