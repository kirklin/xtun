// Runs the device tests and the measurements against tun-rs on this Mac. Builds as the current
// user, then asks for the administrator password once and runs the rest as root.
//
//   node scripts/macos.ts [rounds]

import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..");
const results = resolve(repo, "target/macos-results.txt");

interface Run {
  code: number;
  out: string;
  err: string;
}

function run(command: string, args: string[], options: { cwd?: string } = {}): Run {
  const result = spawnSync(command, args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, ...options });
  if (result.error) {
    throw result.error;
  }
  return { code: result.status ?? -1, out: (result.stdout ?? "").trim(), err: (result.stderr ?? "").trim() };
}

function sleep(seconds: number): void {
  spawnSync("sleep", [String(seconds)]);
}

/// The test programs that run on real interfaces.
const suites = ["device", "tap"];

/// A TCP rate that both libraries carry with room to spare on a Mac. Ping times under it compare
/// the libraries under the same load. At full speed each moves as much as it can, and the faster
/// one may fill a queue of the system that the slower one never reaches: the ping times then tell
/// where the flow's window waits, which the table shows apart.
const pacedGbit = 1;

function build(): { tests: string[]; reflect: string; load: string } {
  const cargo = `${process.env.HOME}/.cargo/bin/cargo`;
  const targets = suites.flatMap((suite) => ["--test", suite]);
  const listing = run(cargo, ["test", "--release", "--features", "async-io,futures", ...targets, "--no-run", "--message-format=json"], {
    cwd: repo,
  });
  if (listing.code !== 0) {
    throw new Error(`building the tests failed:\n${listing.err}`);
  }
  const artifacts = listing.out.split("\n").map((line) => JSON.parse(line));
  const tests = suites.map((suite) => {
    const found = artifacts.find((message) => message.reason === "compiler-artifact" && message.target?.name === suite && message.executable);
    if (!found) {
      throw new Error(`the test program ${suite} was not built`);
    }
    return found.executable as string;
  });
  const bench = run(cargo, ["build", "--release", "-p", "xtun-bench"], { cwd: repo });
  if (bench.code !== 0) {
    throw new Error(`building the reflector failed:\n${bench.err}`);
  }
  return { tests, reflect: resolve(repo, "target/release/reflect"), load: resolve(repo, "target/release/load") };
}

/// The part that runs as root: the tests, then every configuration in turn. Returns whether
/// every test passed.
function privileged(tests: string[], reflect: string, load: string, rounds: number): boolean {
  const lines: string[] = [];
  const say = (line: string) => {
    console.log(line);
    lines.push(line);
  };
  let passed = true;
  for (const test of tests) {
    // Everything the tests print, so that a failure shows its message and where it happened.
    const testRun = spawnSync(test, ["--ignored", "--test-threads=1", "--nocapture"], { encoding: "utf8", cwd: repo });
    passed = testRun.status === 0 && passed;
    say((testRun.stdout ?? "").trim());
    const errors = (testRun.stderr ?? "").trim();
    if (errors !== "") {
      say(errors);
    }
  }

  const peer = "10.80.0.2";
  const percentile = (values: number[], fraction: number) =>
    [...values].sort((a, b) => a - b)[Math.min(values.length - 1, Math.floor(values.length * fraction))];
  const measure = (backend: string) => {
    const child = spawnSync("sh", ["-c", `${reflect} ${backend} pass --offload off > /tmp/xtun-reflect.log 2>&1 & echo $!`], { encoding: "utf8" });
    const pid = Number(child.stdout.trim());
    for (let i = 0; i < 100 && !/^ready/m.test(readFileSync("/tmp/xtun-reflect.log", "utf8")); i += 1) {
      sleep(0.1);
    }
    const server = spawnSync("sh", ["-c", `${load} serve 10.80.0.1 > /dev/null 2>&1 & echo $!`], { encoding: "utf8" });
    sleep(0.5);
    // The round trip of every echo that came back, in milliseconds.
    const ping = (count: number) =>
      [...run("ping", ["-c", String(count), "-i", "0.01", peer]).out.matchAll(/time=([\d.]+) ms/g)].map((match) => Number(match[1]));
    const idle = ping(100);
    const up = Number(run(load, ["up", peer, "6"]).out);
    const down = Number(run(load, ["down", peer, "6"]).out);
    const udp = Number(run(load, ["udp", peer, "6", "100"]).out) / 1e6;
    // The ping times while one TCP flow runs to the peer, paced to `gbit` or as fast as it goes.
    const pingUnder = (gbit?: number) => {
      const rate = gbit === undefined ? "" : ` ${gbit}`;
      const background = spawnSync("sh", ["-c", `${load} up ${peer} 8${rate} > /dev/null 2>&1 & echo $!`], { encoding: "utf8" });
      sleep(1.5);
      const times = ping(400);
      run("kill", [background.stdout.trim()]);
      sleep(0.5);
      return times;
    };
    const paced = pingUnder(pacedGbit);
    const full = pingUnder();
    run("kill", [server.stdout.trim()]);
    run("kill", ["-TERM", String(pid)]);
    sleep(1);
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
  };
  const all = new Map<string, ReturnType<typeof measure>[]>();
  for (let round = 0; round < rounds; round += 1) {
    for (const backend of ["tun-rs", "xtun"]) {
      const result = measure(backend);
      all.set(backend, [...(all.get(backend) ?? []), result]);
      say(`round ${round + 1} ${backend}: ${JSON.stringify(result)}`);
    }
  }
  say("medians over rounds; ping times are the median and the 99th percentile of each run");
  say(
    `backend | TCP up Gbit/s | TCP down Gbit/s | UDP Mpps | ping idle ms | ping at ${pacedGbit} Gbit/s ms | p99 ms | ` +
      "ping at full speed ms | p99 ms",
  );
  for (const [backend, list] of all) {
    const pick = (key: keyof ReturnType<typeof measure>) => percentile(list.map((result) => result[key]), 0.5);
    say(
      `${backend} | ${pick("up").toFixed(2)} | ${pick("down").toFixed(2)} | ${pick("udp").toFixed(3)} | ` +
        `${pick("idle").toFixed(3)} | ${pick("paced").toFixed(3)} | ${pick("pacedTail").toFixed(3)} | ` +
        `${pick("full").toFixed(3)} | ${pick("fullTail").toFixed(3)}`,
    );
  }
  writeFileSync(results, `${lines.join("\n")}\n`);
  return passed;
}

function main(): void {
  const [mode, ...rest] = process.argv.slice(2);
  if (mode === "--privileged") {
    const [reflect, load, rounds, ...tests] = rest;
    process.exit(privileged(tests, reflect, load, Number(rounds)) ? 0 : 1);
  }
  const rounds = mode ?? "3";
  const { tests, reflect, load } = build();
  console.log("built; the next step runs as root and asks for the password");
  const result = spawnSync("sudo", [process.execPath, fileURLToPath(import.meta.url), "--privileged", reflect, load, rounds, ...tests], {
    stdio: "inherit",
  });
  process.exit(result.status ?? 1);
}

main();
