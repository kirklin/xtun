// Measures xtun against tun-rs on real Linux interfaces in a privileged container: the same
// reflector program over either library, TCP both ways, many small UDP packets, and ping times
// while TCP fills the link.
//
//   node scripts/bench.ts [rounds] [filter]
//
// With a filter, only the configurations whose names contain it are measured.

import { spawnSync } from "node:child_process";
import process from "node:process";

import { buildImage, environment, privileged, volumes } from "./linux.ts";

const container = "xtun-bench";
const reflect = "/target/release/reflect";
const peer = "10.80.0.2";
/// A TCP rate that every configuration of both libraries carries with room to spare. Ping times
/// under it compare the libraries under the same load. At full speed each moves as much as it
/// can, and the ping times then tell where the flows' windows wait, which the table shows apart.
const pacedGbit = 4;

interface Run {
  code: number;
  out: string;
  err: string;
}

function run(command: string, args: string[]): Run {
  const result = spawnSync(command, args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  if (result.error) {
    throw result.error;
  }
  return { code: result.status ?? -1, out: (result.stdout ?? "").trim(), err: (result.stderr ?? "").trim() };
}

function shell(command: string): Run {
  return run("docker", ["exec", container, "sh", "-c", command]);
}

function sleep(seconds: number): void {
  spawnSync("sleep", [String(seconds)]);
}

interface Config {
  name: string;
  backend: "xtun" | "tun-rs";
  args: string;
  streams: number;
}

/// The first of four consecutive client ports for TCP and for UDP. The kernel puts every flow on
/// a queue by a hash of its addresses and ports, seeded at boot, so four flows from random ports
/// often share queues and runs with four queues differ by chance. These ports are chosen once so
/// that their four flows land on four different queues, the same for both libraries.
interface Ports {
  tcp: number;
  udp: number;
}

interface Result {
  up: number;
  down: number;
  udp: number;
  idle: number;
  paced: number;
  pacedTail: number;
  full: number;
  fullTail: number;
  cpu: number;
}

function startReflector(config: Config): number {
  shell("pkill -x reflect; pkill -x iperf3; while pgrep -x reflect > /dev/null; do sleep 0.1; done");
  const pid = Number(shell(`${reflect} ${config.backend} ${config.args} > /tmp/reflect.log 2>&1 & echo $!`).out);
  for (let i = 0; i < 100; i += 1) {
    if (shell("grep -q '^ready' /tmp/reflect.log").code === 0) {
      shell("iperf3 -s -B 10.80.0.1 -D");
      sleep(0.5);
      return pid;
    }
    sleep(0.1);
  }
  throw new Error(`the reflector did not start:\n${shell("cat /tmp/reflect.log").out}`);
}

function cpuSeconds(pid: number): number {
  const fields = shell(`cat /proc/${pid}/stat`).out.split(") ")[1].split(" ");
  return (Number(fields[11]) + Number(fields[12])) / 100;
}

function iperf(args: string): Run {
  const result = shell(`iperf3 -c ${peer} ${args}`);
  if (result.code !== 0) {
    throw new Error(`iperf3 ${args} failed:\n${result.out}\n${result.err}`);
  }
  return result;
}

function tcp(extra: string, streams: number, ports: Ports): number {
  const result = iperf(`--cport ${ports.tcp} -t 6 -O 1 -P ${streams} -J ${extra}`);
  return JSON.parse(result.out).end.sum_received.bits_per_second / 1e9;
}

/// Packets per second the server received from four UDP senders of 100-byte datagrams.
function udp(ports: Ports): number {
  const result = iperf(`--cport ${ports.udp} -u -b 0 -l 100 -t 6 -O 1 -P 4 -J`);
  const sum = JSON.parse(result.out).end.sum;
  return (sum.packets - sum.lost_packets) / sum.seconds / 1e6;
}

/// Packets the kernel has put on each of the four queues, from the queue's own queueing
/// discipline under the device's `mq`.
function queuePackets(): number[] {
  const qdiscs = JSON.parse(shell("tc -s -j qdisc show dev bench0").out) as { parent?: string; packets: number }[];
  const counts = [0, 0, 0, 0];
  for (const qdisc of qdiscs) {
    const queue = Number.parseInt(qdisc.parent?.split(":")[1] ?? "0", 16) - 1;
    if (queue >= 0 && queue < counts.length) {
      counts[queue] = qdisc.packets;
    }
  }
  return counts;
}

/// The queue that carries the flow from client port `port`: the one that grows the most while
/// a few megabytes go through.
function queueOf(protocol: "tcp" | "udp", port: number): number {
  const before = queuePackets();
  iperf(`--cport ${port} -n 8M ${protocol === "udp" ? "-u -b 0 -l 1400" : ""}`);
  const growth = queuePackets().map((count, queue) => count - before[queue]);
  return growth.indexOf(Math.max(...growth));
}

function spreadPort(protocol: "tcp" | "udp", from: number): number {
  const queues: number[] = [];
  for (let port = from; port < from + 1000; port += 1) {
    queues.push(queueOf(protocol, port));
    if (queues.length >= 4 && new Set(queues.slice(-4)).size === 4) {
      return port - 3;
    }
  }
  throw new Error(`no four consecutive ${protocol} client ports from ${from} land on four queues`);
}

function choosePorts(): Ports {
  startReflector({ name: "ports", backend: "xtun", args: "pass --offload on --queues 4 --uring off", streams: 4 });
  const ports = { tcp: spreadPort("tcp", 20_000), udp: spreadPort("udp", 30_000) };
  stopReflector();
  return ports;
}

function percentile(values: number[], fraction: number): number {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * fraction))];
}

/// The round trip of every echo that came back, in milliseconds.
function ping(count: number): number[] {
  const result = shell(`ping -c ${count} -i 0.01 -W 1 ${peer}`);
  return [...result.out.matchAll(/time=([\d.]+) ms/g)].map((match) => Number(match[1]));
}

function stopReflector(): void {
  shell("pkill -x iperf3; sleep 0.2; pkill -TERM -x reflect; true");
  sleep(0.5);
}

/// The ping times while the configuration's TCP flows run to the peer, together paced to `gbit`
/// or as fast as they go.
function pingUnder(config: Config, ports: Ports, gbit?: number): number[] {
  // iperf3 takes the rate of each flow, in bits per second.
  const rate = gbit === undefined ? "" : `-b ${Math.round((gbit * 1e9) / config.streams)}`;
  const client = Number(shell(`iperf3 -c ${peer} --cport ${ports.tcp} -t 6 -P ${config.streams} ${rate} > /dev/null 2>&1 & echo $!`).out);
  sleep(1.5);
  const times = ping(400);
  // The client closes its connections through the reflector before anything else uses them.
  shell(`while kill -0 ${client} 2> /dev/null; do sleep 0.1; done`);
  return times;
}

function measure(config: Config, ports: Ports): Result {
  const pid = startReflector(config);
  const idle = ping(100);
  const before = cpuSeconds(pid);
  const up = tcp("", config.streams, ports);
  const cpu = cpuSeconds(pid) - before;
  const down = tcp("-R", config.streams, ports);
  const udpRate = udp(ports);
  const paced = pingUnder(config, ports, pacedGbit);
  const full = pingUnder(config, ports);
  stopReflector();
  return {
    up,
    down,
    udp: udpRate,
    idle: percentile(idle, 0.5),
    paced: percentile(paced, 0.5),
    pacedTail: percentile(paced, 0.99),
    full: percentile(full, 0.5),
    fullTail: percentile(full, 0.99),
    // The upload runs seven seconds: one omitted, six measured.
    cpu: cpu / Math.max((up * 7) / 8, 0.001),
  };
}

const configs: Config[] = [];
for (const [label, args, streams] of [
  ["offload, segments passed whole", "pass --offload on", 1],
  ["offload, segments cut and joined", "split --offload on", 1],
  ["no offload", "pass --offload off", 1],
  ["offload, 4 queues, 4 flows", "pass --offload on --queues 4", 4],
] as const) {
  configs.push({ name: `${label} | tun-rs`, backend: "tun-rs", args, streams });
  configs.push({ name: `${label} | xtun`, backend: "xtun", args: `${args} --uring off`, streams });
  configs.push({ name: `${label} | xtun io_uring`, backend: "xtun", args: `${args} --uring on`, streams });
}

function main(): void {
  const rounds = Number(process.argv[2] ?? "3");
  const chosen = configs.filter((config) => config.name.includes(process.argv[3] ?? ""));
  const image = buildImage();
  run("docker", ["rm", "-f", container]);
  const started = run("docker", [
    "run", "-d",
    // Reaps the reflectors that exit; a zombie would still match `pgrep`.
    "--init",
    "--name", container,
    ...privileged,
    // The client ports come back in every run; without TIME_WAIT a closed connection frees its
    // port at once.
    "--sysctl", "net.ipv4.tcp_max_tw_buckets=0",
    ...volumes, ...environment, "-w", "/src", image, "sleep", "infinity",
  ]);
  if (started.code !== 0) {
    throw new Error(started.err);
  }
  console.log(shell("uname -r; nproc").out.split("\n").join(", "));
  const build = shell("cargo build --release --locked -p xtun-bench 2>&1 | tail -1");
  console.log(build.out);
  const ports = choosePorts();
  console.log(`client ports: TCP from ${ports.tcp}, UDP from ${ports.udp}`);
  const results = new Map<string, Result[]>();
  for (let round = 0; round < rounds; round += 1) {
    for (const config of chosen) {
      const result = measure(config, ports);
      results.set(config.name, [...(results.get(config.name) ?? []), result]);
      console.log(`round ${round + 1} ${config.name}: ${JSON.stringify(result)}`);
    }
  }
  console.log("\nmedians over rounds; ping times are the median and the 99th percentile of each run");
  console.log(
    `config | TCP up Gbit/s | TCP down Gbit/s | UDP Mpps | ping idle ms | ping at ${pacedGbit} Gbit/s ms | p99 ms | ` +
      "ping at full speed ms | p99 ms | CPU s per GB up",
  );
  for (const config of chosen) {
    const list = results.get(config.name) ?? [];
    const pick = (key: keyof Result) => percentile(list.map((result) => result[key]), 0.5);
    console.log(
      `${config.name} | ${pick("up").toFixed(1)} | ${pick("down").toFixed(1)} | ${pick("udp").toFixed(2)} | ` +
        `${pick("idle").toFixed(3)} | ${pick("paced").toFixed(3)} | ${pick("pacedTail").toFixed(3)} | ` +
        `${pick("full").toFixed(3)} | ${pick("fullTail").toFixed(3)} | ${pick("cpu").toFixed(3)}`,
    );
  }
  run("docker", ["rm", "-f", container]);
}

main();
