// Runs the tests on real Linux interfaces inside a privileged container.
//
//   node scripts/linux.ts            unit tests and device tests
//   node scripts/linux.ts <filter>   only the device tests whose names contain <filter>

import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..");
const proxy = "http://http.docker.internal:3128";
const image = "xtun-test";
/// Every runtime and adapter, so that the tests cover them all.
export const features = "--features async-io,futures";

export const volumes = [
  "-v", `${repo}:/src:ro`,
  "-v", "xtun-target:/target",
  "-v", "xtun-cargo:/usr/local/cargo/registry",
];

export const privileged = [
  "--privileged",
  "--sysctl", "net.ipv6.conf.all.disable_ipv6=0",
  "--sysctl", "net.ipv6.conf.default.disable_ipv6=0",
  "--sysctl", "net.ipv4.ip_forward=1",
  "--sysctl", "net.ipv6.conf.all.forwarding=1",
  "--sysctl", "net.ipv4.conf.all.rp_filter=0",
  "--sysctl", "net.ipv4.conf.default.rp_filter=0",
];

export const environment = [
  "-e", "CARGO_TARGET_DIR=/target",
  "-e", `CARGO_HTTP_PROXY=${proxy}`,
  "-e", `http_proxy=${proxy}`,
  "-e", `https_proxy=${proxy}`,
];

export function buildImage(): string {
  const result = spawnSync(
    "docker",
    ["build", "-q", "-t", image, "--build-arg", `http_proxy=${proxy}`, "--build-arg", `https_proxy=${proxy}`, resolve(here, "linux")],
    { encoding: "utf8" },
  );
  if (result.status !== 0) {
    throw new Error(`building the image failed:\n${result.stderr}`);
  }
  return image;
}

function main(): void {
  const filter = process.argv[2] ?? "";
  buildImage();
  const script = [
    "set -e",
    "uname -r",
    filter === "" ? `cargo test --release --locked -p xtun-wire --lib 2>&1 | grep -E '^test result|FAILED|panicked'` : "true",
    filter === "" ? `cargo test --release --locked ${features} --lib 2>&1 | grep -E '^test result|FAILED|panicked'` : "true",
    `cargo test --release --locked --no-fail-fast ${features} --test device --test tap --test kernel -- --ignored --test-threads=1 --nocapture ${filter} 2>&1 | grep -vE '^\\s*$'`,
  ].join("\n");
  const result = spawnSync(
    "docker",
    ["run", "--rm", ...privileged, ...volumes, ...environment, "-w", "/src", image, "sh", "-c", script],
    { stdio: "inherit" },
  );
  process.exit(result.status ?? 1);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
