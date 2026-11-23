// Makes the Windows machine this runs on ready for the device tests of `tests/windows.rs`, as
// `scripts/vm/windows.ts` makes one it reaches over SSH ready: `wintun.dll` and the
// TAP-Windows6 driver, which goes into the driver store, both for this machine's processor, and
// a firewall rule that lets inbound traffic to the test subnets through. Needs an administrator.
// A job of `.github/workflows/ci.yml` runs it on a machine that is thrown away afterwards, so
// nothing is taken back.
//
//   node scripts/ci/windows.ts <directory>
//
// The files go into the directory. The path of `wintun.dll` is printed, and added to the file
// `GITHUB_ENV` names as `XTUN_WINTUN`, where the steps that follow find it.

import { appendFileSync, existsSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";
import process from "node:process";

import { download, must } from "../vm/common.ts";
import { rule, tapWindows, testAddresses, wintun } from "../vm/windows.ts";

function powershell(script: string): string {
  return must("powershell", ["-NoProfile", "-NonInteractive", "-Command", script]);
}

function main(): void {
  const [given] = process.argv.slice(2);
  if (given === undefined) {
    throw new Error("usage: node scripts/ci/windows.ts <directory>");
  }
  const directory = resolve(given);
  mkdirSync(directory, { recursive: true });
  // A program that Windows runs for another processor than the machine's is told the machine's
  // in the first variable.
  const processor = process.env.PROCESSOR_ARCHITEW6432 ?? process.env.PROCESSOR_ARCHITECTURE;
  const arch = processor === "ARM64" ? "arm64" : "amd64";

  const wintunZip = resolve(directory, "wintun.zip");
  const tapZip = resolve(directory, "tap-windows6.zip");
  download(wintun.url, wintunZip, wintun.sha256);
  download(tapWindows.url, tapZip, tapWindows.sha256);
  for (const archive of [wintunZip, tapZip]) {
    powershell(`Expand-Archive -Force -LiteralPath '${archive}' -DestinationPath '${directory}'`);
  }
  const library = resolve(directory, "wintun", "bin", arch, "wintun.dll");
  const driver = resolve(directory, "dist.win10", arch, "OemVista.inf");
  for (const file of [library, driver]) {
    if (!existsSync(file)) {
      throw new Error(`the archives have no ${file}`);
    }
  }

  console.log(must("pnputil", ["/add-driver", driver, "/install"]));
  powershell(
    `New-NetFirewallRule -Name ${rule} -DisplayName ${rule} -Direction Inbound -Action Allow -Profile Any -LocalAddress ${testAddresses} | Out-Null`,
  );

  console.log(library);
  if (process.env.GITHUB_ENV !== undefined) {
    appendFileSync(process.env.GITHUB_ENV, `XTUN_WINTUN=${library}\n`);
  }
}

main();
