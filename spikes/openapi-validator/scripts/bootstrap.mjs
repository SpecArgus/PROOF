import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const spikeRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cacheDirectory = path.join(spikeRoot, ".cache");
const vacuumBinary = path.join(
  cacheDirectory,
  process.platform === "win32" ? "vacuum.exe" : "vacuum",
);

mkdirSync(cacheDirectory, { recursive: true });

const requiredNodeBinaries = [
  path.join(
    spikeRoot,
    "node_modules",
    "@stoplight",
    "spectral-cli",
    "dist",
    "index.js",
  ),
  path.join(spikeRoot, "node_modules", "@redocly", "cli", "bin", "cli.js"),
];

for (const binary of requiredNodeBinaries) {
  if (!existsSync(binary)) {
    throw new Error(`Missing ${binary}. Run npm ci --ignore-scripts first.`);
  }
}

run(
  "go",
  [
    "install",
    "github.com/daveshanley/vacuum@v0.29.10",
  ],
  spikeRoot,
  {
    GOBIN: cacheDirectory,
    GOTOOLCHAIN: "go1.25.12",
  },
);

run(vacuumBinary, ["version"], spikeRoot, {
  VACUUM_NO_UPDATE_CHECK: "true",
});
run(process.execPath, [requiredNodeBinaries[0], "--version"], spikeRoot);
run(process.execPath, [requiredNodeBinaries[1], "--version"], spikeRoot, {
  REDOCLY_TELEMETRY: "off",
  REDOCLY_SUPPRESS_UPDATE_NOTICE: "true",
});

function run(command, args, cwd, extraEnvironment = {}) {
  const result = spawnSync(command, args, {
    cwd,
    env: {
      ...process.env,
      ...extraEnvironment,
    },
    encoding: "utf8",
    stdio: "inherit",
  });

  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(`${command} exited with status ${result.status}.`);
  }
}
