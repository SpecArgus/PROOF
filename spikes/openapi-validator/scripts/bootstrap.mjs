import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import {
  bootstrapPython,
  pythonExecutable,
  pythonRequirementsLock,
  pythonVirtualEnvironment,
} from "./python-runtime.mjs";

const spikeRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cacheDirectory = path.join(spikeRoot, ".cache");
const goModuleCache = path.join(cacheDirectory, "go-mod");
const goBuildCache = path.join(cacheDirectory, "go-build");
const vacuumBinary = path.join(
  cacheDirectory,
  process.platform === "win32" ? "vacuum.exe" : "vacuum",
);
const libopenapiAdapterDirectory = path.join(
  spikeRoot,
  "adapters",
  "libopenapi",
);
const libopenapiAdapterBinary = path.join(
  cacheDirectory,
  process.platform === "win32"
    ? "libopenapi-adapter.exe"
    : "libopenapi-adapter",
);

mkdirSync(cacheDirectory, { recursive: true });
mkdirSync(goModuleCache, { recursive: true });
mkdirSync(goBuildCache, { recursive: true });

const requiredNodeFiles = [
  path.join(
    spikeRoot,
    "node_modules",
    "@stoplight",
    "spectral-cli",
    "dist",
    "index.js",
  ),
  path.join(spikeRoot, "node_modules", "@redocly", "cli", "bin", "cli.js"),
  path.join(
    spikeRoot,
    "node_modules",
    "@redocly",
    "openapi-core",
    "package.json",
  ),
  path.join(spikeRoot, "node_modules", "jsonc-parser", "package.json"),
];

for (const filename of requiredNodeFiles) {
  if (!existsSync(filename)) {
    throw new Error(`Missing ${filename}. Run npm ci --ignore-scripts first.`);
  }
}

run(
  bootstrapPython,
  [
    "-c",
    "import sys; expected=(3,14,2); observed=sys.version_info[:3]; assert observed == expected, f'expected Python {expected}, observed {observed}'",
  ],
  spikeRoot,
);
rmSync(pythonVirtualEnvironment, {
  recursive: true,
  force: true,
  maxRetries: 3,
  retryDelay: 100,
});
run(
  bootstrapPython,
  ["-m", "venv", pythonVirtualEnvironment],
  spikeRoot,
);
run(
  pythonExecutable,
  [
    "-m",
    "pip",
    "install",
    "--disable-pip-version-check",
    "--no-input",
    "--require-hashes",
    "--only-binary=:all:",
    "-r",
    pythonRequirementsLock,
  ],
  spikeRoot,
  {
    PIP_DISABLE_PIP_VERSION_CHECK: "1",
    PIP_NO_INPUT: "1",
  },
);
run(
  pythonExecutable,
  [
    "-c",
    "import importlib.metadata as m; assert m.version('openapi-spec-validator') == '0.9.0'",
  ],
  spikeRoot,
);

const goEnvironment = {
  GOBIN: cacheDirectory,
  GOCACHE: goBuildCache,
  GOMODCACHE: goModuleCache,
  GOTOOLCHAIN: "go1.25.12",
};

run(
  "go",
  [
    "install",
    "github.com/daveshanley/vacuum@v0.29.10",
  ],
  spikeRoot,
  goEnvironment,
);
run(
  "go",
  ["install", "golang.org/x/vuln/cmd/govulncheck@v1.6.0"],
  spikeRoot,
  goEnvironment,
);

run(
  "go",
  ["-C", libopenapiAdapterDirectory, "mod", "download"],
  spikeRoot,
  goEnvironment,
);
run(
  "go",
  [
    "-C",
    libopenapiAdapterDirectory,
    "build",
    "-trimpath",
    "-buildvcs=false",
    "-o",
    libopenapiAdapterBinary,
    ".",
  ],
  spikeRoot,
  goEnvironment,
);

run(vacuumBinary, ["version"], spikeRoot, {
  VACUUM_NO_UPDATE_CHECK: "true",
});
run(process.execPath, [requiredNodeFiles[0], "--version"], spikeRoot);
run(process.execPath, [requiredNodeFiles[1], "--version"], spikeRoot, {
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
