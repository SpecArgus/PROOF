import { spawnSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import {
  pythonAdapterDirectory,
  pythonExecutable,
} from "./python-runtime.mjs";

const spikeRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cacheDirectory = path.join(spikeRoot, ".cache");
const goModuleCache = path.join(cacheDirectory, "go-mod");
const goBuildCache = path.join(cacheDirectory, "go-build");
const libopenapiAdapterDirectory = path.join(
  spikeRoot,
  "adapters",
  "libopenapi",
);
const redoclyTest = path.join(
  spikeRoot,
  "adapters",
  "redocly-core",
  "test.mjs",
);
const pythonAdapterTest = path.join(
  pythonAdapterDirectory,
  "test_adapter.py",
);

mkdirSync(goModuleCache, { recursive: true });
mkdirSync(goBuildCache, { recursive: true });

const goEnvironment = {
  GOCACHE: goBuildCache,
  GOMODCACHE: goModuleCache,
  GOTOOLCHAIN: "go1.25.12",
};

run("go", ["test", "-count=1", "./..."], libopenapiAdapterDirectory, goEnvironment);
run("go", ["vet", "./..."], libopenapiAdapterDirectory, goEnvironment);
run(process.execPath, [redoclyTest], spikeRoot);
run(
  pythonExecutable,
  ["-X", "utf8", "-I", "-B", pythonAdapterTest],
  spikeRoot,
  {
    PYTHONNOUSERSITE: "1",
    PYTHONHASHSEED: "0",
  },
);

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
