import { createHash } from "node:crypto";
import path from "node:path";
import { spikeRoot } from "./provenance.mjs";

export const pythonAdapterDirectory = path.join(
  spikeRoot,
  "adapters",
  "openapi-spec-validator",
);
export const pythonAdapterEntrypoint = path.join(
  pythonAdapterDirectory,
  "adapter.py",
);
export const pythonRequirementsLock = path.join(
  pythonAdapterDirectory,
  "requirements.lock",
);
export const pythonVirtualEnvironment = path.join(
  spikeRoot,
  ".cache",
  "openapi-spec-validator-venv-cp314",
);
export const pythonExecutable = path.join(
  pythonVirtualEnvironment,
  process.platform === "win32" ? "Scripts" : "bin",
  process.platform === "win32" ? "python.exe" : "python",
);
export const bootstrapPython = process.env.PROOF_PYTHON ?? "python";

export function pythonEnvironmentProfile(inspect) {
  if (!Array.isArray(inspect?.installed)) {
    throw new Error("pip inspect output is missing the installed package list.");
  }
  return {
    implementation:
      inspect.environment?.implementation_name ?? null,
    pythonVersion:
      inspect.environment?.implementation_version ?? null,
    platform:
      inspect.environment?.platform_system ?? null,
    architecture:
      inspect.environment?.platform_machine ?? null,
    packages: inspect.installed
      .map(({ metadata }) => ({
        name: normalizePythonName(metadata?.name ?? ""),
        version: metadata?.version ?? null,
      }))
      .filter(
        ({ name }) =>
          name.length > 0 && !["pip", "setuptools"].includes(name),
      )
      .sort(
        (left, right) =>
          left.name.localeCompare(right.name, "en") ||
          String(left.version).localeCompare(String(right.version), "en"),
      ),
  };
}

export function pythonEnvironmentSha256(inspect) {
  return createHash("sha256")
    .update(JSON.stringify(pythonEnvironmentProfile(inspect)))
    .digest("hex");
}

function normalizePythonName(value) {
  return String(value).toLowerCase().replace(/[-_.]+/g, "-");
}
