import { spawn, spawnSync } from "node:child_process";
import {
  cpSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import path from "node:path";
import {
  sha256File,
  stageOneInputSha256,
} from "./provenance.mjs";

const spikeRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cacheRoot = path.join(spikeRoot, ".cache");
const corpusRoot = path.join(spikeRoot, "corpus");
const manifest = JSON.parse(
  readFileSync(path.join(corpusRoot, "manifest.json"), "utf8"),
);
const manifestErrors = validateManifest(manifest);
if (manifestErrors.length > 0) {
  process.stderr.write(
    `Invalid stock CLI corpus manifest:\n- ${manifestErrors.join("\n- ")}\n`,
  );
  process.exit(2);
}
const candidates = [
  {
    id: "vacuum",
    command: path.join(
      cacheRoot,
      process.platform === "win32" ? "vacuum.exe" : "vacuum",
    ),
    args(entrypoint) {
      return [
        "spectral-report",
        entrypoint,
        "-o",
        "-n",
        "--no-style",
        "--ruleset",
        path.join(spikeRoot, "candidates", "vacuum", "ruleset.yaml"),
        "--remote=false",
        "--resolve-all-refs",
        "--no-update-check",
      ];
    },
    environment: {
      VACUUM_NO_UPDATE_CHECK: "true",
    },
    parser: parseVacuum,
  },
  {
    id: "spectral",
    command: process.execPath,
    args(entrypoint) {
      return [
        path.join(
          spikeRoot,
          "node_modules",
          "@stoplight",
          "spectral-cli",
          "dist",
          "index.js",
        ),
        "lint",
        entrypoint,
        "--ruleset",
        path.join(spikeRoot, "candidates", "spectral", ".spectral.yaml"),
        "--format",
        "json",
        "--quiet",
        "--fail-severity",
        "error",
      ];
    },
    environment: {
      SCARF_ANALYTICS: "false",
    },
    parser: parseSpectralCompatible,
  },
  {
    id: "redocly",
    command: process.execPath,
    args(entrypoint) {
      return [
        path.join(
          spikeRoot,
          "node_modules",
          "@redocly",
          "cli",
          "bin",
          "cli.js",
        ),
        "lint",
        entrypoint,
        "--config",
        path.join(spikeRoot, "candidates", "redocly", "redocly.yaml"),
        "--format",
        "json",
        "--max-problems",
        String(manifest.limits.maxDiagnostics),
      ];
    },
    environment: {
      REDOCLY_TELEMETRY: "off",
      REDOCLY_SUPPRESS_UPDATE_NOTICE: "true",
    },
    parser: parseRedocly,
  },
];
const initialProvenance = collectStageOneProvenance();

mkdirSync(cacheRoot, { recursive: true });
const canary = await createCanary();
const results = [];

try {
  for (const candidate of candidates) {
    for (const fixture of manifest.cases) {
      const repeat = fixture.repeat ?? manifest.limits.defaultRepeat;
      const attempts = [];

      for (let iteration = 0; iteration < repeat; iteration += 1) {
        const workspaceRoot = path.join(
          cacheRoot,
          "workspaces",
          candidate.id,
          fixture.id,
          String(iteration),
        );
        rmSync(workspaceRoot, {
          recursive: true,
          force: true,
          maxRetries: 3,
          retryDelay: 100,
        });
        mkdirSync(workspaceRoot, { recursive: true });
        cpSync(path.join(corpusRoot, "cases"), path.join(workspaceRoot, "cases"), {
          recursive: true,
        });

        const entrypoint = materializeFixture(
          fixture,
          workspaceRoot,
          canary.port,
        );
        const inputBytes = statSync(entrypoint).size;
        const candidateCwd = path.dirname(entrypoint);
        let nativeProbe = null;

        if (
          fixture.expected === "remote-denied" ||
          fixture.expected === "input-too-large"
        ) {
          const beforeNativeRequests = canary.requests.length;
          const nativeExecution = await executeCandidate(
            candidate,
            entrypoint,
            candidateCwd,
            manifest.limits,
          );
          const nativeNormalization = normalizeDiagnostics(
            candidate.parser(
              nativeExecution.stdout,
              nativeExecution.stderr,
              entrypoint,
            ),
            workspaceRoot,
            candidateCwd,
            manifest.limits.maxDiagnostics,
            canary.url,
          );
          const nativeDiagnostics = nativeNormalization.diagnostics;
          const nativeOutcome = classifyOutcome(
            nativeExecution,
            nativeDiagnostics,
          );
          const nativeNetworkAttempts =
            canary.requests.length - beforeNativeRequests;
          const nativeAssertion = assertNativeRequirement(
            fixture,
            nativeOutcome,
            nativeNetworkAttempts,
            nativeDiagnostics,
          );
          nativeProbe = {
            outcome: nativeOutcome,
            networkAttempts: nativeNetworkAttempts,
            meetsRequirement: nativeAssertion.passed,
            failures: nativeAssertion.failures,
            diagnostics: nativeDiagnostics,
            diagnosticCounts: nativeNormalization.counts,
            process: summarizeProcess(nativeExecution, inputBytes),
            raw: {
              stdout: nativeExecution.stdout,
              stderr: nativeExecution.stderr,
            },
          };
        }

        const beforeRequests = canary.requests.length;
        let execution;
        const remoteReference = findRemoteReference(entrypoint);

        if (
          fixture.preflightLimitBytes !== undefined &&
          inputBytes > fixture.preflightLimitBytes
        ) {
          execution = {
            exitCode: 0,
            signal: null,
            timedOut: false,
            outputLimited: false,
            forcedSettlement: false,
            terminationDetail: null,
            elapsedMs: 0,
            stdout: "[]",
            stderr: "",
            stdoutBytes: 2,
            stderrBytes: 0,
            preflightDiagnostic: {
              code: "proof-input-too-large",
              message: `Input is ${inputBytes} bytes; limit is ${fixture.preflightLimitBytes} bytes.`,
              severity: "error",
              source: entrypoint,
              pointer: "",
              line: null,
              column: null,
              kind: "policy",
            },
          };
        } else if (remoteReference) {
          execution = {
            exitCode: 0,
            signal: null,
            timedOut: false,
            outputLimited: false,
            forcedSettlement: false,
            terminationDetail: null,
            elapsedMs: 0,
            stdout: "[]",
            stderr: "",
            stdoutBytes: 2,
            stderrBytes: 0,
            preflightDiagnostic: {
              code: "proof-remote-reference-denied",
              message: `Remote references are disabled: ${remoteReference.url}`,
              severity: "error",
              source: entrypoint,
              pointer: remoteReference.pointer,
              line: remoteReference.line,
              column: remoteReference.column,
              kind: "policy",
            },
          };
        } else {
          execution = await executeCandidate(
            candidate,
            entrypoint,
            candidateCwd,
            manifest.limits,
          );
        }

        const networkAttempts = canary.requests.length - beforeRequests;
        const parsedDiagnostics = execution.preflightDiagnostic
          ? [execution.preflightDiagnostic]
          : candidate.parser(execution.stdout, execution.stderr, entrypoint);
        const normalization = normalizeDiagnostics(
          parsedDiagnostics,
          workspaceRoot,
          candidateCwd,
          manifest.limits.maxDiagnostics,
          canary.url,
        );
        const diagnostics = normalization.diagnostics;
        const outcome = classifyOutcome(execution, diagnostics);
        const processSummary = summarizeProcess(execution, inputBytes);
        const canonical = JSON.stringify({
          outcome,
          diagnostics,
          diagnosticCounts: normalization.counts,
          networkAttempts,
          process: canonicalProcess(processSummary),
          nativeProbe: canonicalNativeProbe(nativeProbe),
        });

        attempts.push({
          iteration,
          outcome,
          networkAttempts,
          canonicalSha256: sha256(canonical),
          diagnostics,
          diagnosticCounts: normalization.counts,
          process: processSummary,
          nativeProbe,
          raw: {
            stdout: execution.stdout,
            stderr: execution.stderr,
          },
        });
      }

      const uniqueHashes = [...new Set(attempts.map((item) => item.canonicalSha256))];
      const assertion = assertFixture(fixture, attempts);
      const determinism =
        repeat < 2
          ? "not-assessed"
          : uniqueHashes.length === 1
            ? "stable"
            : "unstable";
      const passed = assertion.passed && determinism !== "unstable";
      const nativeProbe = attempts[0]?.nativeProbe;
      results.push({
        candidate: candidate.id,
        caseId: fixture.id,
        expected: fixture.expected,
        determinism,
        uniqueHashes,
        passed,
        qualification: !passed
          ? "gap"
          : nativeProbe?.meetsRequirement === false
            ? "qualified-with-adapter"
            : "candidate-qualified",
        failures: [
          ...assertion.failures,
          ...(determinism !== "unstable"
            ? []
            : [`Observed ${uniqueHashes.length} normalized result hashes.`]),
        ],
        attempts,
      });
    }
  }
} finally {
  await canary.close();
}

const supervisorControls = await runSupervisorSelfTests();
const integrityErrors = Object.entries(supervisorControls)
  .filter(([, result]) => result.status === "failed")
  .map(([control, result]) => `${control}: ${result.detail}`);
const finalProvenance = collectStageOneProvenance();
if (JSON.stringify(finalProvenance) !== JSON.stringify(initialProvenance)) {
  integrityErrors.push(
    "Stock CLI evaluation inputs or candidate artifacts changed while the run was in progress.",
  );
}
const dispositions = Object.fromEntries(
  candidates.map(({ id }) => {
    const candidateResults = results.filter((result) => result.candidate === id);
    const disposition = candidateResults.some((result) => result.qualification === "gap")
      ? "has-gaps"
      : candidateResults.some(
            (result) => result.qualification === "qualified-with-adapter",
          )
        ? "qualified-with-adapter"
        : "candidate-qualified";
    return [id, disposition];
  }),
);
const summary = {
  schemaVersion: 2,
  environment: {
    platform: process.platform,
    architecture: process.arch,
    node: process.version,
  },
  provenance: initialProvenance,
  runStatus: integrityErrors.length === 0 ? "complete" : "incomplete",
  integrityErrors,
  profile: manifest.limits,
  supervisorControls,
  candidates: candidates.map(({ id }) => id),
  dispositions,
  totals: {
    cases: results.length,
    passed: results.filter((result) => result.passed).length,
    failed: results.filter((result) => !result.passed).length,
    candidateQualified: results.filter(
      (result) => result.qualification === "candidate-qualified",
    ).length,
    qualifiedWithAdapter: results.filter(
      (result) => result.qualification === "qualified-with-adapter",
    ).length,
    gaps: results.filter((result) => result.qualification === "gap").length,
  },
  results,
};

function collectStageOneProvenance() {
  return {
    stageOneInputSha256: stageOneInputSha256(),
    manifestSha256: sha256File(path.join(corpusRoot, "manifest.json")),
    packageLockSha256: sha256File(
      path.join(spikeRoot, "package-lock.json"),
    ),
    candidateArtifactSha256: {
      vacuum: sha256File(candidates[0].command),
      spectral: sha256File(
        path.join(
          spikeRoot,
          "node_modules",
          "@stoplight",
          "spectral-cli",
          "dist",
          "index.js",
        ),
      ),
      redocly: sha256File(
        path.join(
          spikeRoot,
          "node_modules",
          "@redocly",
          "cli",
          "bin",
          "cli.js",
        ),
      ),
    },
  };
}
const evidenceDirectory = path.join(cacheRoot, "evidence");
mkdirSync(evidenceDirectory, { recursive: true });
writeFileSync(
  path.join(evidenceDirectory, "summary.json"),
  `${JSON.stringify(summary, null, 2)}\n`,
  "utf8",
);

for (const result of results) {
  const marker = result.passed ? "PASS" : "GAP";
  console.log(
    `${marker} ${result.candidate}/${result.caseId}` +
      (result.failures.length ? `: ${result.failures.join(" ")}` : ""),
  );
}
console.log(
  `Evaluation complete: ${summary.totals.passed}/${summary.totals.cases} candidate cases passed.`,
);
console.log(`Evidence: ${path.join(evidenceDirectory, "summary.json")}`);

if (summary.runStatus !== "complete") {
  process.exitCode = 2;
} else if (
  summary.totals.failed > 0 &&
  (process.argv.includes("--strict") ||
    process.env.PROOF_STRICT_EVALUATION === "1")
) {
  process.exitCode = 1;
}

function materializeFixture(fixture, workspaceRoot, port) {
  if (fixture.path) {
    return path.join(workspaceRoot, fixture.path);
  }

  const generatedDirectory = path.join(workspaceRoot, "generated");
  mkdirSync(generatedDirectory, { recursive: true });
  const target = path.join(generatedDirectory, `${fixture.id}.json`);

  if (fixture.template) {
    const template = readFileSync(path.join(corpusRoot, fixture.template), "utf8");
    const yamlTarget = path.join(generatedDirectory, `${fixture.id}.yaml`);
    writeFileSync(yamlTarget, template.replaceAll("{{PORT}}", String(port)), "utf8");
    return yamlTarget;
  }

  if (fixture.generatedBytes !== undefined) {
    writeSizedOpenApi(target, fixture.generatedBytes);
    return target;
  }

  throw new Error(`Fixture ${fixture.id} has no materialization source.`);
}

function validateManifest(value) {
  const errors = [];
  if (!isPlainObject(value)) {
    return ["The root value must be an object."];
  }
  if (value.schemaVersion !== 1) {
    errors.push(`schemaVersion must be 1, observed ${String(value.schemaVersion)}.`);
  }
  if (!isPlainObject(value.limits)) {
    errors.push("limits must be an object.");
  } else {
    for (const name of [
      "timeoutMs",
      "maxOutputBytes",
      "maxDiagnostics",
      "defaultRepeat",
    ]) {
      if (!Number.isSafeInteger(value.limits[name]) || value.limits[name] < 1) {
        errors.push(`limits.${name} must be a positive safe integer.`);
      }
    }
  }
  if (!Array.isArray(value.cases) || value.cases.length === 0) {
    errors.push("cases must be a non-empty array.");
    return errors;
  }

  const ids = new Set();
  const expectedValues = new Set([
    "valid",
    "invalid",
    "remote-denied",
    "input-too-large",
  ]);
  for (const fixture of value.cases) {
    if (!isPlainObject(fixture)) {
      errors.push("Every case must be an object.");
      continue;
    }
    if (
      typeof fixture.id !== "string" ||
      !/^[a-z0-9][a-z0-9.-]*$/.test(fixture.id)
    ) {
      errors.push(`Invalid case id: ${String(fixture.id)}.`);
    } else if (ids.has(fixture.id)) {
      errors.push(`Duplicate case id: ${fixture.id}.`);
    } else {
      ids.add(fixture.id);
    }
    if (!expectedValues.has(fixture.expected)) {
      errors.push(
        `${String(fixture.id)}: unknown expected outcome ${String(
          fixture.expected,
        )}.`,
      );
    }
    const sources = [
      fixture.path !== undefined,
      fixture.template !== undefined,
      fixture.generatedBytes !== undefined,
    ].filter(Boolean).length;
    if (sources !== 1) {
      errors.push(
        `${String(fixture.id)}: exactly one of path, template, or generatedBytes is required.`,
      );
    }
    if (
      fixture.repeat !== undefined &&
      (!Number.isSafeInteger(fixture.repeat) || fixture.repeat < 1)
    ) {
      errors.push(`${String(fixture.id)}: repeat must be a positive safe integer.`);
    }
    if (
      fixture.preflightLimitBytes !== undefined &&
      (!Number.isSafeInteger(fixture.preflightLimitBytes) ||
        fixture.preflightLimitBytes < 1)
    ) {
      errors.push(
        `${String(fixture.id)}: preflightLimitBytes must be a positive safe integer.`,
      );
    }
    if (
      fixture.expected === "input-too-large" &&
      (fixture.generatedBytes === undefined ||
        fixture.preflightLimitBytes === undefined)
    ) {
      errors.push(
        `${String(fixture.id)}: input-too-large cases require generatedBytes and preflightLimitBytes.`,
      );
    }
    if (
      fixture.expected === "input-too-large" &&
      Number.isSafeInteger(fixture.generatedBytes) &&
      Number.isSafeInteger(fixture.preflightLimitBytes) &&
      fixture.generatedBytes <= fixture.preflightLimitBytes
    ) {
      errors.push(
        `${String(fixture.id)}: generatedBytes must exceed preflightLimitBytes.`,
      );
    }
    if (
      fixture.expected !== "input-too-large" &&
      fixture.preflightLimitBytes !== undefined
    ) {
      errors.push(
        `${String(fixture.id)}: preflightLimitBytes is only valid for input-too-large cases.`,
      );
    }
    if (
      fixture.expected === "remote-denied" &&
      fixture.template === undefined
    ) {
      errors.push(
        `${String(fixture.id)}: remote-denied cases require a template.`,
      );
    }
    if (
      fixture.requiresLocation !== undefined &&
      typeof fixture.requiresLocation !== "boolean"
    ) {
      errors.push(`${String(fixture.id)}: requiresLocation must be boolean.`);
    }
    for (const field of [
      "evidenceAnyPointerStartsWith",
      "evidenceAnyCodeIncludes",
      "evidenceAnyMessageIncludes",
    ]) {
      if (
        fixture[field] !== undefined &&
        (!Array.isArray(fixture[field]) ||
          fixture[field].length === 0 ||
          fixture[field].some(
            (item) => typeof item !== "string" || item.length === 0,
          ))
      ) {
        errors.push(
          `${String(fixture.id)}: ${field} must be a non-empty string array.`,
        );
      }
    }
    if (fixture.path !== undefined) {
      validateFixtureFile(
        fixture.path,
        "cases",
        `${String(fixture.id)} path`,
        errors,
      );
    }
    if (fixture.template !== undefined) {
      validateFixtureFile(
        fixture.template,
        "templates",
        `${String(fixture.id)} template`,
        errors,
      );
      if (
        typeof fixture.template === "string" &&
        isPortableFixturePath(fixture.template, "templates")
      ) {
        const templateTarget = path.resolve(
          corpusRoot,
          ...fixture.template.split("/"),
        );
        try {
          if (
            lstatSync(templateTarget).isFile() &&
            !readFileSync(templateTarget, "utf8").includes("{{PORT}}")
          ) {
            errors.push(
              `${String(fixture.id)}: remote-reference templates must contain {{PORT}}.`,
            );
          }
        } catch {
          // validateFixtureFile reports missing and non-regular paths.
        }
      }
    }
    if (
      fixture.generatedBytes !== undefined &&
      (!Number.isSafeInteger(fixture.generatedBytes) ||
        fixture.generatedBytes < 1)
    ) {
      errors.push(
        `${String(fixture.id)}: generatedBytes must be a positive safe integer.`,
      );
    }
  }
  return errors;
}

function validateFixtureFile(value, expectedDirectory, label, errors) {
  if (!isPortableFixturePath(value, expectedDirectory)) {
    errors.push(
      `${label} must be a portable relative file below ${expectedDirectory}/.`,
    );
    return;
  }
  const target = path.resolve(corpusRoot, ...value.split("/"));
  const relative = path.relative(corpusRoot, target);
  if (
    relative === "" ||
    relative === ".." ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    errors.push(`${label} escapes the corpus root.`);
    return;
  }
  try {
    if (!lstatSync(target).isFile()) {
      errors.push(`${label} must resolve to a regular committed file.`);
    }
  } catch {
    errors.push(`${label} does not exist.`);
  }
}

function isPortableFixturePath(value, expectedDirectory) {
  const segments = typeof value === "string" ? value.split("/") : [];
  const portable =
    typeof value === "string" &&
    value.length > 0 &&
    !value.includes("\\") &&
    !path.posix.isAbsolute(value) &&
    !path.win32.isAbsolute(value) &&
    value.startsWith(`${expectedDirectory}/`) &&
    segments.every(
      (segment) => segment.length > 0 && segment !== "." && segment !== "..",
    );
  if (!portable) {
    return false;
  }
  const target = path.resolve(corpusRoot, ...segments);
  const relative = path.relative(corpusRoot, target);
  return (
    relative !== "" &&
    relative !== ".." &&
    !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative)
  );
}

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function writeSizedOpenApi(target, targetBytes) {
  const prefix =
    '{"openapi":"3.1.0","info":{"title":"Sized fixture","version":"1.0.0"},"paths":{},"x-padding":"';
  const suffix = '"}';
  const fixedBytes = Buffer.byteLength(prefix) + Buffer.byteLength(suffix);
  const paddingBytes = targetBytes - fixedBytes;

  if (paddingBytes < 0) {
    throw new Error(`Target size ${targetBytes} is too small.`);
  }

  writeFileSync(target, `${prefix}${"a".repeat(paddingBytes)}${suffix}`, "utf8");
  const actualBytes = statSync(target).size;
  if (actualBytes !== targetBytes) {
    throw new Error(`Generated ${actualBytes} bytes instead of ${targetBytes}.`);
  }
}

function findRemoteReference(entrypoint) {
  const text = readFileSync(entrypoint, "utf8");
  const pattern =
    /(?<key>["']?\$ref["']?\s*:\s*["']?)(?<url>https?:\/\/[^"',}\s]+)/g;
  const match = pattern.exec(text);
  if (!match?.groups) {
    return null;
  }

  const urlOffset = match.index + match.groups.key.length;
  const before = text.slice(0, urlOffset);
  const lines = before.split(/\r?\n/);
  return {
    url: match.groups.url,
    pointer: "",
    line: lines.length,
    column: lines.at(-1).length + 1,
  };
}

async function executeCandidate(candidate, entrypoint, cwd, limits) {
  const startedAt = performance.now();
  const stdoutChunks = [];
  const stderrChunks = [];
  let timedOut = false;
  let outputLimited = false;
  let outputBytes = 0;
  let forcedSettlement = false;
  let terminationDetail = null;

  const child = spawn(candidate.command, candidate.args(entrypoint), {
    cwd,
    env: sanitizedEnvironment({
      TZ: "UTC",
      LANG: "C.UTF-8",
      LC_ALL: "C.UTF-8",
      NO_COLOR: "1",
      ...candidate.environment,
    }),
    windowsHide: true,
    detached: process.platform !== "win32",
  });
  let settleProcess;
  let settlementTimer = null;
  const completionPromise = new Promise((resolve, reject) => {
    let settled = false;
    settleProcess = (exitCode, signal) => {
      if (settled) return;
      settled = true;
      if (settlementTimer) {
        clearTimeout(settlementTimer);
      }
      resolve({ exitCode, signal });
    };
    child.once("error", reject);
    child.once("close", settleProcess);
  });
  const terminate = () => {
    terminationDetail = terminateProcessTree(child);
    if (!settlementTimer) {
      settlementTimer = setTimeout(() => {
        forcedSettlement = true;
        terminationDetail = terminateProcessTree(child);
        child.stdout.destroy();
        child.stderr.destroy();
        child.unref();
        settleProcess(null, null);
      }, 2000);
    }
  };

  const timeout = setTimeout(() => {
    timedOut = true;
    terminate();
  }, limits.timeoutMs);

  const capture = (chunks, chunk) => {
    if (outputLimited) {
      return;
    }
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    const remaining = Math.max(0, limits.maxOutputBytes - outputBytes);
    if (remaining > 0) {
      const captured = buffer.subarray(0, remaining);
      chunks.push(captured);
      outputBytes += captured.byteLength;
    }
    if (buffer.byteLength > remaining) {
      outputLimited = true;
      terminate();
    }
  };
  child.stdout.on("data", (chunk) => capture(stdoutChunks, chunk));
  child.stderr.on("data", (chunk) => capture(stderrChunks, chunk));

  const completion = await completionPromise;
  clearTimeout(timeout);
  const stdoutBuffer = Buffer.concat(stdoutChunks);
  const stderrBuffer = Buffer.concat(stderrChunks);

  return {
    ...completion,
    timedOut,
    outputLimited,
    forcedSettlement,
    terminationDetail,
    elapsedMs: Math.round((performance.now() - startedAt) * 100) / 100,
    stdout: stdoutBuffer.toString("utf8"),
    stderr: stderrBuffer.toString("utf8"),
    stdoutBytes: stdoutBuffer.byteLength,
    stderrBytes: stderrBuffer.byteLength,
  };
}

function sanitizedEnvironment(overrides = {}) {
  const environment = {
    ...process.env,
    ...overrides,
  };
  for (const name of ["NODE_OPTIONS", "NODE_PATH"]) {
    delete environment[name];
  }
  return environment;
}

async function runSupervisorSelfTests() {
  const timeoutLimitMs = 100;
  const timeoutExecution = await executeCandidate(
    {
      command: process.execPath,
      args: () => ["-e", "setInterval(() => {}, 1000)"],
      environment: {},
    },
    "",
    spikeRoot,
    {
      ...manifest.limits,
      timeoutMs: timeoutLimitMs,
    },
  );

  const outputLimitBytes = 4097;
  const outputExecution = await executeCandidate(
    {
      command: process.execPath,
      args: () => [
        "-e",
        `process.stdout.write("😀".repeat(${outputLimitBytes}))`,
      ],
      environment: {},
    },
    "",
    spikeRoot,
    {
      ...manifest.limits,
      timeoutMs: 1000,
      maxOutputBytes: outputLimitBytes,
    },
  );

  const diagnosticLimit = 100;
  const diagnosticNormalization = normalizeDiagnostics(
    Array.from({ length: 150 }, (_, index) => ({
      source: path.join(spikeRoot, "synthetic.yaml"),
      line: index + 1,
      column: 1,
      pointer: `/paths/${index}`,
      code: "synthetic",
      severity: "error",
      kind: "finding",
      message: `Synthetic diagnostic ${index}`,
    })),
    spikeRoot,
    spikeRoot,
    diagnosticLimit,
  );
  const processTreeExecution = await executeCandidate(
    {
      command: process.execPath,
      args: () => [
        "-e",
        [
          'const { spawn } = require("node:child_process");',
          "const descendant = spawn(process.execPath,",
          '  ["-e", "setInterval(() => {}, 1000)"],',
          '  { stdio: "ignore", windowsHide: true });',
          "process.stdout.write(String(descendant.pid));",
          "setInterval(() => {}, 1000);",
        ].join("\n"),
      ],
      environment: {},
    },
    "",
    spikeRoot,
    {
      ...manifest.limits,
      timeoutMs: 500,
    },
  );
  const descendantPid = Number(processTreeExecution.stdout.trim());
  await new Promise((resolve) => setTimeout(resolve, 100));
  const descendantAlive =
    Number.isInteger(descendantPid) && descendantPid > 0
      ? isProcessAlive(descendantPid)
      : true;
  if (descendantAlive && Number.isInteger(descendantPid)) {
    terminatePid(descendantPid);
  }

  return {
    timeout: {
      status:
        timeoutExecution.timedOut &&
        !timeoutExecution.forcedSettlement &&
        timeoutExecution.elapsedMs < timeoutLimitMs + 1000
          ? "passed"
          : "failed",
      detail: `timedOut=${timeoutExecution.timedOut}, forcedSettlement=${timeoutExecution.forcedSettlement}, termination=${timeoutExecution.terminationDetail}, elapsedMs=${timeoutExecution.elapsedMs}`,
    },
    outputBytes: {
      status:
        outputExecution.outputLimited &&
        !outputExecution.forcedSettlement &&
        outputExecution.stdoutBytes + outputExecution.stderrBytes <=
          outputLimitBytes
          ? "passed"
          : "failed",
      detail:
        `outputLimited=${outputExecution.outputLimited}, ` +
        `forcedSettlement=${outputExecution.forcedSettlement}, ` +
        `termination=${outputExecution.terminationDetail}, ` +
        `capturedBytes=${
          outputExecution.stdoutBytes + outputExecution.stderrBytes
        }`,
    },
    diagnosticVolume: {
      status:
        diagnosticNormalization.counts.truncated &&
        diagnosticNormalization.counts.emitted === diagnosticLimit
          ? "passed"
          : "failed",
      detail: JSON.stringify(diagnosticNormalization.counts),
    },
    processTree: {
      status:
        processTreeExecution.timedOut &&
        !processTreeExecution.forcedSettlement &&
        !descendantAlive
          ? "passed"
          : "failed",
      detail:
        `timedOut=${processTreeExecution.timedOut}, ` +
        `forcedSettlement=${processTreeExecution.forcedSettlement}, ` +
        `termination=${processTreeExecution.terminationDetail}, ` +
        `descendantPid=${
          Number.isInteger(descendantPid) ? descendantPid : "unavailable"
        }, descendantAlive=${descendantAlive}`,
    },
    memory: {
      status: "unsupported",
      detail: "Candidate CLIs expose no portable hard memory limit; enforce it in the worker/container.",
    },
    referenceDepth: {
      status: "unsupported",
      detail: "Candidate CLIs expose no common reference-depth limit; enforce it in a root-confined resolver.",
    },
  };
}

function terminateProcessTree(child) {
  if (!child.pid) {
    return "no-pid";
  }
  if (process.platform === "win32") {
    const result = spawnSync(
      "taskkill.exe",
      ["/PID", String(child.pid), "/T", "/F"],
      {
        windowsHide: true,
        stdio: "ignore",
        timeout: 2000,
      },
    );
    if (!result.error && result.status === 0) {
      return "taskkill";
    }
    try {
      child.kill("SIGKILL");
      return `direct-kill-after-taskkill-${result.error?.code ?? result.status ?? "unknown"}`;
    } catch {
      return `kill-failed-after-taskkill-${result.error?.code ?? result.status ?? "unknown"}`;
    }
  }
  try {
    process.kill(-child.pid, "SIGKILL");
    return "process-group-kill";
  } catch {
    try {
      child.kill("SIGKILL");
      return "direct-kill-after-group-failure";
    } catch {
      return "kill-failed";
    }
  }
}

function isProcessAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code !== "ESRCH";
  }
}

function terminatePid(pid) {
  if (process.platform === "win32") {
    const result = spawnSync(
      "taskkill.exe",
      ["/PID", String(pid), "/T", "/F"],
      {
        windowsHide: true,
        stdio: "ignore",
        timeout: 2000,
      },
    );
    if (!result.error && result.status === 0) {
      return;
    }
  }
  try {
    process.kill(pid, "SIGKILL");
  } catch {
    // Best-effort direct cleanup for a failed self-test.
  }
}

function parseVacuum(stdout, stderr, entrypoint) {
  return parseJsonDiagnostics(stdout, stderr, entrypoint, (item) => ({
    code: String(item.code ?? "unknown"),
    message: String(item.message ?? ""),
    severity: severityName(item.severity),
    source: item.source ?? entrypoint,
    pointer: pointerFromPath(item.path),
    line: numberOrNull(item.range?.start?.line),
    column: numberOrNull(item.range?.start?.character),
    kind: "finding",
  }), "vacuum");
}

function parseSpectralCompatible(stdout, stderr, entrypoint) {
  return parseJsonDiagnostics(stdout, stderr, entrypoint, (item) => ({
    code: String(item.code ?? "unknown"),
    message: String(item.message ?? ""),
    severity: severityName(item.severity),
    source: item.source ?? entrypoint,
    pointer: pointerFromPath(item.path),
    line: toOneBased(item.range?.start?.line),
    column: toOneBased(item.range?.start?.character),
    kind: "finding",
  }), "spectral");
}

function parseRedocly(stdout, stderr, entrypoint) {
  if (!stdout.trim()) {
    const parseLocation = /\((\d+):(\d+)\)/.exec(stderr);
    if (parseLocation) {
      return [
        {
          code: "redocly-parse-error",
          message: stderr.trim(),
          severity: "error",
          source: entrypoint,
          pointer: "",
          line: Number(parseLocation[1]),
          column: Number(parseLocation[2]),
          kind: "parse-error",
        },
      ];
    }
  }

  return parseJsonDiagnostics(stdout, stderr, entrypoint, (item) => {
    const location = Array.isArray(item.location) ? item.location[0] : item.location;
    return {
      code: String(item.ruleId ?? item.code ?? "unknown"),
      message: String(item.message ?? ""),
      severity: String(item.severity ?? "error").toLowerCase(),
      source:
        location?.source?.absoluteRef ??
        location?.source?.ref ??
        item.source ??
        entrypoint,
      pointer: location?.pointer ?? pointerFromPath(item.path),
      line:
        location?.start?.line ??
        location?.start?.lineNumber ??
        item.line ??
        null,
      column:
        location?.start?.col ??
        location?.start?.column ??
        item.column ??
        null,
      kind: "finding",
    };
  }, "redocly");
}

function parseJsonDiagnostics(stdout, stderr, entrypoint, mapper, candidateId) {
  const trimmed = stdout.trim();
  if (!trimmed) {
    if (!stderr.trim()) {
      return [];
    }
    return [
      {
        code: "candidate-stderr",
        message: stderr.trim(),
        severity: "error",
        source: entrypoint,
        pointer: "",
        line: null,
        column: null,
        kind: "uncontrolled-error",
      },
    ];
  }

  try {
    const parsed = JSON.parse(trimmed);
    const items = Array.isArray(parsed)
      ? parsed
      : parsed.problems ?? parsed.diagnostics ?? [];
    return items.map(mapper);
  } catch (error) {
    return [
      {
        code:
          candidateId === "vacuum" && /Failed to parse specification/i.test(trimmed)
            ? "vacuum-parse-error"
            : "candidate-output-unparsed",
        message: `${error.message}: ${trimmed.slice(0, 500)}${
          stderr.trim() ? `\n${stderr.trim()}` : ""
        }`,
        severity: "error",
        source: entrypoint,
        pointer: "",
        line: null,
        column: null,
        kind:
          candidateId === "vacuum" && /Failed to parse specification/i.test(trimmed)
            ? "parse-error"
            : "uncontrolled-error",
      },
    ];
  }
}

function normalizeDiagnostics(
  diagnostics,
  workspaceRoot,
  candidateCwd,
  maxDiagnostics,
  canaryUrl,
) {
  const normalized = diagnostics
    .map((diagnostic) => ({
      source: normalizeSource(
        diagnostic.source,
        workspaceRoot,
        candidateCwd,
        canaryUrl,
      ),
      line: numberOrNull(diagnostic.line),
      column: numberOrNull(diagnostic.column),
      pointer: normalizePointer(diagnostic.pointer),
      code: diagnostic.code || "unknown",
      severity: diagnostic.severity || "error",
      kind: diagnostic.kind || "finding",
      message: normalizeMessage(diagnostic.message, workspaceRoot, canaryUrl),
    }))
    .sort(compareDiagnostics)
    .filter((diagnostic, index, all) => {
      return index === 0 || JSON.stringify(diagnostic) !== JSON.stringify(all[index - 1]);
    });
  return {
    diagnostics: normalized.slice(0, maxDiagnostics),
    counts: {
      raw: diagnostics.length,
      deduplicated: normalized.length,
      emitted: Math.min(normalized.length, maxDiagnostics),
      truncated: normalized.length > maxDiagnostics,
    },
  };
}

function normalizeMessage(message, workspaceRoot, canaryUrl) {
  const windowsRoot = workspaceRoot.replaceAll("/", "\\");
  const portableRoot = workspaceRoot.replaceAll("\\", "/");
  let normalized = stripAnsi(String(message ?? "")).replaceAll("\r\n", "\n");
  for (const root of [windowsRoot, portableRoot]) {
    normalized = normalized.replace(
      new RegExp(escapeRegExp(root), "gi"),
      "<workspace>",
    );
  }
  if (canaryUrl) {
    normalized = normalized.replaceAll(canaryUrl, "<canary>");
  }
  return normalized.trim();
}

function stripAnsi(value) {
  return value.replace(/\u001B\[[0-?]*[ -/]*[@-~]/g, "");
}

function normalizePointer(pointer) {
  if (!pointer || pointer === "#") {
    return "";
  }
  return String(pointer).startsWith("#")
    ? String(pointer).slice(1)
    : String(pointer);
}

function normalizeSource(source, workspaceRoot, candidateCwd, canaryUrl) {
  if (!source) {
    return null;
  }
  const raw = String(source);
  if (/^[a-z][a-z\d+.-]*:\/\//i.test(raw)) {
    return canaryUrl ? raw.replace(canaryUrl, "<canary>") : raw;
  }
  const resolved = path.resolve(
    path.isAbsolute(raw) ? raw : path.join(candidateCwd, raw),
  );
  const relative = path.relative(workspaceRoot, resolved);
  if (
    relative === "" ||
    (!relative.startsWith(`..${path.sep}`) &&
      relative !== ".." &&
      !path.isAbsolute(relative))
  ) {
    return relative.replaceAll("\\", "/");
  }
  return `<outside-workspace>/${path.basename(resolved)}`;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function compareDiagnostics(left, right) {
  return (
    compareNullable(left.source, right.source) ||
    compareNullable(left.line, right.line) ||
    compareNullable(left.column, right.column) ||
    left.pointer.localeCompare(right.pointer, "en") ||
    left.code.localeCompare(right.code, "en") ||
    left.severity.localeCompare(right.severity, "en") ||
    left.kind.localeCompare(right.kind, "en") ||
    left.message.localeCompare(right.message, "en")
  );
}

function compareNullable(left, right) {
  if (left === right) {
    return 0;
  }
  if (left === null || left === undefined) {
    return 1;
  }
  if (right === null || right === undefined) {
    return -1;
  }
  return typeof left === "number"
    ? left - right
    : String(left).localeCompare(String(right), "en");
}

function classifyOutcome(execution, diagnostics) {
  if (execution.timedOut) {
    return "timeout";
  }
  if (execution.outputLimited) {
    return "output-limit";
  }
  if (
    diagnostics.some(
      (diagnostic) =>
        diagnostic.severity === "error" &&
        diagnostic.kind !== "uncontrolled-error",
    )
  ) {
    return "invalid";
  }
  if (
    execution.exitCode !== 0 ||
    diagnostics.some((diagnostic) => diagnostic.kind === "uncontrolled-error")
  ) {
    return "uncontrolled-error";
  }
  return "valid";
}

function assertNativeRequirement(
  fixture,
  outcome,
  networkAttempts,
  diagnostics,
) {
  const failures = [];
  if (fixture.expected === "remote-denied") {
    if (networkAttempts !== 0) {
      failures.push(`Observed ${networkAttempts} network request(s).`);
    }
    if (outcome !== "invalid") {
      failures.push(`Expected controlled invalid result, observed ${outcome}.`);
    }
  }
  if (
    fixture.expected === "input-too-large" &&
    !diagnostics.some(
      (diagnostic) => diagnostic.code === "proof-input-too-large",
    )
  ) {
    failures.push("Candidate has no native input-size rejection.");
  }
  return {
    passed: failures.length === 0,
    failures,
  };
}

function assertFixture(fixture, attempts) {
  const failures = [];
  for (const attempt of attempts) {
    const relevantErrors = attempt.diagnostics.filter((diagnostic) => {
      if (
        diagnostic.severity !== "error" ||
        diagnostic.kind === "uncontrolled-error"
      ) {
        return false;
      }
      const anchors = [
        ...(fixture.evidenceAnyMessageIncludes ?? []).map((fragment) =>
          diagnostic.message.toLowerCase().includes(fragment.toLowerCase()),
        ),
        ...(fixture.evidenceAnyPointerStartsWith ?? []).map((prefix) =>
          diagnostic.pointer.startsWith(prefix),
        ),
        ...(fixture.evidenceAnyCodeIncludes ?? []).map((fragment) =>
          diagnostic.code.toLowerCase().includes(fragment.toLowerCase()),
        ),
      ];
      if (anchors.length === 0) {
        return true;
      }
      return anchors.some(Boolean);
    });

    if (fixture.expected === "valid" && attempt.outcome !== "valid") {
      failures.push(`Expected valid, observed ${attempt.outcome}.`);
    }
    if (fixture.expected === "invalid" && attempt.outcome !== "invalid") {
      failures.push(`Expected invalid, observed ${attempt.outcome}.`);
    }
    if (
      ["invalid", "remote-denied"].includes(fixture.expected) &&
      (fixture.evidenceAnyMessageIncludes?.length ||
        fixture.evidenceAnyPointerStartsWith?.length ||
        fixture.evidenceAnyCodeIncludes?.length) &&
      relevantErrors.length === 0
    ) {
      failures.push(
        `No controlled error matched evidence anchor: ${[
          ...(fixture.evidenceAnyMessageIncludes ?? []),
          ...(fixture.evidenceAnyPointerStartsWith ?? []),
          ...(fixture.evidenceAnyCodeIncludes ?? []),
        ].join(" | ")}.`,
      );
    }
    if (
      fixture.expected === "input-too-large" &&
      !attempt.diagnostics.some(
        (diagnostic) => diagnostic.code === "proof-input-too-large",
      )
    ) {
      failures.push("Oversized input was not rejected by preflight.");
    }
    if (fixture.expected === "remote-denied") {
      if (attempt.networkAttempts !== 0) {
        failures.push(`Observed ${attempt.networkAttempts} network request(s).`);
      }
      if (attempt.outcome !== "invalid") {
        failures.push(`Expected controlled invalid result, observed ${attempt.outcome}.`);
      }
    }
    if (
      fixture.requiresLocation &&
      !relevantErrors.some(
        (diagnostic) =>
          Number.isInteger(diagnostic.line) &&
          diagnostic.line >= 1 &&
          Number.isInteger(diagnostic.column) &&
          diagnostic.column >= 1,
      )
    ) {
      failures.push(
        "No anchor-matching diagnostic included both line and column.",
      );
    }
  }
  return {
    passed: failures.length === 0,
    failures: [...new Set(failures)],
  };
}

function pointerFromPath(segments) {
  if (!Array.isArray(segments) || segments.length === 0) {
    return "";
  }
  return `/${segments
    .map((segment) => String(segment).replaceAll("~", "~0").replaceAll("/", "~1"))
    .join("/")}`;
}

function severityName(severity) {
  return ["error", "warn", "info", "hint"][severity] ?? String(severity ?? "error");
}

function toOneBased(value) {
  return Number.isInteger(value) ? value + 1 : null;
}

function numberOrNull(value) {
  if (value === null || value === undefined || value === "") {
    return null;
  }
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function summarizeProcess(execution, inputBytes) {
  return {
    exitCode: execution.exitCode,
    signal: execution.signal,
    timedOut: execution.timedOut,
    outputLimited: execution.outputLimited,
    forcedSettlement: execution.forcedSettlement,
    terminationDetail: execution.terminationDetail,
    elapsedMs: execution.elapsedMs,
    inputBytes,
    stdoutBytes: execution.stdoutBytes,
    stderrBytes: execution.stderrBytes,
  };
}

function canonicalProcess(processSummary) {
  return {
    exitCode: processSummary.exitCode,
    signal: processSummary.signal,
    timedOut: processSummary.timedOut,
    outputLimited: processSummary.outputLimited,
    forcedSettlement: processSummary.forcedSettlement,
    terminationDetail: processSummary.terminationDetail,
    inputBytes: processSummary.inputBytes,
    stdoutBytes: processSummary.stdoutBytes,
    stderrBytes: processSummary.stderrBytes,
  };
}

function canonicalNativeProbe(nativeProbe) {
  if (!nativeProbe) {
    return null;
  }
  return {
    outcome: nativeProbe.outcome,
    networkAttempts: nativeProbe.networkAttempts,
    meetsRequirement: nativeProbe.meetsRequirement,
    failures: nativeProbe.failures,
    diagnostics: nativeProbe.diagnostics,
    diagnosticCounts: nativeProbe.diagnosticCounts,
    process: canonicalProcess(nativeProbe.process),
  };
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

async function createCanary() {
  const requests = [];
  const server = createServer((request, response) => {
    requests.push({
      method: request.method,
      url: request.url,
    });
    response.writeHead(200, {
      "content-type": "application/yaml",
    });
    response.end(
      [
        "components:",
        "  schemas:",
        "    PetList:",
        "      type: array",
        "      items:",
        "        type: string",
        "",
      ].join("\n"),
    );
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (typeof address === "string" || address === null) {
    throw new Error("Loopback canary did not expose a TCP address.");
  }

  return {
    port: address.port,
    url: `http://127.0.0.1:${address.port}`,
    requests,
    close() {
      return new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    },
  };
}
