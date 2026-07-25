import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  evaluationInputSha256,
  sha256File,
  sha256Paths,
} from "./provenance.mjs";
import {
  pythonAdapterEntrypoint,
  pythonEnvironmentProfile,
  pythonEnvironmentSha256,
  pythonExecutable,
  pythonRequirementsLock,
} from "./python-runtime.mjs";

const spikeRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cacheRoot = path.join(spikeRoot, ".cache");
const corpusRoot = path.join(spikeRoot, "corpus", "adapter-cases");
const manifestPath = path.join(corpusRoot, "manifest.json");
const workspaceBase = path.join(cacheRoot, "adapter-workspaces");
const defaultOutputPath = path.join(cacheRoot, "evidence", "adapter-summary.json");
const outputLimitBytes = 1024 * 1024;
const controlledOutcomes = new Set([
  "valid",
  "invalid",
  "parse-error",
  "policy-denied",
  "limit-exceeded",
]);
const diagnosticFields = [
  "source",
  "line",
  "column",
  "pointer",
  "code",
  "severity",
  "kind",
  "message",
];
const platform = platformName(process.platform);

try {
  await main();
} catch (error) {
  console.error(`HARNESS ERROR: ${error?.message ?? String(error)}`);
  process.exitCode = 2;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const manifest = readManifest();
  const manifestErrors = validateManifest(manifest);
  if (manifestErrors.length > 0) {
    throw new HarnessIntegrityError(
      `Invalid adapter corpus manifest:\n- ${manifestErrors.join("\n- ")}`,
    );
  }
  if (
    options.caseId !== null &&
    !manifest.cases.some(({ id }) => id === options.caseId)
  ) {
    throw new HarnessIntegrityError(`Unknown --case id: ${options.caseId}.`);
  }

  mkdirSync(workspaceBase, { recursive: true });
  const allCandidates = candidateDefinitions();
  const scope =
    options.candidate === "all" && options.caseId === null ? "full" : "partial";
  const selectedCandidates =
    options.candidate === "all"
      ? allCandidates
      : allCandidates.filter(({ id }) => id === options.candidate);
  const initialProvenanceObservation =
    collectDirectProvenance(selectedCandidates);
  const supervisorControls = await runSupervisorSelfChecks();
  const integrityErrors = [
    ...initialProvenanceObservation.errors,
    ...Object.entries(supervisorControls)
      .filter(([, control]) => control.status !== "passed")
      .map(([id, control]) => `supervisor.${id}: ${control.detail}`),
  ];
  const results = [];
  const canary = await createLoopbackCanary();
  const selectedCases =
    options.caseId === null
      ? manifest.cases
      : manifest.cases.filter(({ id }) => id === options.caseId);

  try {
    for (const candidate of selectedCandidates) {
      for (const caseDefinition of selectedCases) {
        if (!isApplicable(caseDefinition)) {
          results.push(skippedResult(candidate.id, caseDefinition));
          continue;
        }

        const unavailableReason = candidateAvailabilityError(candidate);
        if (unavailableReason) {
          results.push(unavailableResult(candidate.id, caseDefinition, unavailableReason));
          continue;
        }

        try {
          results.push(
            await evaluateCase({
              candidate,
              caseDefinition,
              manifest,
              canary,
            }),
          );
        } catch (error) {
          const detail = `${candidate.id}/${caseDefinition.id}: ${
            error?.message ?? String(error)
          }`;
          const preservedWorkspaces = unique(
            [
              ...(Array.isArray(error?.workspaceRoots)
                ? error.workspaceRoots
                : []),
              error?.workspaceRoot,
            ].filter(
              (workspace) =>
                typeof workspace === "string" && existsSync(workspace),
            ),
          );
          integrityErrors.push(detail);
          results.push({
            candidate: candidate.id,
            caseId: caseDefinition.id,
            required: caseDefinition.required === true,
            status: "harness-error",
            passed: false,
            determinism: "not-assessed",
            uniqueHashes: [],
            failures: [detail],
            attempts: [],
            preservedWorkspaces,
          });
        }
      }
    }
  } finally {
    try {
      await canary.close();
    } catch (error) {
      integrityErrors.push(
        `loopback-canary.shutdown: ${error?.message ?? String(error)}`,
      );
    }
  }

  const finalProvenanceObservation =
    collectDirectProvenance(selectedCandidates);
  integrityErrors.push(...finalProvenanceObservation.errors);
  if (
    JSON.stringify(finalProvenanceObservation.provenance) !==
    JSON.stringify(initialProvenanceObservation.provenance)
  ) {
    integrityErrors.push(
      "Direct-adapter evaluation inputs, artifacts, or runtime environments changed while the run was in progress.",
    );
  }
  const candidateSummaries = summarizeCandidates(
    selectedCandidates,
    results,
    manifest,
    scope,
    integrityErrors.length === 0,
  );
  const { candidateArtifactSha256 } =
    initialProvenanceObservation.provenance;
  for (const candidate of candidateSummaries) {
    candidate.artifactSha256 = candidateArtifactSha256[candidate.id];
  }
  const dispositions = Object.fromEntries(
    candidateSummaries.map(({ id, disposition }) => [
      id,
      disposition,
    ]),
  );
  const gateResults = Object.fromEntries(
    candidateSummaries.map(({ id, gates }) => [id, gates]),
  );
  const summary = {
    schemaVersion: 1,
    manifestSchemaVersion: manifest.schemaVersion,
    environment: {
      platform: process.platform,
      architecture: process.arch,
      node: process.version,
    },
    runStatus: integrityErrors.length === 0 ? "complete" : "incomplete",
    scope,
    coverage: {
      full: scope === "full",
      selectedCandidates: selectedCandidates.map(({ id }) => id),
      candidateCount: selectedCandidates.length,
      corpusCandidateCount: allCandidates.length,
      selectedCaseCount: selectedCases.length,
      corpusCaseCount: manifest.cases.length,
    },
    platform,
    totals: summarizeTotals(results),
    dispositions,
    gateResults,
    results,
    selectionRule: manifest.selectionRule,
    outputLimitBytes,
    profile: manifest.limitProfiles.default,
    supervisorControls,
    integrityErrors,
    candidates: candidateSummaries,
    provenance: initialProvenanceObservation.provenance,
  };

  const outputPath = options.output
    ? path.resolve(process.cwd(), options.output)
    : scope === "full"
      ? defaultOutputPath
      : path.join(
          cacheRoot,
          "evidence",
          `adapter-summary.partial.${options.candidate}.${options.caseId ?? "all"}.json`,
        );
  mkdirSync(path.dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, `${JSON.stringify(summary, null, 2)}\n`, "utf8");

  printResults(results, candidateSummaries, outputPath);

  if (integrityErrors.length > 0) {
    process.exitCode = 2;
  } else if (
    options.strict &&
    candidateSummaries.some(({ disposition }) => disposition === "has-gaps")
  ) {
    process.exitCode = 1;
  }
}

function collectDirectProvenance(candidates) {
  const errors = [];
  const candidateArtifactSha256 = {};
  const candidateRuntime = {};
  for (const candidate of candidates) {
    const available = candidate.requiredPaths.every((target) =>
      existsSync(target),
    );
    candidateArtifactSha256[candidate.id] = available
      ? artifactSha256(candidate.artifactPaths ?? candidate.requiredPaths)
      : null;
    if (!available || !candidate.runtimeEvidence) {
      continue;
    }
    try {
      candidateRuntime[candidate.id] = candidate.runtimeEvidence();
    } catch (error) {
      errors.push(
        `${candidate.id} runtime evidence: ${error?.message ?? String(error)}`,
      );
    }
  }
  return {
    errors,
    provenance: {
      evaluationInputSha256: evaluationInputSha256(),
      manifestSha256: sha256File(manifestPath),
      packageLockSha256: sha256File(
        path.join(spikeRoot, "package-lock.json"),
      ),
      candidateArtifactSha256,
      candidateRuntime,
    },
  };
}

function parseArguments(argv) {
  const options = {
    candidate: "all",
    caseId: null,
    strict: process.env.PROOF_STRICT_ADAPTER_EVALUATION === "1",
    output: null,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--strict") {
      options.strict = true;
      continue;
    }
    if (
      argument === "--candidate" ||
      argument === "--case" ||
      argument === "--output"
    ) {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) {
        throw new HarnessIntegrityError(`Missing value for ${argument}.`);
      }
      if (argument === "--case") {
        options.caseId = value;
      } else {
        options[argument.slice(2)] = value;
      }
      index += 1;
      continue;
    }
    if (argument.startsWith("--candidate=")) {
      options.candidate = argument.slice("--candidate=".length);
      continue;
    }
    if (argument.startsWith("--output=")) {
      options.output = argument.slice("--output=".length);
      continue;
    }
    if (argument.startsWith("--case=")) {
      options.caseId = argument.slice("--case=".length);
      continue;
    }
    throw new HarnessIntegrityError(`Unknown argument: ${argument}`);
  }

  const candidateIds = new Set([
    "all",
    "libopenapi",
    "redocly-core",
    "openapi-spec-validator",
  ]);
  if (!candidateIds.has(options.candidate)) {
    throw new HarnessIntegrityError(
      `--candidate must be one of: ${[...candidateIds].join(", ")}.`,
    );
  }
  return options;
}

function readManifest() {
  try {
    return JSON.parse(readFileSync(manifestPath, "utf8"));
  } catch (error) {
    throw new HarnessIntegrityError(
      `Cannot read ${portablePath(path.relative(spikeRoot, manifestPath))}: ${
        error?.message ?? String(error)
      }`,
    );
  }
}

function validateManifest(manifest) {
  const errors = [];
  if (!isPlainObject(manifest)) {
    return ["The root value must be an object."];
  }
  if (manifest.schemaVersion !== 1) {
    errors.push(`schemaVersion must be 1, observed ${manifest.schemaVersion}.`);
  }
  if (!isPlainObject(manifest.limitProfiles?.default)) {
    errors.push("limitProfiles.default must be an object.");
  }
  if (!Array.isArray(manifest.acceptanceGates)) {
    errors.push("acceptanceGates must be an array.");
  }
  if (!Array.isArray(manifest.cases) || manifest.cases.length === 0) {
    errors.push("cases must be a non-empty array.");
    return errors;
  }

  const caseIds = new Set();
  for (const caseDefinition of manifest.cases) {
    if (!isPlainObject(caseDefinition)) {
      errors.push("Every case must be an object.");
      continue;
    }
    if (
      typeof caseDefinition.id !== "string" ||
      !/^[a-z0-9][a-z0-9.-]*$/.test(caseDefinition.id)
    ) {
      errors.push(`Invalid case id: ${String(caseDefinition.id)}.`);
    } else if (caseIds.has(caseDefinition.id)) {
      errors.push(`Duplicate case id: ${caseDefinition.id}.`);
    } else {
      caseIds.add(caseDefinition.id);
    }
    if (!isPlainObject(caseDefinition.materialization)) {
      errors.push(`${caseDefinition.id}: materialization must be an object.`);
    }
    if (typeof caseDefinition.repositoryRoot !== "string") {
      errors.push(`${caseDefinition.id}: repositoryRoot must be a string.`);
    }
    if (typeof caseDefinition.entrypoint !== "string") {
      errors.push(`${caseDefinition.id}: entrypoint must be a string.`);
    }
    if (!isPlainObject(caseDefinition.expected)) {
      errors.push(`${caseDefinition.id}: expected must be an object.`);
    }
    if (
      !Number.isInteger(caseDefinition.repeat) ||
      caseDefinition.repeat < 1
    ) {
      errors.push(`${caseDefinition.id}: repeat must be a positive integer.`);
    }
    if (
      caseDefinition.platforms !== undefined &&
      (!Array.isArray(caseDefinition.platforms) ||
        caseDefinition.platforms.some(
          (value) => !["windows", "linux", "darwin"].includes(value),
        ))
    ) {
      errors.push(`${caseDefinition.id}: platforms contains an unknown value.`);
    }
    const profileName = caseDefinition.limits?.profile ?? "default";
    if (!isPlainObject(manifest.limitProfiles?.[profileName])) {
      errors.push(`${caseDefinition.id}: unknown limit profile ${profileName}.`);
    } else {
      const limits = {
        ...manifest.limitProfiles[profileName],
        ...caseDefinition.limits,
      };
      for (const [name, minimum] of [
        ["timeoutMs", 1],
        ["maxEntrypointBytes", 1],
        ["maxReferenceDepth", 0],
        ["maxFileCount", 1],
        ["maxAggregateBytes", 1],
        ["maxDiagnostics", 1],
      ]) {
        if (!Number.isSafeInteger(limits[name]) || limits[name] < minimum) {
          errors.push(
            `${caseDefinition.id}: ${name} must be an integer >= ${minimum}.`,
          );
        }
      }
    }
  }

  const gateIds = new Set();
  for (const gate of manifest.acceptanceGates ?? []) {
    if (!isPlainObject(gate) || typeof gate.id !== "string") {
      errors.push("Every acceptance gate must have a string id.");
      continue;
    }
    if (gateIds.has(gate.id)) {
      errors.push(`Duplicate acceptance gate id: ${gate.id}.`);
    }
    gateIds.add(gate.id);
    if (!Array.isArray(gate.cases) || gate.cases.length === 0) {
      errors.push(`${gate.id}: cases must be a non-empty array.`);
      continue;
    }
    for (const caseId of gate.cases) {
      if (!caseIds.has(caseId)) {
        errors.push(`${gate.id}: unknown case ${caseId}.`);
      }
    }
  }
  return errors;
}

function candidateDefinitions() {
  const goExecutable = path.join(
    cacheRoot,
    process.platform === "win32"
      ? "libopenapi-adapter.exe"
      : "libopenapi-adapter",
  );
  const redoclyModule = path.join(
    spikeRoot,
    "adapters",
    "redocly-core",
    "index.mjs",
  );
  const commonArguments = [
    "--entrypoint",
    "<entrypoint-relative-to-repository-root>",
    "--repository-root",
    "<absolute-repository-root>",
    "--max-entrypoint-bytes",
    "<bytes>",
    "--max-files",
    "<count>",
    "--max-total-bytes",
    "<bytes>",
    "--max-depth",
    "<edges>",
    "--max-diagnostics",
    "<count>",
  ];

  return [
    {
      id: "libopenapi",
      command: goExecutable,
      requiredPaths: [goExecutable],
      artifactPaths: [goExecutable],
      invocation: {
        runtime: "native",
        executable: portablePath(path.relative(spikeRoot, goExecutable)),
        arguments: commonArguments,
      },
      arguments(context) {
        return commonAdapterArguments(context);
      },
    },
    {
      id: "redocly-core",
      command: process.execPath,
      requiredPaths: [redoclyModule],
      artifactPaths: [redoclyModule],
      invocation: {
        runtime: "node",
        executable: "<node>",
        module: portablePath(path.relative(spikeRoot, redoclyModule)),
        arguments: [
          portablePath(path.relative(spikeRoot, redoclyModule)),
          ...commonArguments,
        ],
      },
      arguments(context) {
        return [redoclyModule, ...commonAdapterArguments(context)];
      },
    },
    {
      id: "openapi-spec-validator",
      command: pythonExecutable,
      requiredPaths: [pythonExecutable, pythonAdapterEntrypoint],
      artifactPaths: [pythonAdapterEntrypoint],
      invocation: {
        runtime: "python",
        executable: portablePath(path.relative(spikeRoot, pythonExecutable)),
        module: portablePath(
          path.relative(spikeRoot, pythonAdapterEntrypoint),
        ),
        arguments: [
          "-X",
          "utf8",
          "-I",
          portablePath(
            path.relative(spikeRoot, pythonAdapterEntrypoint),
          ),
          ...commonArguments,
        ],
      },
      arguments(context) {
        return [
          "-X",
          "utf8",
          "-I",
          pythonAdapterEntrypoint,
          ...commonAdapterArguments(context),
        ];
      },
      runtimeEvidence: inspectPythonRuntime,
    },
  ];
}

function artifactSha256(paths) {
  return paths.length === 1 ? sha256File(paths[0]) : sha256Paths(paths);
}

function inspectPythonRuntime() {
  const result = spawnSync(
    pythonExecutable,
    ["-X", "utf8", "-I", "-m", "pip", "inspect", "--local"],
    {
      cwd: spikeRoot,
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
      windowsHide: true,
      env: sanitizedEnvironment(),
    },
  );
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(
      `pip inspect exited ${result.status}: ${result.stderr.trim()}`,
    );
  }
  let inspect;
  try {
    inspect = JSON.parse(result.stdout);
  } catch (error) {
    throw new Error(`pip inspect emitted invalid JSON: ${error.message}`);
  }
  return {
    executableSha256: sha256File(pythonExecutable),
    requirementsLockSha256: sha256File(pythonRequirementsLock),
    environmentSha256: pythonEnvironmentSha256(inspect),
    environment: pythonEnvironmentProfile(inspect),
  };
}

function commonAdapterArguments({ entrypoint, repositoryRoot, limits }) {
  return [
    "--entrypoint",
    entrypoint,
    "--repository-root",
    repositoryRoot,
    "--max-entrypoint-bytes",
    String(limits.maxEntrypointBytes),
    "--max-files",
    String(limits.maxFileCount),
    "--max-total-bytes",
    String(limits.maxAggregateBytes),
    "--max-depth",
    String(limits.maxReferenceDepth),
    "--max-diagnostics",
    String(limits.maxDiagnostics),
  ];
}

function candidateAvailabilityError(candidate) {
  const missing = candidate.requiredPaths.filter((target) => !existsSync(target));
  if (missing.length === 0) {
    return null;
  }
  return `Candidate artifact is missing: ${missing
    .map((target) => portablePath(path.relative(spikeRoot, target)))
    .join(", ")}.`;
}

async function evaluateCase({ candidate, caseDefinition, manifest, canary }) {
  const limits = resolveLimits(caseDefinition, manifest);
  const attempts = [];
  const liveRuns = [];

  try {
    for (let iteration = 0; iteration < caseDefinition.repeat; iteration += 1) {
      const materialized = materializeCase(
        candidate.id,
        caseDefinition,
        iteration,
        canary.url,
      );
      const invocationArguments = candidate.arguments({
        entrypoint: caseDefinition.entrypoint,
        repositoryRoot: materialized.repositoryRoot,
        limits,
      });
      const beforeRequests = canary.requestCount;
      const execution = await executeProcess({
        command: candidate.command,
        arguments: invocationArguments,
        cwd: materialized.workspaceRoot,
        timeoutMs: limits.timeoutMs,
        maxOutputBytes: outputLimitBytes,
        environment: {
          TZ: "UTC",
          LANG: "C.UTF-8",
          LC_ALL: "C.UTF-8",
          NO_COLOR: "1",
        },
      });
      await new Promise((resolve) => setImmediate(resolve));
      const networkRequests = canary.requestCount - beforeRequests;
      const inspected = inspectAdapterOutput(
        execution.stdout,
        materialized.workspaceRoot,
        canary.url,
        candidate.id,
      );
      const failures = [
        ...assertProcessContract(execution, inspected),
        ...assertAdapterContract(inspected),
        ...assertExpectedResult({
          caseDefinition,
          inspected,
          networkRequests,
        }),
      ];
      const canonical = canonicalAttempt(
        inspected,
        networkRequests,
        failures,
        execution,
      );
      const attempt = {
        iteration,
        passed: failures.length === 0,
        outcome: inspected.result?.outcome ?? "uncontrolled-error",
        networkRequests,
        canonicalSha256: sha256(JSON.stringify(canonical)),
        diagnostics: inspected.result?.diagnostics ?? [],
        stats: inspected.result?.stats ?? null,
        process: {
          exitCode: execution.exitCode,
          signal: execution.signal,
          timedOut: execution.timedOut,
          outputLimited: execution.outputLimited,
          stdoutBytes: execution.stdoutBytes,
          stderrBytes: execution.stderrBytes,
          spawnErrorCode: execution.spawnError?.code ?? null,
          forcedSettlement: execution.forcedSettlement,
          terminationDetail: execution.terminationDetail,
        },
        failures: unique(failures),
      };

      attempts.push(attempt);
      liveRuns.push({
        workspaceRoot: materialized.workspaceRoot,
        execution,
        invocation: {
          command: candidate.invocation.executable,
          arguments: invocationArguments.map((argument) =>
            normalizeInvocationArgument(argument, materialized.workspaceRoot),
          ),
        },
      });
    }

    const uniqueHashes = unique(
      attempts.map(({ canonicalSha256 }) => canonicalSha256),
    );
    const expectedHashCount =
      caseDefinition.expected.canonicalHashCount ??
      (caseDefinition.repeat > 1 ? 1 : null);
    const determinismFailures =
      expectedHashCount !== null && uniqueHashes.length !== expectedHashCount
        ? [
            `Expected ${expectedHashCount} canonical result hash(es), observed ${uniqueHashes.length}.`,
          ]
        : [];
    const failures = unique([
      ...attempts.flatMap((attempt) =>
        attempt.failures.map(
          (failure) => `repeat ${attempt.iteration + 1}: ${failure}`,
        ),
      ),
      ...determinismFailures,
    ]);
    const passed = failures.length === 0;
    const preservedWorkspaces = [];

    if (passed) {
      for (const run of liveRuns) {
        safelyRemoveWorkspace(run.workspaceRoot);
      }
    } else {
      for (const run of liveRuns) {
        persistFailureArtifacts(run);
        preservedWorkspaces.push(run.workspaceRoot);
      }
    }

    return {
      candidate: candidate.id,
      caseId: caseDefinition.id,
      required: caseDefinition.required === true,
      status: passed ? "passed" : "gap",
      passed,
      determinism:
        caseDefinition.repeat < 2
          ? "not-assessed"
          : uniqueHashes.length === 1
            ? "stable"
            : "unstable",
      uniqueHashes,
      failures,
      attempts,
      preservedWorkspaces,
    };
  } catch (error) {
    error.workspaceRoots = unique([
      ...(Array.isArray(error?.workspaceRoots) ? error.workspaceRoots : []),
      ...liveRuns.map(({ workspaceRoot }) => workspaceRoot),
      error?.workspaceRoot,
    ]).filter((workspace) => typeof workspace === "string");
    throw error;
  }
}

function resolveLimits(caseDefinition, manifest) {
  const profileName = caseDefinition.limits?.profile ?? "default";
  const { profile: _profile, ...caseLimits } = caseDefinition.limits ?? {};
  return {
    ...manifest.limitProfiles[profileName],
    ...caseLimits,
  };
}

function materializeCase(
  candidateId,
  caseDefinition,
  iteration,
  loopbackCanaryUrl,
) {
  const parent = path.join(
    workspaceBase,
    safePathSegment(candidateId),
    safePathSegment(caseDefinition.id),
  );
  mkdirSync(parent, { recursive: true });
  const workspaceRoot = mkdtempSync(
    path.join(parent, `repeat-${String(iteration + 1).padStart(2, "0")}-`),
  );
  assertPathInside(workspaceBase, workspaceRoot, "temporary workspace");

  try {
    const materialization = caseDefinition.materialization;
    if (
      [
        "copy-tree",
        "copy-tree-and-template",
        "copy-tree-and-directory-link",
      ].includes(materialization.kind)
    ) {
      const source = resolveContainedExistingDirectory(
        corpusRoot,
        materialization.source,
        `${caseDefinition.id} source`,
      );
      copyTreeByteForByte(source, workspaceRoot);
    } else if (materialization.kind === "generated-sized-openapi") {
      const entrypoint = resolveContainedPath(
        workspaceRoot,
        caseDefinition.entrypoint,
        `${caseDefinition.id} entrypoint`,
      );
      mkdirSync(path.dirname(entrypoint), { recursive: true });
      writeSizedOpenApi(entrypoint, materialization.generatedBytes);
    } else if (materialization.kind === "generated-invalid-utf8-json") {
      const entrypoint = resolveContainedPath(
        workspaceRoot,
        caseDefinition.entrypoint,
        `${caseDefinition.id} entrypoint`,
      );
      mkdirSync(path.dirname(entrypoint), { recursive: true });
      writeInvalidUtf8OpenApi(entrypoint);
    } else {
      throw new HarnessIntegrityError(
        `${caseDefinition.id}: unsupported materialization kind ${String(
          materialization.kind,
        )}.`,
      );
    }

    if (materialization.kind === "copy-tree-and-template") {
      applyTemplateSubstitutions(
        workspaceRoot,
        materialization,
        caseDefinition.id,
        loopbackCanaryUrl,
      );
    }
    if (materialization.kind === "copy-tree-and-directory-link") {
      createDirectoryLink(workspaceRoot, materialization, caseDefinition.id);
    }

    const repositoryRoot = resolveContainedExistingDirectory(
      workspaceRoot,
      caseDefinition.repositoryRoot,
      `${caseDefinition.id} repositoryRoot`,
    );
    resolveContainedExistingFile(
      repositoryRoot,
      caseDefinition.entrypoint,
      `${caseDefinition.id} entrypoint`,
    );
    return {
      workspaceRoot,
      repositoryRoot,
    };
  } catch (error) {
    error.workspaceRoot = workspaceRoot;
    throw error;
  }
}

function copyTreeByteForByte(sourceRoot, destinationRoot) {
  const copyDirectory = (source, destination) => {
    mkdirSync(destination, { recursive: true });
    const entries = readdirSync(source, { withFileTypes: true }).sort((left, right) =>
      compareText(left.name, right.name),
    );
    for (const entry of entries) {
      const sourcePath = path.join(source, entry.name);
      const destinationPath = path.join(destination, entry.name);
      if (entry.isDirectory()) {
        copyDirectory(sourcePath, destinationPath);
        continue;
      }
      if (!entry.isFile()) {
        throw new HarnessIntegrityError(
          `Committed corpus contains a non-file entry: ${portablePath(
            path.relative(corpusRoot, sourcePath),
          )}.`,
        );
      }
      copyFileSync(sourcePath, destinationPath);
      const sourceBytes = readFileSync(sourcePath);
      const destinationBytes = readFileSync(destinationPath);
      if (
        sourceBytes.byteLength !== destinationBytes.byteLength ||
        !sourceBytes.equals(destinationBytes)
      ) {
        throw new HarnessIntegrityError(
          `Byte-for-byte copy verification failed for ${portablePath(
            path.relative(corpusRoot, sourcePath),
          )}.`,
        );
      }
    }
  };
  copyDirectory(sourceRoot, destinationRoot);
}

function applyTemplateSubstitutions(
  workspaceRoot,
  materialization,
  caseId,
  loopbackCanaryUrl,
) {
  if (
    !Array.isArray(materialization.substitutions) ||
    materialization.substitutions.length === 0
  ) {
    throw new HarnessIntegrityError(`${caseId}: substitutions must be non-empty.`);
  }
  for (const substitution of materialization.substitutions) {
    if (substitution.valueFrom !== "loopbackCanaryUrl") {
      throw new HarnessIntegrityError(
        `${caseId}: unsupported substitution valueFrom ${String(
          substitution.valueFrom,
        )}.`,
      );
    }
    const template = resolveContainedExistingFile(
      workspaceRoot,
      substitution.template,
      `${caseId} template`,
    );
    const output = resolveContainedPath(
      workspaceRoot,
      substitution.output,
      `${caseId} template output`,
    );
    const content = readFileSync(template, "utf8");
    if (
      typeof substitution.token !== "string" ||
      substitution.token.length === 0 ||
      !content.includes(substitution.token)
    ) {
      throw new HarnessIntegrityError(
        `${caseId}: token is absent from ${substitution.template}.`,
      );
    }
    mkdirSync(path.dirname(output), { recursive: true });
    writeFileSync(
      output,
      content.replaceAll(substitution.token, loopbackCanaryUrl),
      "utf8",
    );
  }
}

function createDirectoryLink(workspaceRoot, materialization, caseId) {
  const linkPath = resolveContainedPath(
    workspaceRoot,
    materialization.linkPath,
    `${caseId} linkPath`,
  );
  const targetPath = resolveContainedExistingDirectory(
    workspaceRoot,
    materialization.targetPath,
    `${caseId} targetPath`,
  );
  mkdirSync(path.dirname(linkPath), { recursive: true });
  if (existsSync(linkPath)) {
    throw new HarnessIntegrityError(`${caseId}: linkPath already exists.`);
  }
  const expectedKind = process.platform === "win32" ? "junction" : "symlink";
  if (materialization.linkKind !== expectedKind) {
    throw new HarnessIntegrityError(
      `${caseId}: ${materialization.linkKind} is incompatible with ${platform}.`,
    );
  }
  symlinkSync(targetPath, linkPath, process.platform === "win32" ? "junction" : "dir");
  if (
    realpathSync.native(linkPath).toLowerCase() !==
    realpathSync.native(targetPath).toLowerCase()
  ) {
    throw new HarnessIntegrityError(`${caseId}: directory link target mismatch.`);
  }
}

function writeSizedOpenApi(target, targetBytes) {
  if (!Number.isSafeInteger(targetBytes) || targetBytes <= 0) {
    throw new HarnessIntegrityError(
      `generatedBytes must be a positive safe integer, observed ${targetBytes}.`,
    );
  }
  const prefix =
    '{"openapi":"3.0.3","info":{"title":"Sized fixture","version":"1.0.0"},"paths":{},"x-padding":"';
  const suffix = '"}';
  const fixedBytes = Buffer.byteLength(prefix) + Buffer.byteLength(suffix);
  const paddingBytes = targetBytes - fixedBytes;
  if (paddingBytes < 0) {
    throw new HarnessIntegrityError(
      `Target size ${targetBytes} is smaller than the valid OpenAPI envelope.`,
    );
  }
  writeFileSync(target, `${prefix}${"a".repeat(paddingBytes)}${suffix}`, "utf8");
  const actualBytes = statSync(target).size;
  if (actualBytes !== targetBytes) {
    throw new HarnessIntegrityError(
      `Generated ${actualBytes} bytes instead of ${targetBytes}.`,
    );
  }
  JSON.parse(readFileSync(target, "utf8"));
}

function writeInvalidUtf8OpenApi(target) {
  const prefix = Buffer.from(
    '{"openapi":"3.1.0","info":{"title":"',
    "utf8",
  );
  const suffix = Buffer.from(
    '","version":"1.0.0"},"paths":{}}',
    "utf8",
  );
  writeFileSync(
    target,
    Buffer.concat([prefix, Buffer.from([0xff]), suffix]),
  );
}

async function executeProcess({
  command,
  arguments: args,
  cwd,
  timeoutMs,
  maxOutputBytes,
  environment,
}) {
  const stdoutChunks = [];
  const stderrChunks = [];
  let capturedBytes = 0;
  let timedOut = false;
  let outputLimited = false;
  let spawnError = null;
  let forcedSettlement = false;
  let terminationDetail = null;
  let child;

  try {
    child = spawn(command, args, {
      cwd,
      env: sanitizedEnvironment(environment),
      windowsHide: true,
      detached: process.platform !== "win32",
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (error) {
    return {
      exitCode: null,
      signal: null,
      timedOut: false,
      outputLimited: false,
      stdout: "",
      stderr: "",
      stdoutBytes: 0,
      stderrBytes: 0,
      spawnError: serializeSpawnError(error),
      forcedSettlement: false,
      terminationDetail: null,
    };
  }

  let settleProcess;
  let settlementTimer = null;
  const completionPromise = new Promise((resolve) => {
    let settled = false;
    settleProcess = (exitCode, signal) => {
      if (settled) return;
      settled = true;
      if (settlementTimer) {
        clearTimeout(settlementTimer);
      }
      resolve({ exitCode, signal });
    };
    child.once("error", (error) => {
      spawnError = serializeSpawnError(error);
      settleProcess(null, null);
    });
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
  const capture = (chunks, chunk) => {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    const remaining = Math.max(0, maxOutputBytes - capturedBytes);
    if (remaining > 0) {
      const captured = buffer.subarray(0, remaining);
      chunks.push(captured);
      capturedBytes += captured.byteLength;
    }
    if (buffer.byteLength > remaining && !outputLimited) {
      outputLimited = true;
      terminate();
    }
  };
  child.stdout.on("data", (chunk) => capture(stdoutChunks, chunk));
  child.stderr.on("data", (chunk) => capture(stderrChunks, chunk));

  const timeout = setTimeout(() => {
    timedOut = true;
    terminate();
  }, timeoutMs);
  const completion = await completionPromise;
  clearTimeout(timeout);

  const stdoutBuffer = Buffer.concat(stdoutChunks);
  const stderrBuffer = Buffer.concat(stderrChunks);
  return {
    ...completion,
    timedOut,
    outputLimited,
    stdout: stdoutBuffer.toString("utf8"),
    stderr: stderrBuffer.toString("utf8"),
    stdoutBytes: stdoutBuffer.byteLength,
    stderrBytes: stderrBuffer.byteLength,
    spawnError,
    forcedSettlement,
    terminationDetail,
  };
}

function sanitizedEnvironment(overrides = {}) {
  const environment = {
    ...process.env,
    ...overrides,
  };
  for (const name of [
    "NODE_OPTIONS",
    "NODE_PATH",
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONUSERBASE",
    "PYTHONWARNINGS",
  ]) {
    delete environment[name];
  }
  environment.PYTHONNOUSERSITE = "1";
  environment.PYTHONHASHSEED = "0";
  environment.PYTHONIOENCODING = "utf-8";
  return environment;
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

function inspectAdapterOutput(
  stdout,
  workspaceRoot,
  canaryUrl,
  expectedAdapterId = null,
) {
  const contractErrors = [];
  const trimmed = stdout.trim();
  if (!trimmed) {
    return {
      result: null,
      contractErrors: ["stdout did not contain a JSON object."],
    };
  }

  let parsed;
  try {
    parsed = JSON.parse(trimmed);
  } catch (error) {
    return {
      result: null,
      contractErrors: [
        `stdout must contain exactly one JSON object: ${error.message}.`,
      ],
    };
  }
  if (!isPlainObject(parsed)) {
    return {
      result: null,
      contractErrors: ["The stdout JSON value must be an object."],
    };
  }

  if (parsed.schemaVersion !== 1) {
    contractErrors.push(
      `schemaVersion must be 1, observed ${String(parsed.schemaVersion)}.`,
    );
  }
  if (typeof parsed.adapter !== "string" || parsed.adapter.length === 0) {
    contractErrors.push("adapter must be a non-empty string.");
  } else if (
    expectedAdapterId !== null &&
    parsed.adapter !== expectedAdapterId
  ) {
    contractErrors.push(
      `adapter must be ${expectedAdapterId}, observed ${parsed.adapter}.`,
    );
  }
  if (!controlledOutcomes.has(parsed.outcome)) {
    contractErrors.push(`Unknown controlled outcome: ${String(parsed.outcome)}.`);
  }
  if (!Array.isArray(parsed.diagnostics)) {
    contractErrors.push("diagnostics must be an array.");
  }
  if (!isPlainObject(parsed.stats)) {
    contractErrors.push("stats must be an object.");
  }

  const diagnostics = Array.isArray(parsed.diagnostics)
    ? parsed.diagnostics.map((diagnostic, index) =>
        normalizeDiagnostic({
          diagnostic,
          index,
          workspaceRoot,
          canaryUrl,
          contractErrors,
        }),
      )
    : [];
  const stats = isPlainObject(parsed.stats)
    ? normalizeStats(parsed.stats, contractErrors)
    : null;
  return {
    result: {
      schemaVersion: parsed.schemaVersion,
      adapter: parsed.adapter,
      outcome: parsed.outcome,
      diagnostics,
      stats,
    },
    contractErrors,
  };
}

function normalizeDiagnostic({
  diagnostic,
  index,
  workspaceRoot,
  canaryUrl,
  contractErrors,
}) {
  if (!isPlainObject(diagnostic)) {
    contractErrors.push(`diagnostics[${index}] must be an object.`);
    return {
      source: null,
      line: null,
      column: null,
      pointer: "",
      code: "",
      severity: "",
      kind: "",
      message: "",
    };
  }
  for (const field of diagnosticFields) {
    if (!Object.hasOwn(diagnostic, field)) {
      contractErrors.push(`diagnostics[${index}] is missing ${field}.`);
    }
  }

  const source = normalizeDiagnosticSource(
    diagnostic.source,
    index,
    contractErrors,
  );
  const line = normalizeCoordinate(
    diagnostic.line,
    `diagnostics[${index}].line`,
    contractErrors,
  );
  const column = normalizeCoordinate(
    diagnostic.column,
    `diagnostics[${index}].column`,
    contractErrors,
  );
  const pointer = normalizePointer(
    diagnostic.pointer,
    index,
    contractErrors,
  );
  const code = normalizeRequiredString(
    diagnostic.code,
    `diagnostics[${index}].code`,
    contractErrors,
  );
  const severity = normalizeRequiredString(
    diagnostic.severity,
    `diagnostics[${index}].severity`,
    contractErrors,
  );
  const kind = normalizeRequiredString(
    diagnostic.kind,
    `diagnostics[${index}].kind`,
    contractErrors,
  );
  const rawMessage = normalizeRequiredString(
    diagnostic.message,
    `diagnostics[${index}].message`,
    contractErrors,
  );
  if (containsWorkspacePath(rawMessage, workspaceRoot)) {
    contractErrors.push(
      `diagnostics[${index}].message exposes the temporary workspace path.`,
    );
  }
  return {
    source,
    line,
    column,
    pointer,
    code,
    severity,
    kind,
    message: normalizeMessage(rawMessage, workspaceRoot, canaryUrl),
  };
}

function normalizeDiagnosticSource(source, index, contractErrors) {
  if (source === null || source === undefined || source === "") {
    return null;
  }
  if (typeof source !== "string") {
    contractErrors.push(`diagnostics[${index}].source must be a string or null.`);
    return String(source);
  }
  const portable = portablePath(source).replace(/^\.\//, "");
  if (
    path.isAbsolute(source) ||
    path.win32.isAbsolute(source) ||
    path.posix.isAbsolute(portable) ||
    /^[a-z][a-z\d+.-]*:/i.test(portable) ||
    portable === ".." ||
    portable.startsWith("../") ||
    portable.includes("/../")
  ) {
    contractErrors.push(
      `diagnostics[${index}].source must be relative to repositoryRoot.`,
    );
  }
  return portable;
}

function normalizeCoordinate(value, label, contractErrors) {
  if (value === null || value === undefined) {
    return null;
  }
  if (!Number.isInteger(value) || value < 1) {
    contractErrors.push(`${label} must be a one-based integer or null.`);
    return null;
  }
  return value;
}

function normalizePointer(pointer, index, contractErrors) {
  if (pointer === null || pointer === undefined || pointer === "#") {
    return "";
  }
  if (typeof pointer !== "string") {
    contractErrors.push(`diagnostics[${index}].pointer must be a string or null.`);
    return String(pointer);
  }
  const normalized = pointer.startsWith("#") ? pointer.slice(1) : pointer;
  if (normalized !== "" && !normalized.startsWith("/")) {
    contractErrors.push(
      `diagnostics[${index}].pointer must be an RFC 6901 document pointer.`,
    );
  }
  if (/~(?![01])/.test(normalized)) {
    contractErrors.push(
      `diagnostics[${index}].pointer contains an invalid RFC 6901 escape.`,
    );
  }
  return normalized;
}

function normalizeRequiredString(value, label, contractErrors) {
  if (typeof value !== "string" || value.length === 0) {
    contractErrors.push(`${label} must be a non-empty string.`);
    return value === null || value === undefined ? "" : String(value);
  }
  return value;
}

function normalizeStats(stats, contractErrors) {
  const filesRead = firstDefined(stats.filesRead, stats.filesLoaded);
  const totalBytes = stats.totalBytes;
  const maxDepthObserved = stats.maxDepthObserved;
  const diagnosticsRaw = stats.diagnosticsRaw;
  const diagnosticsEmitted = stats.diagnosticsEmitted;
  const rawTruncated = stats.diagnosticsTruncated;

  for (const [label, value] of [
    ["stats.filesRead/filesLoaded", filesRead],
    ["stats.totalBytes", totalBytes],
    ["stats.maxDepthObserved", maxDepthObserved],
    ["stats.diagnosticsRaw", diagnosticsRaw],
    ["stats.diagnosticsEmitted", diagnosticsEmitted],
  ]) {
    if (!Number.isSafeInteger(value) || value < 0) {
      contractErrors.push(`${label} must be a non-negative integer.`);
    }
  }

  let diagnosticsTruncated;
  if (Number.isSafeInteger(rawTruncated) && rawTruncated >= 0) {
    diagnosticsTruncated = rawTruncated;
  } else {
    contractErrors.push(
      "stats.diagnosticsTruncated must be a non-negative integer.",
    );
    diagnosticsTruncated = 0;
  }

  return {
    filesRead: numberOrNull(filesRead),
    entrypointBytes: numberOrNull(stats.entrypointBytes),
    totalBytes: numberOrNull(totalBytes),
    referencesSeen: numberOrNull(stats.referencesSeen),
    maxDepthObserved: numberOrNull(maxDepthObserved),
    diagnosticsRaw: numberOrNull(diagnosticsRaw),
    diagnosticsEmitted: numberOrNull(diagnosticsEmitted),
    diagnosticsTruncated,
    truncated: diagnosticsTruncated > 0,
    limitCode:
      typeof stats.limitCode === "string" && stats.limitCode.length > 0
        ? stats.limitCode
        : null,
  };
}

function assertProcessContract(execution, inspected) {
  const failures = [];
  if (execution.spawnError) {
    failures.push(
      `Candidate process could not start (${execution.spawnError.code ?? "unknown"}).`,
    );
  }
  if (execution.timedOut) {
    failures.push("Candidate exceeded the wall-clock timeout.");
  }
  if (execution.outputLimited) {
    failures.push(`Candidate exceeded the ${outputLimitBytes}-byte output limit.`);
  }
  if (execution.forcedSettlement) {
    failures.push(
      "Candidate process did not close within two seconds after forced termination.",
    );
  }
  if (execution.stderr.trim()) {
    failures.push("Candidate wrote unexpected content to stderr.");
  }
  if (inspected.result) {
    const exceptional = inspected.result.diagnostics.some(({ kind }) =>
      ["contract", "internal"].includes(kind),
    );
    const expectedExitCode = exceptional ? 2 : 0;
    if (execution.exitCode !== expectedExitCode) {
      failures.push(
        `${exceptional ? "Contract/internal" : "Controlled"} outcome ${
          inspected.result.outcome
        } must exit ${expectedExitCode}; observed ${
          execution.exitCode ?? "no exit code"
        }.`,
      );
    }
  } else if (
    execution.exitCode !== null &&
    execution.exitCode !== 0 &&
    execution.exitCode !== 2
  ) {
    failures.push(
      `Unexpected process exit code ${execution.exitCode}; only 0 and 2 are defined.`,
    );
  }
  return failures;
}

function assertAdapterContract(inspected) {
  const failures = [...inspected.contractErrors];
  if (!inspected.result) {
    return failures;
  }
  const { diagnostics, stats } = inspected.result;
  if (!stats) {
    return failures;
  }
  if (stats.diagnosticsEmitted !== diagnostics.length) {
    failures.push(
      `stats.diagnosticsEmitted=${stats.diagnosticsEmitted} but stdout contains ${diagnostics.length} diagnostic(s).`,
    );
  }
  if (
    stats.diagnosticsRaw !== null &&
    stats.diagnosticsEmitted !== null &&
    stats.diagnosticsRaw < stats.diagnosticsEmitted
  ) {
    failures.push("stats.diagnosticsRaw is smaller than diagnosticsEmitted.");
  }
  if (
    stats.diagnosticsRaw !== null &&
    stats.diagnosticsEmitted !== null &&
    stats.diagnosticsTruncated !==
      stats.diagnosticsRaw - stats.diagnosticsEmitted
  ) {
    failures.push(
      "stats.diagnosticsTruncated does not equal diagnosticsRaw - diagnosticsEmitted.",
    );
  }
  const sorted = [...diagnostics].sort(compareDiagnostics);
  if (JSON.stringify(sorted) !== JSON.stringify(diagnostics)) {
    failures.push("Diagnostics are not in the declared deterministic sort order.");
  }
  const deduplicationKeys = diagnostics.map(diagnosticDeduplicationKey);
  if (new Set(deduplicationKeys).size !== diagnostics.length) {
    failures.push("Diagnostics contain duplicate normalized findings.");
  }
  return failures;
}

function assertExpectedResult({ caseDefinition, inspected, networkRequests }) {
  const failures = [];
  const expected = caseDefinition.expected;
  const expectedNetworkRequests = expected.networkRequests ?? 0;
  if (networkRequests !== expectedNetworkRequests) {
    failures.push(
      `Expected ${expectedNetworkRequests} loopback request(s), observed ${networkRequests}.`,
    );
  }
  if (!inspected.result) {
    return failures;
  }
  const { outcome, diagnostics, stats } = inspected.result;
  if (outcome !== expected.outcome) {
    failures.push(`Expected outcome ${expected.outcome}, observed ${outcome}.`);
  }
  if (expected.findingCount !== undefined && diagnostics.length !== expected.findingCount) {
    failures.push(
      `Expected ${expected.findingCount} finding(s), observed ${diagnostics.length}.`,
    );
  }

  const availableCodes = new Set([
    ...diagnostics.map(({ code }) => code),
    stats?.limitCode,
  ]);
  if (expected.code !== null && !availableCodes.has(expected.code)) {
    failures.push(`Expected stable code ${expected.code}.`);
  }
  if (expected.code === null && stats?.limitCode) {
    failures.push(`Unexpected limit code ${stats.limitCode}.`);
  }

  const locationDiagnostic =
    diagnostics.find(({ code }) => code === expected.code) ?? diagnostics[0];
  for (const field of ["source", "line", "column", "pointer"]) {
    if (
      expected[field] !== undefined &&
      locationDiagnostic?.[field] !== expected[field]
    ) {
      failures.push(
        `Expected ${field}=${JSON.stringify(expected[field])}, observed ${JSON.stringify(
          locationDiagnostic?.[field] ?? null,
        )}.`,
      );
    }
  }
  if (
    expected.columnRange &&
    (!locationDiagnostic ||
      locationDiagnostic.column < expected.columnRange[0] ||
      locationDiagnostic.column > expected.columnRange[1])
  ) {
    failures.push(
      `Expected column in [${expected.columnRange.join(", ")}], observed ${JSON.stringify(
        locationDiagnostic?.column ?? null,
      )}.`,
    );
  }
  if (
    caseDefinition.requiresLocation &&
    diagnostics.some(
      ({ line, column }) =>
        !Number.isInteger(line) ||
        line < 1 ||
        !Number.isInteger(column) ||
        column < 1,
    )
  ) {
    failures.push("Every emitted finding must include a one-based line and column.");
  }
  if (diagnostics.some(({ severity }) => severity !== "error")) {
    failures.push("Every emitted corpus finding must have error severity.");
  }

  if (stats) {
    for (const [expectedField, actualField] of [
      ["filesRead", "filesRead"],
      ["aggregateBytesRead", "totalBytes"],
      ["maximumDepthObserved", "maxDepthObserved"],
      ["maximumSimpleCanonicalDepthObserved", "maxDepthObserved"],
      ["emittedDiagnostics", "diagnosticsEmitted"],
    ]) {
      if (
        expected[expectedField] !== undefined &&
        stats[actualField] !== expected[expectedField]
      ) {
        failures.push(
          `Expected ${expectedField}=${expected[expectedField]}, observed ${JSON.stringify(
            stats[actualField],
          )}.`,
        );
      }
    }
    if (
      expected.minimumObservedDiagnostics !== undefined &&
      stats.diagnosticsRaw < expected.minimumObservedDiagnostics
    ) {
      failures.push(
        `Expected at least ${expected.minimumObservedDiagnostics} observed diagnostics, observed ${stats.diagnosticsRaw}.`,
      );
    }
    if (
      expected.truncated !== undefined &&
      stats.truncated !== expected.truncated
    ) {
      failures.push(
        `Expected truncated=${expected.truncated}, observed ${stats.truncated}.`,
      );
    }
    if (
      expected.minimumTruncatedDiagnostics !== undefined &&
      stats.diagnosticsTruncated < expected.minimumTruncatedDiagnostics
    ) {
      failures.push(
        `Expected at least ${expected.minimumTruncatedDiagnostics} truncated diagnostics, observed ${stats.diagnosticsTruncated}.`,
      );
    }
  }

  if (
    expected.retainedFindingCode &&
    (diagnostics.length === 0 ||
      diagnostics.some(({ code }) => code !== expected.retainedFindingCode))
  ) {
    failures.push(
      `Every retained finding must use ${expected.retainedFindingCode}.`,
    );
  }
  if (expected.orderedFindings) {
    assertOrderedFindings(expected.orderedFindings, diagnostics, failures);
  }
  if (
    expected.orderedEmittedPointers &&
    JSON.stringify(diagnostics.map(({ pointer }) => pointer)) !==
      JSON.stringify(expected.orderedEmittedPointers)
  ) {
    failures.push(
      `Emitted pointer order differs from ${JSON.stringify(
        expected.orderedEmittedPointers,
      )}.`,
    );
  }
  return failures;
}

function assertOrderedFindings(expectedFindings, diagnostics, failures) {
  if (diagnostics.length !== expectedFindings.length) {
    failures.push(
      `Expected ${expectedFindings.length} ordered findings, observed ${diagnostics.length}.`,
    );
    return;
  }
  for (let index = 0; index < expectedFindings.length; index += 1) {
    for (const field of ["source", "line", "column", "pointer"]) {
      if (diagnostics[index][field] !== expectedFindings[index][field]) {
        failures.push(
          `Finding ${index + 1} expected ${field}=${JSON.stringify(
            expectedFindings[index][field],
          )}, observed ${JSON.stringify(diagnostics[index][field])}.`,
        );
      }
    }
  }
}

function canonicalAttempt(inspected, networkRequests, failures, execution) {
  const process = {
    exitCode: execution.exitCode,
    signal: execution.signal,
    timedOut: execution.timedOut,
    outputLimited: execution.outputLimited,
    forcedSettlement: execution.forcedSettlement,
    terminationDetail: execution.terminationDetail,
    stdoutBytes: execution.stdoutBytes,
    stderrBytes: execution.stderrBytes,
    spawnErrorCode: execution.spawnError?.code ?? null,
  };
  if (!inspected.result) {
    return {
      contractErrors: unique(inspected.contractErrors),
      networkRequests,
      failureKinds: failures.map(stableFailureKind),
      process,
    };
  }
  return {
    outcome: inspected.result.outcome,
    diagnostics: inspected.result.diagnostics,
    stats: inspected.result.stats,
    networkRequests,
    process,
  };
}

function stableFailureKind(failure) {
  return String(failure)
    .replace(/\b\d+\b/g, "<n>")
    .replace(/[A-Fa-f0-9]{8,}/g, "<hex>");
}

function skippedResult(candidateId, caseDefinition) {
  return {
    candidate: candidateId,
    caseId: caseDefinition.id,
    required: caseDefinition.required === true,
    status: "skipped-platform",
    passed: null,
    applicablePlatforms: caseDefinition.platforms,
    reason: `Case applies to ${caseDefinition.platforms.join(", ")}; current platform is ${platform}.`,
    determinism: "not-assessed",
    uniqueHashes: [],
    failures: [],
    attempts: [],
    preservedWorkspaces: [],
  };
}

function unavailableResult(candidateId, caseDefinition, reason) {
  return {
    candidate: candidateId,
    caseId: caseDefinition.id,
    required: caseDefinition.required === true,
    status: "gap",
    passed: false,
    determinism: "not-assessed",
    uniqueHashes: [],
    failures: [reason],
    attempts: [],
    preservedWorkspaces: [],
  };
}

function summarizeCandidates(
  candidates,
  results,
  manifest,
  scope,
  integrityHealthy,
) {
  return candidates.map((candidate) => {
    const candidateResults = results.filter(
      ({ candidate: candidateId }) => candidateId === candidate.id,
    );
    const applicable = candidateResults.filter(
      ({ status }) => status !== "skipped-platform",
    );
    const requiredApplicable = applicable.filter(({ required }) => required);
    const gates = manifest.acceptanceGates.map((gate) => {
      const gateResults = candidateResults.filter(
        (result) =>
          gate.cases.includes(result.caseId) &&
          result.status !== "skipped-platform",
      );
      const passed =
        gateResults.length > 0 &&
        gateResults.every(({ status }) => status === "passed");
      return {
        id: gate.id,
        required: gate.required === true,
        status:
          gateResults.length === 0
            ? "not-assessed"
            : passed
              ? "passed"
              : "gap",
        applicableCases: gateResults.map(({ caseId }) => caseId),
        failedCases: gateResults
          .filter(({ status }) => status !== "passed")
          .map(({ caseId }) => caseId),
      };
    });
    const hasGap =
      requiredApplicable.some(({ status }) => status !== "passed") ||
      gates.some(({ required, status }) => required && status === "gap");
    const hardGateFailures = [];
    if (
      candidateResults.some((result) =>
        result.attempts.some(({ networkRequests }) => networkRequests > 0),
      )
    ) {
      hardGateFailures.push("network-egress-observed");
    }
    if (
      candidateResults.some(
        ({ determinism }) => determinism === "unstable",
      )
    ) {
      hardGateFailures.push("non-deterministic-normalized-result");
    }
    if (
      gates.some(
        ({ id, status }) =>
          id === "root-confined-filesystem" && status === "gap",
      )
    ) {
      hardGateFailures.push("repository-root-containment");
    }
    return {
      id: candidate.id,
      invocation: candidate.invocation,
      disposition: !integrityHealthy
        ? "not-assessed-incomplete"
        : hasGap
          ? "has-gaps"
          : scope === "full"
            ? `selectable-on-${platform}`
            : "not-assessed-partial",
      applicableRequiredCases: requiredApplicable.length,
      passedRequiredCases: requiredApplicable.filter(
        ({ status }) => status === "passed",
      ).length,
      hardGateFailure: hardGateFailures.length > 0,
      hardGateFailures,
      gates,
    };
  });
}

function summarizeTotals(results) {
  return {
    cases: results.length,
    applicable: results.filter(
      ({ status }) => status !== "skipped-platform",
    ).length,
    passed: results.filter(({ status }) => status === "passed").length,
    failed: results.filter(({ status }) =>
      ["gap", "harness-error"].includes(status),
    ).length,
    skipped: results.filter(({ status }) => status === "skipped-platform")
      .length,
    evaluated: results.filter(({ status }) =>
      ["passed", "gap"].includes(status),
    ).length,
    gaps: results.filter(({ status }) => status === "gap").length,
    harnessErrors: results.filter(({ status }) => status === "harness-error")
      .length,
  };
}

function printResults(results, candidateSummaries, outputPath) {
  for (const result of results) {
    const marker =
      result.status === "passed"
        ? "PASS"
        : result.status === "skipped-platform"
          ? "SKIP"
          : result.status === "harness-error"
            ? "ERROR"
            : "GAP";
    const detail =
      result.failures.length > 0 ? `: ${result.failures.join(" ")}` : "";
    console.log(`${marker} ${result.candidate}/${result.caseId}${detail}`);
    for (const workspace of result.preservedWorkspaces) {
      console.log(`  preserved: ${workspace}`);
    }
  }
  for (const candidate of candidateSummaries) {
    console.log(`${candidate.id}: ${candidate.disposition}`);
  }
  console.log(`Evidence: ${outputPath}`);
}

async function runSupervisorSelfChecks() {
  const timeoutResult = await executeProcess({
    command: process.execPath,
    arguments: ["-e", "setInterval(() => {}, 1000)"],
    cwd: spikeRoot,
    timeoutMs: 100,
    maxOutputBytes: outputLimitBytes,
    environment: {},
  });
  const outputResult = await executeProcess({
    command: process.execPath,
    arguments: [
      "-e",
      `process.stdout.write("x".repeat(${outputLimitBytes + 4096}))`,
    ],
    cwd: spikeRoot,
    timeoutMs: 2000,
    maxOutputBytes: outputLimitBytes,
    environment: {},
  });
  const parserResult = inspectAdapterOutput(
    '{"schemaVersion":1,"adapter":"self-check","outcome":"valid","diagnostics":[],"stats":{"filesRead":1,"totalBytes":1,"maxDepthObserved":0,"diagnosticsRaw":0,"diagnosticsEmitted":0,"diagnosticsTruncated":0}}\n',
    spikeRoot,
    "http://127.0.0.1:1/self-check",
  );
  const processTreeResult = await executeProcess({
    command: process.execPath,
    arguments: [
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
    cwd: spikeRoot,
    timeoutMs: 500,
    maxOutputBytes: outputLimitBytes,
    environment: {},
  });
  const descendantPid = Number(processTreeResult.stdout.trim());
  await new Promise((resolve) => setTimeout(resolve, 100));
  const descendantAlive =
    Number.isInteger(descendantPid) && descendantPid > 0
      ? isProcessAlive(descendantPid)
      : true;
  if (descendantAlive && Number.isInteger(descendantPid)) {
    terminatePid(descendantPid);
  }
  let rejectsMultipleObjects = false;
  try {
    JSON.parse('{"one":1}\n{"two":2}');
  } catch {
    rejectsMultipleObjects = true;
  }

  return {
    timeout: {
      status:
        timeoutResult.timedOut && !timeoutResult.forcedSettlement
          ? "passed"
          : "failed",
      detail: `timedOut=${timeoutResult.timedOut},forcedSettlement=${timeoutResult.forcedSettlement},termination=${timeoutResult.terminationDetail}`,
    },
    outputBytes: {
      status:
        outputResult.outputLimited &&
        !outputResult.forcedSettlement &&
        outputResult.stdoutBytes + outputResult.stderrBytes <= outputLimitBytes
          ? "passed"
          : "failed",
      detail: `outputLimited=${outputResult.outputLimited},forcedSettlement=${outputResult.forcedSettlement},termination=${outputResult.terminationDetail},capturedBytes=${
        outputResult.stdoutBytes + outputResult.stderrBytes
      }`,
    },
    processTree: {
      status:
        processTreeResult.timedOut &&
        !processTreeResult.forcedSettlement &&
        !descendantAlive
          ? "passed"
          : "failed",
      detail: `timedOut=${processTreeResult.timedOut},descendantPid=${
        Number.isInteger(descendantPid) ? descendantPid : "unavailable"
      },descendantAlive=${descendantAlive},forcedSettlement=${processTreeResult.forcedSettlement},termination=${processTreeResult.terminationDetail}`,
    },
    jsonContract: {
      status:
        parserResult.contractErrors.length === 0 && rejectsMultipleObjects
          ? "passed"
          : "failed",
      detail: `validObjectErrors=${parserResult.contractErrors.length},rejectsMultipleObjects=${rejectsMultipleObjects}`,
    },
  };
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
    // Best-effort direct cleanup for a failed supervisor self-check.
  }
}

async function createLoopbackCanary() {
  let requestCount = 0;
  const server = createServer((_request, response) => {
    requestCount += 1;
    response.writeHead(200, {
      "content-type": "application/yaml",
      connection: "close",
    });
    response.end(
      [
        "type: object",
        "properties:",
        "  id:",
        "    type: string",
        "",
      ].join("\n"),
    );
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  const url = `http://127.0.0.1:${address.port}/remote-schema.yaml`;
  return {
    url,
    get requestCount() {
      return requestCount;
    },
    close() {
      return new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
        server.closeAllConnections?.();
      });
    },
  };
}

function persistFailureArtifacts(run) {
  try {
    writeFileSync(
      path.join(run.workspaceRoot, ".adapter-stdout.txt"),
      run.execution.stdout,
      "utf8",
    );
    writeFileSync(
      path.join(run.workspaceRoot, ".adapter-stderr.txt"),
      run.execution.stderr,
      "utf8",
    );
    writeFileSync(
      path.join(run.workspaceRoot, ".adapter-invocation.json"),
      `${JSON.stringify(run.invocation, null, 2)}\n`,
      "utf8",
    );
  } catch (error) {
    console.error(
      `Could not persist failure artifacts in ${run.workspaceRoot}: ${
        error?.message ?? String(error)
      }`,
    );
  }
}

function safelyRemoveWorkspace(target) {
  assertPathInside(workspaceBase, target, "workspace cleanup target");
  if (existsSync(target)) {
    rmSync(target, { recursive: true, force: true, maxRetries: 3 });
  }
}

function resolveContainedExistingDirectory(root, relative, label) {
  const resolved = resolveContainedPath(root, relative, label);
  if (!existsSync(resolved) || !statSync(resolved).isDirectory()) {
    throw new HarnessIntegrityError(`${label} is not an existing directory.`);
  }
  return resolved;
}

function resolveContainedExistingFile(root, relative, label) {
  const resolved = resolveContainedPath(root, relative, label);
  if (!existsSync(resolved) || !statSync(resolved).isFile()) {
    throw new HarnessIntegrityError(`${label} is not an existing file.`);
  }
  return resolved;
}

function resolveContainedPath(root, relative, label) {
  if (typeof relative !== "string" || path.isAbsolute(relative)) {
    throw new HarnessIntegrityError(`${label} must be a relative path.`);
  }
  const resolved = path.resolve(root, relative);
  assertPathInside(root, resolved, label, { allowRoot: true });
  return resolved;
}

function assertPathInside(root, target, label, { allowRoot = false } = {}) {
  const relative = path.relative(path.resolve(root), path.resolve(target));
  const contained =
    (allowRoot && relative === "") ||
    (relative !== "" &&
      relative !== ".." &&
      !relative.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(relative));
  if (!contained) {
    throw new HarnessIntegrityError(`${label} escapes its allowed root.`);
  }
}

function isApplicable(caseDefinition) {
  return (
    caseDefinition.platforms === undefined ||
    caseDefinition.platforms.includes(platform)
  );
}

function compareDiagnostics(left, right) {
  return (
    compareNullable(left.source, right.source) ||
    compareNullable(left.line, right.line) ||
    compareNullable(left.column, right.column) ||
    compareText(left.pointer, right.pointer) ||
    compareText(left.code, right.code) ||
    compareText(left.severity, right.severity) ||
    compareText(left.kind, right.kind) ||
    compareText(left.message, right.message)
  );
}

function diagnosticDeduplicationKey(diagnostic) {
  return JSON.stringify([
    diagnostic.source,
    diagnostic.line,
    diagnostic.column,
    diagnostic.pointer,
    diagnostic.code,
    diagnostic.severity,
    diagnostic.kind,
    diagnostic.message,
  ]);
}

function compareNullable(left, right) {
  if (left === right) return 0;
  if (left === null || left === undefined) return 1;
  if (right === null || right === undefined) return -1;
  if (typeof left === "number" && typeof right === "number") {
    return left - right;
  }
  return compareText(String(left), String(right));
}

function compareText(left, right) {
  if (left === right) return 0;
  return left < right ? -1 : 1;
}

function normalizeMessage(message, workspaceRoot, canaryUrl) {
  let normalized = stripAnsi(String(message)).replaceAll("\r\n", "\n");
  for (const root of [
    workspaceRoot,
    portablePath(workspaceRoot),
    workspaceRoot.replaceAll("/", "\\"),
  ]) {
    normalized = normalized.replace(
      new RegExp(escapeRegExp(root), "gi"),
      "<workspace>",
    );
  }
  if (canaryUrl) {
    normalized = normalized.replaceAll(canaryUrl, "<loopback-canary>");
  }
  return normalized.trim();
}

function containsWorkspacePath(value, workspaceRoot) {
  const normalizedValue = portablePath(String(value)).toLowerCase();
  return normalizedValue.includes(portablePath(workspaceRoot).toLowerCase());
}

function normalizeInvocationArgument(argument, workspaceRoot) {
  const value = String(argument);
  if (containsWorkspacePath(value, workspaceRoot)) {
    return portablePath(value).replace(
      portablePath(workspaceRoot),
      "<workspace>",
    );
  }
  return portablePath(value);
}

function stripAnsi(value) {
  return value.replace(/\u001B\[[0-?]*[ -/]*[@-~]/g, "");
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function firstDefined(...values) {
  return values.find((value) => value !== undefined);
}

function numberOrNull(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function unique(values) {
  return [...new Set(values)];
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function portablePath(value) {
  return String(value).replaceAll("\\", "/");
}

function safePathSegment(value) {
  if (!/^[a-z0-9][a-z0-9.-]*$/.test(value)) {
    throw new HarnessIntegrityError(`Unsafe path segment: ${value}.`);
  }
  return value;
}

function platformName(nodePlatform) {
  if (nodePlatform === "win32") return "windows";
  if (nodePlatform === "darwin") return "darwin";
  if (nodePlatform === "linux") return "linux";
  return nodePlatform;
}

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function serializeSpawnError(error) {
  return {
    code: typeof error?.code === "string" ? error.code : null,
    message: error?.message ?? String(error),
  };
}

class HarnessIntegrityError extends Error {
  constructor(message) {
    super(message);
    this.name = "HarnessIntegrityError";
  }
}
