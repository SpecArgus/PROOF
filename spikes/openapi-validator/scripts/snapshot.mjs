import {
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import {
  evaluationInputSha256,
  sha256File,
  stageOneInputSha256,
} from "./provenance.mjs";

const spikeRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cacheEvidence = path.join(spikeRoot, ".cache", "evidence");
const trackedEvidence = path.join(spikeRoot, "evidence");
const npmExecutable = process.env.npm_execpath;
if (!npmExecutable) {
  throw new Error("Run this script through `npm run snapshot`.");
}

const evaluation = readJson(path.join(cacheEvidence, "summary.json"));
const adapterEvaluation = readJson(
  path.join(cacheEvidence, "adapter-summary.json"),
);
const inventory = readJson(
  path.join(cacheEvidence, "inventory-summary.json"),
);
const vacuumModules = readJson(
  path.join(cacheEvidence, "vacuum-license-inventory.json"),
);
const libopenapiModules = readJson(
  path.join(cacheEvidence, "libopenapi-adapter-license-inventory.json"),
);
const pythonPackages = readJson(
  path.join(cacheEvidence, "openapi-spec-validator-python-packages.json"),
);
const libopenapiVulnerabilities = readJson(
  path.join(
    cacheEvidence,
    "libopenapi-adapter-vulnerability-summary.json",
  ),
);
const nodeVulnerabilities = readJson(
  path.join(cacheEvidence, "node-vulnerability-summary.json"),
);
const pythonVulnerabilities = readJson(
  path.join(cacheEvidence, "python-vulnerability-summary.json"),
);

if (evaluation.runStatus !== "complete") {
  throw new Error(
    `Refusing to snapshot an incomplete evaluation: ${evaluation.integrityErrors.join(
      "; ",
    )}`,
  );
}

if (adapterEvaluation.runStatus !== "complete") {
  throw new Error(
    `Refusing to snapshot an incomplete adapter evaluation: ${adapterEvaluation.integrityErrors.join(
      "; ",
    )}`,
  );
}

if (
  adapterEvaluation.scope !== "full" ||
  adapterEvaluation.coverage?.full !== true ||
  adapterEvaluation.coverage?.candidateCount !==
    adapterEvaluation.coverage?.corpusCandidateCount ||
  adapterEvaluation.coverage?.selectedCaseCount !==
    adapterEvaluation.coverage?.corpusCaseCount
) {
  throw new Error("Refusing to snapshot a partial adapter evaluation.");
}

if (
  evaluation.integrityErrors.length > 0 ||
  adapterEvaluation.integrityErrors.length > 0
) {
  throw new Error("Refusing to snapshot evaluation integrity errors.");
}

if (adapterEvaluation.totals.harnessErrors !== 0) {
  throw new Error(
    `Refusing to snapshot ${adapterEvaluation.totals.harnessErrors} adapter harness error(s).`,
  );
}

const currentEvaluationInputSha256 = evaluationInputSha256();
const currentStageOneInputSha256 = stageOneInputSha256();
const currentPackageLockSha256 = sha256File(
  path.join(spikeRoot, "package-lock.json"),
);
const currentInventoryScriptSha256 = sha256File(
  path.join(spikeRoot, "scripts", "inventory.mjs"),
);
const currentGoAuditScriptSha256 = sha256File(
  path.join(spikeRoot, "scripts", "audit-go.mjs"),
);
const currentNodeAuditScriptSha256 = sha256File(
  path.join(spikeRoot, "scripts", "audit-node.mjs"),
);
const currentPythonAuditScriptSha256 = sha256File(
  path.join(spikeRoot, "scripts", "audit-python.mjs"),
);
const currentGovulncheckSha256 = sha256File(
  path.join(
    spikeRoot,
    ".cache",
    process.platform === "win32" ? "govulncheck.exe" : "govulncheck",
  ),
);
const currentNpmEntrypointSha256 = sha256File(npmExecutable);
assertEqual(
  evaluation.provenance?.stageOneInputSha256,
  currentStageOneInputSha256,
  "stock CLI evaluation input fingerprint",
);
assertEqual(
  adapterEvaluation.provenance?.evaluationInputSha256,
  currentEvaluationInputSha256,
  "direct-adapter evaluation input fingerprint",
);
assertEqual(
  inventory.provenance?.stageOneInputSha256,
  currentStageOneInputSha256,
  "inventory stock CLI input fingerprint",
);
assertEqual(
  inventory.provenance?.evaluationInputSha256,
  currentEvaluationInputSha256,
  "inventory direct-adapter input fingerprint",
);
assertEqual(
  inventory.provenance?.inventoryScriptSha256,
  currentInventoryScriptSha256,
  "inventory generator script hash",
);
assertEqual(
  inventory.provenance?.npmVersion,
  "11.6.2",
  "inventory npm version",
);
assertEqual(
  inventory.provenance?.npmEntrypointSha256,
  currentNpmEntrypointSha256,
  "inventory npm entrypoint hash",
);
assertEqual(
  inventory.npm?.toolVersion,
  "11.6.2",
  "SBOM npm version",
);
assertEqual(
  inventory.npm?.toolEntrypointSha256,
  currentNpmEntrypointSha256,
  "SBOM npm entrypoint hash",
);
for (const [label, observed] of [
  ["stock CLI evaluation", evaluation.provenance?.packageLockSha256],
  [
    "direct-adapter evaluation",
    adapterEvaluation.provenance?.packageLockSha256,
  ],
  ["inventory", inventory.provenance?.packageLockSha256],
  ["Node audit", nodeVulnerabilities.target?.packageLockSha256],
]) {
  assertEqual(observed, currentPackageLockSha256, `${label} package-lock hash`);
}
assertEqual(
  evaluation.provenance?.candidateArtifactSha256?.vacuum,
  inventory.vacuum.sha256,
  "evaluated and inventoried Vacuum binary",
);
assertEqual(
  evaluation.provenance?.candidateArtifactSha256?.spectral,
  inventory.npm.candidateArtifactSha256?.spectral,
  "evaluated and inventoried Spectral CLI entrypoint",
);
assertEqual(
  evaluation.provenance?.candidateArtifactSha256?.redocly,
  inventory.npm.candidateArtifactSha256?.redocly,
  "evaluated and inventoried Redocly CLI entrypoint",
);
assertEqual(
  adapterEvaluation.provenance?.candidateArtifactSha256?.libopenapi,
  inventory.libopenapiAdapter.sha256,
  "evaluated and inventoried libopenapi adapter binary",
);
assertEqual(
  adapterEvaluation.provenance?.candidateArtifactSha256?.["redocly-core"],
  inventory.npm.candidateArtifactSha256?.redoclyCoreAdapter,
  "evaluated and inventoried Redocly Core adapter entrypoint",
);
assertEqual(
  adapterEvaluation.provenance?.candidateArtifactSha256?.[
    "openapi-spec-validator"
  ],
  inventory.openapiSpecValidatorAdapter.adapterSha256,
  "evaluated and inventoried openapi-spec-validator adapter entrypoint",
);
assertEqual(
  inventory.openapiSpecValidatorAdapter.requirementsLockSha256,
  sha256File(
    path.join(
      spikeRoot,
      "adapters",
      "openapi-spec-validator",
      "requirements.lock",
    ),
  ),
  "inventoried Python requirements lock",
);
assertEqual(
  adapterEvaluation.provenance?.candidateRuntime?.[
    "openapi-spec-validator"
  ]?.executableSha256,
  inventory.openapiSpecValidatorAdapter.pythonExecutableSha256,
  "evaluated and inventoried Python executable",
);
assertEqual(
  adapterEvaluation.provenance?.candidateRuntime?.[
    "openapi-spec-validator"
  ]?.requirementsLockSha256,
  inventory.openapiSpecValidatorAdapter.requirementsLockSha256,
  "evaluated and inventoried Python requirements lock",
);
assertEqual(
  adapterEvaluation.provenance?.candidateRuntime?.[
    "openapi-spec-validator"
  ]?.environmentSha256,
  inventory.openapiSpecValidatorAdapter.environmentSha256,
  "evaluated and inventoried Python installed environment",
);
assertEqual(
  libopenapiVulnerabilities.target?.binarySha256,
  inventory.libopenapiAdapter.sha256,
  "inventoried and audited libopenapi adapter binary",
);
assertEqual(
  libopenapiVulnerabilities.target?.evaluationInputSha256,
  currentEvaluationInputSha256,
  "Go audit input fingerprint",
);
assertEqual(
  libopenapiVulnerabilities.target?.auditScriptSha256,
  currentGoAuditScriptSha256,
  "Go audit script hash",
);
assertEqual(
  libopenapiVulnerabilities.toolVersion,
  "1.6.0",
  "Go audit tool version",
);
assertEqual(
  libopenapiVulnerabilities.toolBinarySha256,
  currentGovulncheckSha256,
  "Go audit tool binary hash",
);
assertEqual(
  libopenapiVulnerabilities.database?.name,
  "https://vuln.go.dev",
  "Go vulnerability database",
);
assertEqual(
  nodeVulnerabilities.target?.evaluationInputSha256,
  currentEvaluationInputSha256,
  "Node audit input fingerprint",
);
assertEqual(
  nodeVulnerabilities.target?.auditScriptSha256,
  currentNodeAuditScriptSha256,
  "Node audit script hash",
);
assertEqual(nodeVulnerabilities.toolVersion, "11.6.2", "Node audit npm version");
assertEqual(
  nodeVulnerabilities.toolEntrypointSha256,
  currentNpmEntrypointSha256,
  "Node audit npm entrypoint hash",
);
assertEqual(
  nodeVulnerabilities.registry,
  "https://registry.npmjs.org/",
  "Node audit registry",
);
assertEqual(
  nodeVulnerabilities.toolEntrypointSha256,
  inventory.npm?.toolEntrypointSha256,
  "inventoried and auditing npm entrypoint",
);
assertEqual(
  pythonVulnerabilities.target?.evaluationInputSha256,
  currentEvaluationInputSha256,
  "Python audit input fingerprint",
);
assertEqual(
  pythonVulnerabilities.target?.auditScriptSha256,
  currentPythonAuditScriptSha256,
  "Python audit script hash",
);
assertEqual(
  pythonVulnerabilities.target?.requirementsLockSha256,
  inventory.openapiSpecValidatorAdapter.requirementsLockSha256,
  "audited and inventoried Python requirements lock",
);
assertEqual(
  pythonVulnerabilities.target?.pythonExecutableSha256,
  inventory.openapiSpecValidatorAdapter.pythonExecutableSha256,
  "audited and inventoried Python executable",
);
assertEqual(
  pythonVulnerabilities.target?.environmentSha256,
  inventory.openapiSpecValidatorAdapter.environmentSha256,
  "audited and inventoried Python installed environment",
);
if (
  libopenapiVulnerabilities.status !== "pass" ||
  libopenapiVulnerabilities.integrityErrors?.length !== 0
) {
  throw new Error("Refusing to snapshot an incomplete or failing Go audit.");
}
if (
  !["pass", "pass-with-nonselected-findings"].includes(
    nodeVulnerabilities.status,
  ) ||
  nodeVulnerabilities.selectionRelevantFindingCount !== 0
) {
  throw new Error(
    "Refusing to snapshot an incomplete or selection-relevant failing Node audit.",
  );
}
if (pythonVulnerabilities.status !== "pass") {
  throw new Error("Refusing to snapshot an incomplete or failing Python audit.");
}

const failedAdapterSupervisorControls = Object.entries(
  adapterEvaluation.supervisorControls,
)
  .filter(([, result]) => result.status !== "passed")
  .map(([control]) => control);
if (failedAdapterSupervisorControls.length > 0) {
  throw new Error(
    `Refusing to snapshot failed adapter supervisor controls: ${failedAdapterSupervisorControls.join(
      ", ",
    )}`,
  );
}

const evaluationSnapshot = {
  schemaVersion: 1,
  environment: evaluation.environment,
  provenance: evaluation.provenance,
  sourceSchemaVersion: evaluation.schemaVersion,
  profile: evaluation.profile,
  runStatus: evaluation.runStatus,
  integrityErrors: evaluation.integrityErrors,
  dispositions: evaluation.dispositions,
  totals: evaluation.totals,
  supervisorControls: {
    timeout: {
      status: evaluation.supervisorControls.timeout.status,
    },
    outputBytes: {
      status: evaluation.supervisorControls.outputBytes.status,
    },
    diagnosticVolume: {
      status: evaluation.supervisorControls.diagnosticVolume.status,
      counts: JSON.parse(evaluation.supervisorControls.diagnosticVolume.detail),
    },
    processTree: evaluation.supervisorControls.processTree,
    memory: evaluation.supervisorControls.memory,
    referenceDepth: evaluation.supervisorControls.referenceDepth,
  },
  results: evaluation.results.map((result) => {
    const attempt = result.attempts[0];
    return {
      candidate: result.candidate,
      caseId: result.caseId,
      expected: result.expected,
      determinism: result.determinism,
      uniqueHashes: result.uniqueHashes,
      qualification: result.qualification,
      passed: result.passed,
      failures: result.failures,
      observation: {
        outcome: attempt.outcome,
        networkAttempts: attempt.networkAttempts,
        canonicalSha256: attempt.canonicalSha256,
        diagnostics: attempt.diagnostics,
        diagnosticCounts: attempt.diagnosticCounts,
        inputBytes: attempt.process.inputBytes,
        exitCode: attempt.process.exitCode,
        signal: attempt.process.signal,
        timedOut: attempt.process.timedOut,
        outputLimited: attempt.process.outputLimited,
        forcedSettlement: attempt.process.forcedSettlement,
        terminationDetail: attempt.process.terminationDetail,
        stdoutBytes: attempt.process.stdoutBytes,
        stderrBytes: attempt.process.stderrBytes,
        nativeProbe: attempt.nativeProbe
          ? {
              outcome: attempt.nativeProbe.outcome,
              networkAttempts: attempt.nativeProbe.networkAttempts,
              meetsRequirement: attempt.nativeProbe.meetsRequirement,
              failures: attempt.nativeProbe.failures,
              diagnostics: attempt.nativeProbe.diagnostics,
              diagnosticCounts: attempt.nativeProbe.diagnosticCounts,
              process: {
                exitCode: attempt.nativeProbe.process.exitCode,
                signal: attempt.nativeProbe.process.signal,
                timedOut: attempt.nativeProbe.process.timedOut,
                outputLimited: attempt.nativeProbe.process.outputLimited,
                forcedSettlement:
                  attempt.nativeProbe.process.forcedSettlement,
                terminationDetail:
                  attempt.nativeProbe.process.terminationDetail,
                inputBytes: attempt.nativeProbe.process.inputBytes,
                stdoutBytes: attempt.nativeProbe.process.stdoutBytes,
                stderrBytes: attempt.nativeProbe.process.stderrBytes,
              },
            }
          : null,
      },
    };
  }),
};

const adapterEvaluationSnapshot = {
  schemaVersion: 1,
  environment: adapterEvaluation.environment,
  provenance: adapterEvaluation.provenance,
  sourceSchemaVersion: adapterEvaluation.schemaVersion,
  manifestSchemaVersion: adapterEvaluation.manifestSchemaVersion,
  runStatus: adapterEvaluation.runStatus,
  scope: adapterEvaluation.scope,
  coverage: adapterEvaluation.coverage,
  integrityErrors: adapterEvaluation.integrityErrors,
  platform: adapterEvaluation.platform,
  profile: adapterEvaluation.profile,
  selectionRule: adapterEvaluation.selectionRule,
  dispositions: adapterEvaluation.dispositions,
  totals: adapterEvaluation.totals,
  gateResults: adapterEvaluation.gateResults,
  supervisorControls: adapterEvaluation.supervisorControls,
  candidates: adapterEvaluation.candidates.map((candidate) => ({
    id: candidate.id,
    disposition: candidate.disposition,
    applicableRequiredCases: candidate.applicableRequiredCases,
    passedRequiredCases: candidate.passedRequiredCases,
    hardGateFailure: candidate.hardGateFailure,
    hardGateFailures: candidate.hardGateFailures,
    requiredGapGates: candidate.gates
      .filter((gate) => gate.required && gate.status === "gap")
      .map((gate) => gate.id),
  })),
  results: adapterEvaluation.results.map((result) => {
    const attempt = result.attempts[0] ?? null;
    return {
      candidate: result.candidate,
      caseId: result.caseId,
      required: result.required,
      status: result.status,
      passed: result.passed,
      applicablePlatforms: result.applicablePlatforms ?? null,
      reason: result.reason ?? null,
      determinism: result.determinism,
      uniqueHashes: result.uniqueHashes,
      failures: result.failures,
      observation: attempt
        ? {
            outcome: attempt.outcome,
            networkRequests: attempt.networkRequests,
            canonicalSha256: attempt.canonicalSha256,
            diagnostics: attempt.diagnostics,
            stats: attempt.stats,
            process: {
              exitCode: attempt.process.exitCode,
              signal: attempt.process.signal,
              timedOut: attempt.process.timedOut,
              outputLimited: attempt.process.outputLimited,
              forcedSettlement: attempt.process.forcedSettlement,
              terminationDetail: attempt.process.terminationDetail,
              spawnErrorCode: attempt.process.spawnErrorCode,
            },
          }
        : null,
    };
  }),
};

mkdirSync(trackedEvidence, { recursive: true });
writeJson(
  path.join(trackedEvidence, "evaluation-summary.json"),
  evaluationSnapshot,
);
writeJson(
  path.join(trackedEvidence, "adapter-evaluation-summary.json"),
  adapterEvaluationSnapshot,
);
writeJson(
  path.join(trackedEvidence, "inventory-summary.json"),
  inventory,
);
writeJson(
  path.join(trackedEvidence, "vacuum-modules.json"),
  vacuumModules,
);
writeJson(
  path.join(trackedEvidence, "libopenapi-adapter-modules.json"),
  libopenapiModules,
);
writeJson(
  path.join(
    trackedEvidence,
    "openapi-spec-validator-python-packages.json",
  ),
  pythonPackages,
);
writeJson(
  path.join(
    trackedEvidence,
    "libopenapi-adapter-vulnerability-summary.json",
  ),
  libopenapiVulnerabilities,
);
writeJson(
  path.join(trackedEvidence, "node-vulnerability-summary.json"),
  nodeVulnerabilities,
);
writeJson(
  path.join(trackedEvidence, "python-vulnerability-summary.json"),
  pythonVulnerabilities,
);

console.log(`Reviewed evidence snapshot: ${trackedEvidence}`);

function readJson(filename) {
  return JSON.parse(readFileSync(filename, "utf8"));
}

function writeJson(filename, value) {
  writeFileSync(filename, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function assertEqual(observed, expected, label) {
  if (observed !== expected) {
    throw new Error(
      `Refusing to snapshot stale or mixed evidence: ${label} is ${JSON.stringify(
        observed,
      )}, expected ${JSON.stringify(expected)}.`,
    );
  }
}
