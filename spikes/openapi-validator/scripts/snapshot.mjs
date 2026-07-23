import {
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const spikeRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cacheEvidence = path.join(spikeRoot, ".cache", "evidence");
const trackedEvidence = path.join(spikeRoot, "evidence");

const evaluation = readJson(path.join(cacheEvidence, "summary.json"));
const inventory = readJson(
  path.join(cacheEvidence, "inventory-summary.json"),
);
const vacuumModules = readJson(
  path.join(cacheEvidence, "vacuum-license-inventory.json"),
);

if (evaluation.runStatus !== "complete") {
  throw new Error(
    `Refusing to snapshot an incomplete evaluation: ${evaluation.integrityErrors.join(
      "; ",
    )}`,
  );
}

const evaluationSnapshot = {
  schemaVersion: 1,
  environment: {
    platform: process.platform,
    architecture: process.arch,
    node: process.version,
  },
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
        timedOut: attempt.process.timedOut,
        outputLimited: attempt.process.outputLimited,
        nativeProbe: attempt.nativeProbe
          ? {
              outcome: attempt.nativeProbe.outcome,
              networkAttempts: attempt.nativeProbe.networkAttempts,
              meetsRequirement: attempt.nativeProbe.meetsRequirement,
              failures: attempt.nativeProbe.failures,
              diagnostics: attempt.nativeProbe.diagnostics,
              diagnosticCounts: attempt.nativeProbe.diagnosticCounts,
            }
          : null,
      },
    };
  }),
};

mkdirSync(trackedEvidence, { recursive: true });
writeJson(
  path.join(trackedEvidence, "evaluation-summary.json"),
  evaluationSnapshot,
);
writeJson(
  path.join(trackedEvidence, "inventory-summary.json"),
  inventory,
);
writeJson(
  path.join(trackedEvidence, "vacuum-modules.json"),
  vacuumModules,
);

console.log(`Reviewed evidence snapshot: ${trackedEvidence}`);

function readJson(filename) {
  return JSON.parse(readFileSync(filename, "utf8"));
}

function writeJson(filename, value) {
  writeFileSync(filename, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}
