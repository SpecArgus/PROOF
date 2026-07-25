import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const spikeRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const summary = JSON.parse(
  readFileSync(
    path.join(spikeRoot, ".cache", "evidence", "adapter-summary.json"),
    "utf8",
  ),
);

assert.equal(summary.runStatus, "complete");
assert.deepEqual(summary.integrityErrors, []);
assert.equal(summary.scope, "full");
assert.equal(summary.coverage.full, true);
assert.equal(summary.coverage.candidateCount, 3);
assert.equal(summary.coverage.corpusCandidateCount, 3);
assert.equal(summary.coverage.selectedCaseCount, 26);
assert.equal(summary.coverage.corpusCaseCount, 26);
assert.deepEqual(summary.coverage.selectedCandidates, [
  "libopenapi",
  "redocly-core",
  "openapi-spec-validator",
]);
assert.equal(summary.totals.cases, 78);
assert.equal(summary.totals.applicable, 75);
assert.equal(summary.totals.passed, 73);
assert.equal(summary.totals.failed, 2);
assert.equal(summary.totals.skipped, 3);
assert.equal(summary.totals.harnessErrors, 0);
assert.deepEqual(summary.dispositions, {
  libopenapi: "has-gaps",
  "redocly-core": "has-gaps",
  "openapi-spec-validator": `selectable-on-${summary.platform}`,
});

for (const [name, control] of Object.entries(summary.supervisorControls)) {
  assert.equal(control.status, "passed", `${name}: ${control.detail}`);
}

const gaps = summary.results
  .filter(({ status }) => status === "gap")
  .map(({ candidate, caseId }) => `${candidate}/${caseId}`)
  .sort();
assert.deepEqual(gaps, [
  "libopenapi/multi-file-deterministic-invalid",
  "redocly-core/diagnostic-flood",
]);

const skipped = summary.results.filter(
  ({ status }) => status === "skipped-platform",
);
assert.equal(skipped.length, 3);
assert.ok(
  skipped.every(
    ({ caseId }) =>
      caseId === "directory-symlink-escape" ||
      caseId === "directory-junction-escape",
  ),
);
assert.deepEqual(
  [...new Set(skipped.map(({ candidate }) => candidate))].sort(),
  ["libopenapi", "openapi-spec-validator", "redocly-core"],
);

const libopenapiGap = findResult(
  "libopenapi",
  "multi-file-deterministic-invalid",
);
assert.equal(libopenapiGap.determinism, "stable");
assert.equal(libopenapiGap.uniqueHashes.length, 1);
assert.equal(libopenapiGap.attempts.length, 10);
assert.ok(
  libopenapiGap.attempts.every(
    ({ outcome, diagnostics }) =>
      outcome === "valid" && diagnostics.length === 0,
  ),
);

const redoclyGap = findResult("redocly-core", "diagnostic-flood");
assert.equal(redoclyGap.determinism, "stable");
assert.equal(redoclyGap.uniqueHashes.length, 1);
assert.equal(redoclyGap.attempts.length, 5);
assert.ok(
  redoclyGap.attempts.every(
    ({ outcome, stats }) =>
      outcome === "invalid" &&
      stats.diagnosticsRaw === 1 &&
      stats.diagnosticsEmitted === 1 &&
      stats.truncated === false,
  ),
);

assert.deepEqual(requiredGapGates("libopenapi"), [
  "deterministic-diagnostics",
]);
assert.deepEqual(requiredGapGates("redocly-core"), ["diagnostic-volume"]);
assert.deepEqual(requiredGapGates("openapi-spec-validator"), []);
assert.ok(
  summary.gateResults["openapi-spec-validator"].every(
    ({ required, status }) => !required || status === "passed",
  ),
);
const pythonCandidate = summary.candidates.find(
  ({ id }) => id === "openapi-spec-validator",
);
assert.ok(pythonCandidate);
assert.equal(pythonCandidate.hardGateFailure, false);
assert.deepEqual(pythonCandidate.hardGateFailures, []);
assert.equal(
  pythonCandidate.passedRequiredCases,
  pythonCandidate.applicableRequiredCases,
);

process.stdout.write(
  "Adapter baseline is stable: 73/75 applicable candidate cases pass; " +
    "the two documented gaps remain isolated and openapi-spec-validator " +
    `passes every required ${summary.platform} gate.\n`,
);

function findResult(candidate, caseId) {
  const result = summary.results.find(
    (item) => item.candidate === candidate && item.caseId === caseId,
  );
  assert.ok(result, `Missing ${candidate}/${caseId}.`);
  return result;
}

function requiredGapGates(candidate) {
  return summary.gateResults[candidate]
    .filter(({ required, status }) => required && status === "gap")
    .map(({ id }) => id)
    .sort();
}
