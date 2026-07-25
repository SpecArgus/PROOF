import {
  appendFileSync,
  existsSync,
  readFileSync,
} from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const spikeRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cacheEvidence = path.join(spikeRoot, ".cache", "evidence");
const summaryFile = process.env.GITHUB_STEP_SUMMARY;
const platform = process.env.EVALUATION_PLATFORM ?? process.platform;

const cliEvaluation = readJsonIfPresent(
  path.join(cacheEvidence, "summary.json"),
);
const adapterEvaluation = readJsonIfPresent(
  path.join(cacheEvidence, "adapter-summary.json"),
);
const vulnerabilitySummary = readJsonIfPresent(
  path.join(
    cacheEvidence,
    "libopenapi-adapter-vulnerability-summary.json",
  ),
);
const nodeVulnerabilitySummary = readJsonIfPresent(
  path.join(cacheEvidence, "node-vulnerability-summary.json"),
);
const pythonVulnerabilitySummary = readJsonIfPresent(
  path.join(cacheEvidence, "python-vulnerability-summary.json"),
);
const inventory = readJsonIfPresent(
  path.join(cacheEvidence, "inventory-summary.json"),
);
const adapterEvaluationReady =
  adapterEvaluation?.runStatus === "complete" &&
  adapterEvaluation?.scope === "full" &&
  adapterEvaluation?.coverage?.full === true;
const selectableCandidates =
  (adapterEvaluationReady ? adapterEvaluation?.candidates : [])
    ?.filter(({ disposition }) => disposition.startsWith("selectable-on-"))
    .map(({ id }) => id) ?? [];

const lines = [
  `## OpenAPI validator evaluation — ${escapeCell(platform)}`,
  "",
];

if (cliEvaluation) {
  lines.push(
    "### Stock CLI baseline",
    "",
    `- Run status: **${escapeCell(cliEvaluation.runStatus)}**`,
    `- Fixture contract: **${cliEvaluation.totals.passed}/${cliEvaluation.totals.cases}** candidate cases passed`,
    `- Candidate gaps: **${cliEvaluation.totals.gaps}**`,
    "",
    "| Candidate | Disposition |",
    "| --- | --- |",
    ...Object.entries(cliEvaluation.dispositions).map(
      ([candidate, disposition]) =>
        `| ${escapeCell(candidate)} | ${escapeCell(disposition)} |`,
    ),
    "",
  );
} else {
  lines.push(
    "### Stock CLI baseline",
    "",
    "- No completed stock CLI summary was available.",
    "",
  );
}

if (adapterEvaluation) {
  const gaps = adapterEvaluation.results.filter(
    (result) => result.status === "gap",
  );
  lines.push(
    "### Direct adapter follow-up",
    "",
    `- Run status: **${escapeCell(adapterEvaluation.runStatus)}**`,
    `- Applicable required cases: **${adapterEvaluation.totals.passed}/${adapterEvaluation.totals.applicable}** passed`,
    `- Gaps: **${adapterEvaluation.totals.gaps}**; platform skips: **${adapterEvaluation.totals.skipped}**; harness errors: **${adapterEvaluation.totals.harnessErrors}**`,
    !adapterEvaluationReady
      ? "- Platform result: **not assessed because the run is incomplete or partial**"
      : selectableCandidates.length > 0
      ? `- Platform result: **all applicable required gates passed by ${escapeCell(selectableCandidates.join(", "))}**`
      : "- Platform result: **no evaluated adapter passed every applicable required gate**",
    "",
    "| Candidate | Disposition | Required cases |",
    "| --- | --- | ---: |",
    ...adapterEvaluation.candidates.map(
      (candidate) =>
        `| ${escapeCell(candidate.id)} | ${escapeCell(candidate.disposition)} | ${candidate.passedRequiredCases}/${candidate.applicableRequiredCases} |`,
    ),
    "",
    "| Candidate | Required gate | Gap case | Observation |",
    "| --- | --- | --- | --- |",
    ...gaps.map((result) => {
      const firstAttempt = result.attempts[0];
      const gate = adapterEvaluation.gateResults[result.candidate].find(
        (candidateGate) => candidateGate.failedCases.includes(result.caseId),
      );
      const observation = firstAttempt
        ? `${firstAttempt.outcome}; ${firstAttempt.stats?.diagnosticsRaw ?? "unknown"} raw diagnostic(s)`
        : "no completed attempt";
      return `| ${escapeCell(result.candidate)} | ${escapeCell(gate?.id ?? "unknown")} | ${escapeCell(result.caseId)} | ${escapeCell(observation)} |`;
    }),
    "",
    "| Supervisor self-check | Status |",
    "| --- | --- |",
    ...Object.entries(adapterEvaluation.supervisorControls).map(
      ([control, result]) =>
        `| ${escapeCell(control)} | ${escapeCell(result.status)} |`,
    ),
    "",
  );
} else {
  lines.push(
    "### Direct adapter follow-up",
    "",
    "- No completed direct-adapter summary was available.",
    "",
  );
}

lines.push(
  "### Dependency evidence",
  "",
  inventory
    ? `- libopenapi adapter: **${inventory.libopenapiAdapter.moduleCount}** linked modules, **${inventory.libopenapiAdapter.unknownLicenseModules.length}** with unknown licenses`
    : "- No completed dependency inventory was available.",
  inventory
    ? `- Redocly Core adapter closure: **${inventory.npm.candidateClosures.redoclyCoreAdapter.componentCount}** components, **${inventory.npm.candidateClosures.redoclyCoreAdapter.unknownLicenseComponents.length}** with unknown licenses`
    : "",
  "",
  "### Go vulnerability audit",
  "",
  vulnerabilitySummary
    ? `- Status: **${escapeCell(vulnerabilitySummary.status)}**; reachable findings: **${vulnerabilitySummary.reachableFindingCount}**; module findings: **${vulnerabilitySummary.moduleFindingCount}**; database updated: **${escapeCell(vulnerabilitySummary.database?.lastModified ?? "unavailable")}**`
    : "- No completed Go vulnerability summary was available.",
  "",
  "### Node vulnerability audit",
  "",
  nodeVulnerabilitySummary
    ? `- Status: **${escapeCell(nodeVulnerabilitySummary.status)}**; findings at or above low: **${nodeVulnerabilitySummary.findingsAtOrAboveThreshold}**; npm: **${escapeCell(nodeVulnerabilitySummary.toolVersion)}**`
    : "- No completed Node vulnerability summary was available.",
  "",
  "### Python vulnerability audit",
  "",
  pythonVulnerabilitySummary
    ? `- Status: **${escapeCell(pythonVulnerabilitySummary.status)}**; active findings: **${pythonVulnerabilitySummary.activeFindingCount}**; locked packages queried: **${pythonVulnerabilitySummary.packagesScanned}**`
    : "- No completed Python vulnerability summary was available.",
  "",
);

const output = `${lines.join("\n")}\n`;
if (summaryFile) {
  appendFileSync(summaryFile, output, "utf8");
} else {
  process.stdout.write(output);
}

function readJsonIfPresent(filename) {
  if (!existsSync(filename)) {
    return null;
  }

  try {
    return JSON.parse(readFileSync(filename, "utf8"));
  } catch (error) {
    process.stderr.write(`Unable to read ${filename}: ${error.message}\n`);
    return null;
  }
}

function escapeCell(value) {
  return String(value).replaceAll("|", "\\|").replaceAll("\n", " ");
}
