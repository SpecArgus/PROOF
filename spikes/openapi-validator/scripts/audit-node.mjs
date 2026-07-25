import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import {
  evaluationInputSha256,
  sha256File,
} from "./provenance.mjs";

const scriptFile = fileURLToPath(import.meta.url);
const spikeRoot = path.resolve(path.dirname(scriptFile), "..");
const evidenceRoot = path.join(spikeRoot, ".cache", "evidence");
const packageLock = path.join(spikeRoot, "package-lock.json");
const inventoryFile = path.join(evidenceRoot, "inventory-summary.json");
const npmExecutable = process.env.npm_execpath;
const expectedNpmVersion = "11.6.2";
const expectedRegistry = "https://registry.npmjs.org/";

if (!npmExecutable) {
  throw new Error("Run this script through `npm run audit:node`.");
}

mkdirSync(evidenceRoot, { recursive: true });

const npmVersion = runNpm(["--version"]).trim();
const registry = runNpm(["config", "get", "registry"]).trim();
const integrityErrors = [];
if (npmVersion !== expectedNpmVersion) {
  integrityErrors.push(
    `Expected npm ${expectedNpmVersion}, observed ${npmVersion || "unknown"}.`,
  );
}
if (registry !== expectedRegistry) {
  integrityErrors.push(
    `Expected npm audit registry ${expectedRegistry}, observed ${registry || "unknown"}.`,
  );
}
const result = spawnSync(
  process.execPath,
  [npmExecutable, "audit", "--json", "--audit-level=low"],
  {
    cwd: spikeRoot,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    env: {
      ...process.env,
      SCARF_ANALYTICS: "false",
      REDOCLY_TELEMETRY: "off",
    },
  },
);

if (result.error) {
  throw result.error;
}

writeFileSync(
  path.join(evidenceRoot, "npm-audit.json"),
  result.stdout,
  "utf8",
);

let report;
try {
  report = JSON.parse(result.stdout);
} catch (error) {
  throw new Error(`npm audit emitted invalid JSON: ${error.message}`);
}

const vulnerabilities = report.metadata?.vulnerabilities;
if (
  !vulnerabilities ||
  !["info", "low", "moderate", "high", "critical", "total"].every(
    (key) => Number.isSafeInteger(vulnerabilities[key]),
  )
) {
  throw new Error("npm audit output is missing vulnerability totals.");
}
const inventory = JSON.parse(readFileSync(inventoryFile, "utf8"));
const vulnerablePackages = Object.entries(report.vulnerabilities ?? {})
  .map(([name, vulnerability]) => ({
    name,
    severity: vulnerability.severity,
    direct: vulnerability.isDirect === true,
    nodes: [...(vulnerability.nodes ?? [])].sort((left, right) =>
      left.localeCompare(right, "en"),
    ),
  }))
  .sort((left, right) => left.name.localeCompare(right.name, "en"));
const vulnerableNames = new Set(
  vulnerablePackages.map(({ name }) => name),
);
const candidateFindings = Object.fromEntries(
  Object.entries(inventory.npm?.candidateClosures ?? {})
    .sort(([left], [right]) => left.localeCompare(right, "en"))
    .map(([candidate, closure]) => {
      const packages = (closure.components ?? [])
        .filter(({ name }) => vulnerableNames.has(name))
        .map(({ name, version }) => ({ name, version }))
        .sort((left, right) => left.name.localeCompare(right.name, "en"));
      return [
        candidate,
        {
          status: packages.length === 0 ? "pass" : "findings",
          findingPackageCount: packages.length,
          packages,
        },
      ];
    }),
);
const selectionRelevantCandidates = ["redoclyCoreAdapter"];
const selectionRelevantFindingCount = selectionRelevantCandidates.reduce(
  (total, candidate) =>
    total + (candidateFindings[candidate]?.findingPackageCount ?? 0),
  0,
);
if (
  !selectionRelevantCandidates.every(
    (candidate) => candidateFindings[candidate] !== undefined,
  )
) {
  integrityErrors.push(
    "The inventory is missing a selection-relevant Node candidate closure.",
  );
}
if (
  (result.status === 0) !==
  (vulnerabilities.total === 0)
) {
  integrityErrors.push(
    "npm audit exit status is inconsistent with its vulnerability totals.",
  );
}
const auditCompleted =
  result.status === 0 ||
  (result.status === 1 && vulnerabilities.total > 0);
if (!auditCompleted) {
  integrityErrors.push(`npm audit exited unexpectedly with ${result.status}.`);
}

const summary = {
  schemaVersion: 1,
  tool: "npm audit",
  toolVersion: npmVersion,
  toolEntrypointSha256: sha256File(npmExecutable),
  registry,
  generatedAt: new Date().toISOString(),
  auditLevel: "low",
  findingsAtOrAboveThreshold:
    vulnerabilities.low +
    vulnerabilities.moderate +
    vulnerabilities.high +
    vulnerabilities.critical,
  status:
    integrityErrors.length > 0
      ? "incomplete"
      : selectionRelevantFindingCount > 0
        ? "selection-relevant-findings"
        : vulnerabilities.total > 0
          ? "pass-with-nonselected-findings"
          : "pass",
  integrityErrors,
  exitCode: result.status,
  auditReportVersion: report.auditReportVersion ?? null,
  vulnerabilities,
  vulnerablePackages,
  candidateFindings,
  selectionRelevantCandidates,
  selectionRelevantFindingCount,
  dependencyCounts: report.metadata.dependencies ?? null,
  target: {
    packageLockSha256: sha256File(packageLock),
    evaluationInputSha256: evaluationInputSha256(),
    auditScriptSha256: sha256File(scriptFile),
  },
};

writeFileSync(
  path.join(evidenceRoot, "node-vulnerability-summary.json"),
  `${JSON.stringify(summary, null, 2)}\n`,
  "utf8",
);

if (
  !["pass", "pass-with-nonselected-findings"].includes(summary.status)
) {
  process.stderr.write(
    `npm audit found ${selectionRelevantFindingCount} selection-relevant vulnerable package(s) or incomplete evidence.\n`,
  );
  process.exitCode = 2;
} else if (summary.status === "pass-with-nonselected-findings") {
  process.stdout.write(
    `npm audit found ${vulnerabilities.total} high-level package finding(s), all confined to nonselected candidate closures.\n`,
  );
} else {
  process.stdout.write(
    "npm audit found no known vulnerabilities at or above low severity in the locked Node dependency graph.\n",
  );
}

function runNpm(args) {
  const command = spawnSync(process.execPath, [npmExecutable, ...args], {
    cwd: spikeRoot,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    env: {
      ...process.env,
      SCARF_ANALYTICS: "false",
      REDOCLY_TELEMETRY: "off",
    },
  });
  if (command.error) {
    throw command.error;
  }
  if (command.status !== 0) {
    throw new Error(
      `npm ${args.join(" ")} exited ${command.status}: ${command.stderr.trim()}`,
    );
  }
  return command.stdout;
}
