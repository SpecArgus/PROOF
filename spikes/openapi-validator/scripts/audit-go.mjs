import { spawnSync } from "node:child_process";
import { mkdirSync, statSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import {
  evaluationInputSha256,
  sha256File,
} from "./provenance.mjs";

const scriptFile = fileURLToPath(import.meta.url);
const spikeRoot = path.resolve(path.dirname(scriptFile), "..");
const cacheRoot = path.join(spikeRoot, ".cache");
const evidenceRoot = path.join(cacheRoot, "evidence");
const govulncheck = path.join(
  cacheRoot,
  process.platform === "win32" ? "govulncheck.exe" : "govulncheck",
);
const adapter = path.join(
  cacheRoot,
  process.platform === "win32"
    ? "libopenapi-adapter.exe"
    : "libopenapi-adapter",
);
const expectedVulnerabilityDatabase = "https://vuln.go.dev";

mkdirSync(evidenceRoot, { recursive: true });

const result = spawnSync(
  govulncheck,
  ["-json", "-mode", "binary", adapter],
  {
    cwd: spikeRoot,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    env: {
      ...process.env,
      GOTOOLCHAIN: "go1.25.12",
      GOVULNDB: expectedVulnerabilityDatabase,
    },
  },
);

if (result.error) {
  throw result.error;
}

writeFileSync(
  path.join(evidenceRoot, "libopenapi-adapter-govulncheck.jsonstream"),
  result.stdout,
  "utf8",
);

let records;
try {
  records = parseJsonObjectSequence(result.stdout);
} catch (error) {
  throw new Error(
    `govulncheck emitted an invalid JSON stream: ${error.message}`,
  );
}
const findings = records
  .map((record) => record.finding)
  .filter(Boolean);
const reachableFindings = findings.filter((finding) =>
  finding.trace?.some((step) => step.function),
);
const moduleFindings = findings.filter(
  (finding) => !finding.trace?.some((step) => step.function),
);
const reachableVulnerabilityIds = [
  ...new Set(reachableFindings.map((finding) => finding.osv).filter(Boolean)),
].sort();
const moduleVulnerabilityIds = [
  ...new Set(moduleFindings.map((finding) => finding.osv).filter(Boolean)),
].sort();
const configuration = records.find((record) => record.config)?.config ?? null;
const sbom = records.find((record) => record.SBOM)?.SBOM ?? null;
const progressMessages = records
  .map((record) => record.progress?.message)
  .filter(Boolean);
const integrityErrors = [];
if (!configuration) {
  integrityErrors.push("govulncheck did not emit a configuration record.");
}
if (!configuration?.db || !configuration?.db_last_modified) {
  integrityErrors.push("govulncheck did not identify its vulnerability database.");
}
if (
  configuration?.db &&
  configuration.db !== expectedVulnerabilityDatabase
) {
  integrityErrors.push(
    `Expected Go vulnerability database ${expectedVulnerabilityDatabase}, observed ${configuration.db}.`,
  );
}
if (!configuration?.scanner_version) {
  integrityErrors.push("govulncheck did not identify its scanner version.");
}
const toolVersion = configuration?.scanner_version?.replace(/^v/, "") ?? null;
if (toolVersion !== "1.6.0") {
  integrityErrors.push(
    `Expected govulncheck 1.6.0, observed ${String(toolVersion)}.`,
  );
}
if (!sbom || !Array.isArray(sbom.modules)) {
  integrityErrors.push("govulncheck did not emit the scanned binary SBOM.");
}
if (progressMessages.length === 0) {
  integrityErrors.push("govulncheck did not emit scan progress.");
}
const status =
  result.status === 0 && integrityErrors.length === 0
    ? "pass"
    : "findings-or-error";
const auditSummary = {
  schemaVersion: 1,
  tool: "govulncheck",
  toolVersion,
  toolBinarySha256: sha256File(govulncheck),
  toolBinaryBytes: statSync(govulncheck).size,
  mode: "binary",
  status,
  exitCode: result.status,
  integrityErrors,
  target: {
    binarySha256: sha256File(adapter),
    binaryBytes: statSync(adapter).size,
    evaluationInputSha256: evaluationInputSha256(),
    auditScriptSha256: sha256File(scriptFile),
  },
  reachableFindingCount: reachableFindings.length,
  reachableVulnerabilityIds,
  moduleFindingCount: moduleFindings.length,
  moduleVulnerabilityIds,
  database:
    configuration?.db && configuration?.db_last_modified
      ? {
          name: configuration.db,
          lastModified: configuration.db_last_modified,
        }
      : null,
};
writeFileSync(
  path.join(evidenceRoot, "libopenapi-adapter-vulnerability-summary.json"),
  `${JSON.stringify(auditSummary, null, 2)}\n`,
  "utf8",
);

if (result.stderr) {
  process.stderr.write(result.stderr);
}
if (status !== "pass") {
  process.stderr.write(
    `govulncheck did not produce a clean, complete audit (exit ${result.status}); inspect the JSON stream evidence.\n`,
  );
  process.exitCode = result.status || 2;
} else {
  process.stdout.write(
    "govulncheck found no known reachable vulnerabilities in the libopenapi adapter binary.\n",
  );
}

function parseJsonObjectSequence(source) {
  const records = [];
  let index = 0;
  while (index < source.length) {
    while (index < source.length && /\s/.test(source[index])) {
      index += 1;
    }
    if (index >= source.length) {
      break;
    }
    if (source[index] !== "{") {
      throw new Error(`expected an object at byte ${index}`);
    }

    const start = index;
    let depth = 0;
    let inString = false;
    let escaped = false;
    for (; index < source.length; index += 1) {
      const character = source[index];
      if (inString) {
        if (escaped) {
          escaped = false;
        } else if (character === "\\") {
          escaped = true;
        } else if (character === '"') {
          inString = false;
        }
        continue;
      }
      if (character === '"') {
        inString = true;
      } else if (character === "{") {
        depth += 1;
      } else if (character === "}") {
        depth -= 1;
        if (depth === 0) {
          index += 1;
          records.push(JSON.parse(source.slice(start, index)));
          break;
        }
      }
    }
    if (depth !== 0 || inString) {
      throw new Error(`unterminated object beginning at byte ${start}`);
    }
  }
  return records;
}
