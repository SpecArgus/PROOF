import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import {
  evaluationInputSha256,
  sha256File,
} from "./provenance.mjs";
import {
  pythonEnvironmentSha256,
  pythonExecutable,
  pythonRequirementsLock,
} from "./python-runtime.mjs";

const scriptFile = fileURLToPath(import.meta.url);
const spikeRoot = path.resolve(path.dirname(scriptFile), "..");
const evidenceRoot = path.join(spikeRoot, ".cache", "evidence");
const serviceBaseUrl = "https://pypi.org/pypi";
const requirements = parseRequirementsLock(pythonRequirementsLock);

mkdirSync(evidenceRoot, { recursive: true });

const inspect = inspectPythonEnvironment();
assertLockedEnvironment(inspect, requirements);

const responses = await mapConcurrent(
  requirements,
  4,
  async ({ name, version }) => queryRelease(name, version),
);
const integrityErrors = responses.flatMap(({ errors }) => errors);
const activeFindings = responses
  .flatMap(({ vulnerabilities }) => vulnerabilities)
  .filter(({ withdrawn }) => withdrawn === null);
const withdrawnFindings = responses
  .flatMap(({ vulnerabilities }) => vulnerabilities)
  .filter(({ withdrawn }) => withdrawn !== null);
const status =
  integrityErrors.length === 0 && activeFindings.length === 0
    ? "pass"
    : integrityErrors.length > 0
      ? "incomplete"
      : "findings";

const summary = {
  schemaVersion: 1,
  tool: "PyPI release JSON vulnerability inventory",
  service: serviceBaseUrl,
  advisorySource:
    "PyPI release-specific JSON API; vulnerability records identify their upstream source, commonly OSV",
  generatedAt: new Date().toISOString(),
  status,
  packagesScanned: responses.length,
  activeFindingCount: activeFindings.length,
  activeFindings,
  withdrawnFindingCount: withdrawnFindings.length,
  integrityErrors,
  releases: responses.map(
    ({
      name,
      version,
      lastSerial,
      activeVulnerabilityCount,
      withdrawnVulnerabilityCount,
    }) => ({
      name,
      version,
      lastSerial,
      activeVulnerabilityCount,
      withdrawnVulnerabilityCount,
    }),
  ),
  target: {
    requirementsLockSha256: sha256File(pythonRequirementsLock),
    pythonExecutableSha256: sha256File(pythonExecutable),
    pythonExecutableBytes: statSync(pythonExecutable).size,
    environmentSha256: pythonEnvironmentSha256(inspect),
    evaluationInputSha256: evaluationInputSha256(),
    auditScriptSha256: sha256File(scriptFile),
  },
  limitations: [
    "The audit reports release-specific known vulnerabilities returned by PyPI at the recorded time; it is not a proof that no undisclosed vulnerability exists.",
    "The Node-based audit client queries the PyPI JSON API once for every package in the exact runtime lock and is not part of the candidate runtime.",
  ],
};

writeFileSync(
  path.join(evidenceRoot, "python-vulnerability-summary.json"),
  `${JSON.stringify(summary, null, 2)}\n`,
  "utf8",
);

if (status === "pass") {
  process.stdout.write(
    `PyPI reported no active known vulnerabilities for ${responses.length} locked Python packages.\n`,
  );
} else {
  process.stderr.write(
    `Python vulnerability audit status ${status}: ${activeFindings.length} active finding(s), ${integrityErrors.length} integrity error(s).\n`,
  );
  process.exitCode = status === "findings" ? 1 : 2;
}

function parseRequirementsLock(filename) {
  const matches = [
    ...readFileSync(filename, "utf8").matchAll(
      /^([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s\\]+)\s*\\/gm,
    ),
  ];
  if (matches.length === 0) {
    throw new Error("Python requirements lock contains no pinned packages.");
  }
  const packages = matches.map((match) => ({
    name: normalizePythonName(match[1]),
    version: match[2],
  }));
  if (new Set(packages.map(({ name }) => name)).size !== packages.length) {
    throw new Error("Python requirements lock contains duplicate packages.");
  }
  return packages.sort((left, right) => left.name.localeCompare(right.name, "en"));
}

function inspectPythonEnvironment() {
  const result = spawnSync(
    pythonExecutable,
    ["-X", "utf8", "-I", "-m", "pip", "inspect", "--local"],
    {
      cwd: spikeRoot,
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
      windowsHide: true,
      env: {
        ...process.env,
        PYTHONNOUSERSITE: "1",
        PYTHONIOENCODING: "utf-8",
      },
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
  return JSON.parse(result.stdout);
}

function assertLockedEnvironment(inspect, locked) {
  const observed = new Map(
    (inspect.installed ?? [])
      .map(({ metadata }) => [
        normalizePythonName(metadata?.name ?? ""),
        metadata?.version,
      ])
      .filter(([name]) => name && !["pip", "setuptools"].includes(name)),
  );
  const missing = locked.filter(
    ({ name, version }) => observed.get(name) !== version,
  );
  const unexpected = [...observed].filter(
    ([name]) => !locked.some((item) => item.name === name),
  );
  if (missing.length > 0 || unexpected.length > 0) {
    throw new Error(
      `Installed Python environment differs from the runtime lock; missing or mismatched: ${
        missing.map(({ name, version }) => `${name}==${version}`).join(", ") ||
        "none"
      }; unexpected: ${
        unexpected.map(([name, version]) => `${name}==${version}`).join(", ") ||
        "none"
      }.`,
    );
  }
}

async function queryRelease(name, version) {
  const url = `${serviceBaseUrl}/${encodeURIComponent(name)}/${encodeURIComponent(version)}/json`;
  const errors = [];
  let response;
  try {
    response = await fetch(url, {
      headers: {
        accept: "application/json",
        "user-agent": "SpecArgus-PROOF-openapi-validator-spike/1",
      },
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
    });
  } catch (error) {
    return failedRelease(name, version, `request failed: ${error.message}`);
  }
  if (response.status !== 200) {
    return failedRelease(name, version, `HTTP ${response.status}`);
  }

  let payload;
  try {
    payload = await response.json();
  } catch (error) {
    return failedRelease(name, version, `invalid JSON: ${error.message}`);
  }
  if (
    normalizePythonName(payload.info?.name ?? "") !== name ||
    payload.info?.version !== version
  ) {
    errors.push(
      `PyPI response identity mismatch for ${name}==${version}: ${String(
        payload.info?.name,
      )}==${String(payload.info?.version)}.`,
    );
  }
  if (!Array.isArray(payload.vulnerabilities)) {
    errors.push(
      `PyPI response for ${name}==${version} omitted vulnerabilities.`,
    );
  }
  const vulnerabilities = (payload.vulnerabilities ?? []).map((finding) => ({
    package: name,
    version,
    id: finding.id ?? null,
    aliases: Array.isArray(finding.aliases)
      ? [...finding.aliases].sort()
      : [],
    summary: finding.summary ?? null,
    fixedIn: Array.isArray(finding.fixed_in)
      ? [...finding.fixed_in].sort()
      : [],
    link: finding.link ?? null,
    source: finding.source ?? null,
    withdrawn: finding.withdrawn ?? null,
  }));
  return {
    name,
    version,
    lastSerial: payload.last_serial ?? null,
    vulnerabilities,
    activeVulnerabilityCount: vulnerabilities.filter(
      ({ withdrawn }) => withdrawn === null,
    ).length,
    withdrawnVulnerabilityCount: vulnerabilities.filter(
      ({ withdrawn }) => withdrawn !== null,
    ).length,
    errors,
  };
}

function failedRelease(name, version, detail) {
  return {
    name,
    version,
    lastSerial: null,
    vulnerabilities: [],
    activeVulnerabilityCount: 0,
    withdrawnVulnerabilityCount: 0,
    errors: [`PyPI query failed for ${name}==${version}: ${detail}.`],
  };
}

async function mapConcurrent(items, concurrency, worker) {
  const results = new Array(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(concurrency, items.length) }, async () => {
      while (next < items.length) {
        const index = next;
        next += 1;
        results[index] = await worker(items[index]);
      }
    }),
  );
  return results;
}

function normalizePythonName(value) {
  return String(value).toLowerCase().replace(/[-_.]+/g, "-");
}
