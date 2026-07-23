import { spawnSync } from "node:child_process";
import {
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
  mkdirSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

const spikeRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cacheRoot = path.join(spikeRoot, ".cache");
const evidenceRoot = path.join(cacheRoot, "evidence");
const vacuumBinary = path.join(
  cacheRoot,
  process.platform === "win32" ? "vacuum.exe" : "vacuum",
);

mkdirSync(evidenceRoot, { recursive: true });

const npmExecutable = process.env.npm_execpath;
if (!npmExecutable) {
  throw new Error("Run this script through `npm run inventory`.");
}

const npmSbom = runJson(process.execPath, [
  npmExecutable,
  "sbom",
  "--sbom-format",
  "cyclonedx",
]);
const npmSbomPath = path.join(evidenceRoot, "npm-sbom.cdx.json");
writeFileSync(npmSbomPath, `${JSON.stringify(npmSbom, null, 2)}\n`, "utf8");

const vacuumBuild = runJson("go", [
  "version",
  "-m",
  "-json",
  vacuumBinary,
]);
const vacuumBuildPath = path.join(evidenceRoot, "vacuum-build.json");
writeFileSync(
  vacuumBuildPath,
  `${JSON.stringify(vacuumBuild, null, 2)}\n`,
  "utf8",
);

const goModuleCache = runText("go", ["env", "GOMODCACHE"]).trim();
const goModules = [
  vacuumBuild.Main,
  ...(vacuumBuild.Deps ?? []),
].filter((module) => module?.Path && module?.Version);
const goLicenses = goModules.map((module) => {
  const directory = path.join(
    goModuleCache,
    `${escapeGoModule(module.Path)}@${escapeGoModule(module.Version)}`,
  );
  return {
    path: module.Path,
    version: module.Version,
    sum: module.Sum ?? null,
    license: detectDirectoryLicense(directory),
  };
});

const installedNodeLicenses = indexNodeLicenses(
  path.join(spikeRoot, "node_modules"),
);
const nodeComponents = npmSbom.components ?? [];
const nodeLicenses = nodeComponents.map((component) => ({
  bomRef: component["bom-ref"],
  name: component.name,
  version: component.version,
  purl: component.purl ?? null,
  licenses:
    (component.licenses ?? []).map(
      (entry) => entry.license?.id ?? entry.license?.name ?? "UNKNOWN",
    ).filter((license) => license !== "UNKNOWN").length > 0
      ? (component.licenses ?? []).map(
          (entry) => entry.license?.id ?? entry.license?.name ?? "UNKNOWN",
        )
      : (installedNodeLicenses.get(`${component.name}@${component.version}`) ?? []),
}));
const nodeLicenseByRef = new Map(
  nodeLicenses.map((component) => [component.bomRef, component]),
);
const dependencyGraph = new Map(
  (npmSbom.dependencies ?? []).map((dependency) => [
    dependency.ref,
    dependency.dependsOn ?? [],
  ]),
);
const nodeCandidateClosures = Object.fromEntries(
  [
    ["spectral", "@stoplight/spectral-cli@6.16.2"],
    ["redocly", "@redocly/cli@2.40.0"],
  ].map(([candidate, rootRef]) => {
    const refs = dependencyClosure(rootRef, dependencyGraph);
    const components = [...refs]
      .map((ref) => nodeLicenseByRef.get(ref))
      .filter(Boolean);
    return [
      candidate,
      {
        componentCount: components.length,
        licenseCounts: countValues(
          components.flatMap((component) => component.licenses),
        ),
        unknownLicenseComponents: components
          .filter((component) => component.licenses.length === 0)
          .map((component) => `${component.name}@${component.version}`),
      },
    ];
  }),
);
const redoclyNoticePackages = readFileSync(
  path.join(
    spikeRoot,
    "node_modules",
    "@redocly",
    "cli",
    "THIRD_PARTY_NOTICES",
  ),
  "utf8",
)
  .split(/\r?\n/)
  .filter((line) => /^\s{2}\S+@\S+/.test(line))
  .map((line) => line.trim().split(/\s+/)[0]);
nodeCandidateClosures.redocly.bundledNoticePackageCount =
  redoclyNoticePackages.length;
nodeCandidateClosures.redocly.sbomCoverage =
  "npm reports the bundled CLI as one component; THIRD_PARTY_NOTICES discloses the embedded packages.";

const inventory = {
  schemaVersion: 1,
  environment: {
    platform: process.platform,
    architecture: process.arch,
    node: process.version,
  },
  candidates: {
    vacuum: "0.29.10",
    spectral: "6.16.2",
    redocly: "2.40.0",
  },
  npm: {
    sbomFormat: npmSbom.bomFormat,
    specVersion: npmSbom.specVersion,
    componentCount: nodeComponents.length,
    licenseCounts: countValues(nodeLicenses.flatMap((item) => item.licenses)),
    unknownLicenseComponents: nodeLicenses
      .filter((item) => item.licenses.length === 0)
      .map((item) => `${item.name}@${item.version}`),
    candidateClosures: nodeCandidateClosures,
  },
  vacuum: {
    sha256: sha256File(vacuumBinary),
    bytes: statSync(vacuumBinary).size,
    goVersion: vacuumBuild.GoVersion,
    moduleCount: goModules.length,
    licenseCounts: countValues(goLicenses.map((item) => item.license)),
    unknownLicenseModules: goLicenses
      .filter((item) => item.license === "UNKNOWN")
      .map((item) => `${item.path}@${item.version}`),
  },
  limitations: [
    "npm sbom records the installed Node graph but does not prove package contents match declared licenses.",
    "Go license detection is a local source-cache heuristic, not a legal conclusion.",
    "go version -m inventories modules linked into the binary but is not a complete SPDX or CycloneDX SBOM.",
    "The bundled Redocly CLI is one npm SBOM component; its THIRD_PARTY_NOTICES package list must be reconciled separately.",
  ],
};

writeFileSync(
  path.join(evidenceRoot, "inventory-summary.json"),
  `${JSON.stringify(inventory, null, 2)}\n`,
  "utf8",
);
writeFileSync(
  path.join(evidenceRoot, "vacuum-license-inventory.json"),
  `${JSON.stringify(goLicenses, null, 2)}\n`,
  "utf8",
);

console.log(
  `Node: ${inventory.npm.componentCount} CycloneDX components; ` +
    `${inventory.npm.unknownLicenseComponents.length} without declared licenses.`,
);
console.log(
  `Vacuum: ${inventory.vacuum.moduleCount} linked Go modules; ` +
    `${inventory.vacuum.unknownLicenseModules.length} unresolved license heuristics.`,
);
console.log(`Evidence: ${evidenceRoot}`);

function runJson(command, args) {
  return JSON.parse(runText(command, args));
}

function runText(command, args) {
  const result = spawnSync(command, args, {
    cwd: spikeRoot,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    env: {
      ...process.env,
      SCARF_ANALYTICS: "false",
      REDOCLY_TELEMETRY: "off",
    },
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(
      `${command} exited with ${result.status}: ${result.stderr.trim()}`,
    );
  }
  return result.stdout;
}

function escapeGoModule(value) {
  return value.replace(/[A-Z]/g, (character) => `!${character.toLowerCase()}`);
}

function detectDirectoryLicense(directory) {
  try {
    const candidates = readdirSync(directory)
      .filter((name) => /^(license|licence|copying|notice)(\.|$)/i.test(name))
      .sort((left, right) => left.localeCompare(right, "en"));
    for (const name of candidates) {
      const text = readFileSync(path.join(directory, name), "utf8").slice(0, 50000);
      const detected = detectLicenseText(text);
      if (detected !== "UNKNOWN") {
        return detected;
      }
    }
  } catch {
    return "UNKNOWN";
  }
  return "UNKNOWN";
}

function detectLicenseText(text) {
  if (/Apache License[\s\S]{0,100}Version 2\.0/i.test(text)) {
    return "Apache-2.0";
  }
  if (/Mozilla Public License[\s\S]{0,100}2\.0/i.test(text)) {
    return "MPL-2.0";
  }
  if (/GNU AFFERO GENERAL PUBLIC LICENSE/i.test(text)) {
    return "AGPL";
  }
  if (/GNU GENERAL PUBLIC LICENSE/i.test(text)) {
    return "GPL";
  }
  if (/Redistribution and use in source and binary forms/i.test(text)) {
    return /Neither the name/i.test(text) ? "BSD-3-Clause" : "BSD-2-Clause";
  }
  if (/Permission is hereby granted, free of charge/i.test(text)) {
    return "MIT";
  }
  if (/ISC License/i.test(text)) {
    return "ISC";
  }
  return "UNKNOWN";
}

function indexNodeLicenses(nodeModulesDirectory) {
  const licenses = new Map();
  const visited = new Set();

  visit(nodeModulesDirectory);
  return licenses;

  function visit(directory) {
    let entries;
    try {
      entries = readdirSync(directory, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (!entry.isDirectory() || entry.name.startsWith(".")) {
        continue;
      }
      const entryPath = path.join(directory, entry.name);
      if (entry.name.startsWith("@")) {
        visit(entryPath);
        continue;
      }
      const packageJsonPath = path.join(entryPath, "package.json");
      try {
        const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf8"));
        const key = `${packageJson.name}@${packageJson.version}`;
        const declared = [
          ...(typeof packageJson.license === "string"
            ? [packageJson.license]
            : []),
          ...(Array.isArray(packageJson.licenses)
            ? packageJson.licenses
                .map((license) =>
                  typeof license === "string" ? license : license?.type,
                )
                .filter(Boolean)
            : []),
        ];
        const detected =
          declared.length > 0 ? declared : [detectDirectoryLicense(entryPath)];
        licenses.set(
          key,
          detected.filter((license) => license !== "UNKNOWN"),
        );
      } catch {
        // Ignore non-package directories.
      }
      const nested = path.join(entryPath, "node_modules");
      if (!visited.has(nested)) {
        visited.add(nested);
        visit(nested);
      }
    }
  }
}

function countValues(values) {
  return Object.fromEntries(
    [...new Set(values)].sort().map((value) => [
      value,
      values.filter((candidate) => candidate === value).length,
    ]),
  );
}

function dependencyClosure(rootRef, graph) {
  const visited = new Set();
  const pending = [rootRef];
  while (pending.length > 0) {
    const current = pending.pop();
    if (visited.has(current)) {
      continue;
    }
    visited.add(current);
    pending.push(...(graph.get(current) ?? []));
  }
  return visited;
}

function sha256File(filename) {
  return createHash("sha256").update(readFileSync(filename)).digest("hex");
}
