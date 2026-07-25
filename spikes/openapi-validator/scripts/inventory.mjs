import { spawnSync } from "node:child_process";
import {
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
  mkdirSync,
} from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import {
  evaluationInputSha256,
  sha256File,
  stageOneInputSha256,
} from "./provenance.mjs";
import {
  pythonAdapterEntrypoint,
  pythonEnvironmentSha256,
  pythonExecutable,
  pythonRequirementsLock,
} from "./python-runtime.mjs";

const scriptFile = fileURLToPath(import.meta.url);
const spikeRoot = path.resolve(path.dirname(scriptFile), "..");
const cacheRoot = path.join(spikeRoot, ".cache");
const evidenceRoot = path.join(cacheRoot, "evidence");
const goModuleCache = path.join(cacheRoot, "go-mod");
const goBuildCache = path.join(cacheRoot, "go-build");
const vacuumBinary = path.join(
  cacheRoot,
  process.platform === "win32" ? "vacuum.exe" : "vacuum",
);
const libopenapiAdapterBinary = path.join(
  cacheRoot,
  process.platform === "win32"
    ? "libopenapi-adapter.exe"
    : "libopenapi-adapter",
);
const spectralCliEntrypoint = path.join(
  spikeRoot,
  "node_modules",
  "@stoplight",
  "spectral-cli",
  "dist",
  "index.js",
);
const redoclyCliEntrypoint = path.join(
  spikeRoot,
  "node_modules",
  "@redocly",
  "cli",
  "bin",
  "cli.js",
);
const redoclyCoreAdapterEntrypoint = path.join(
  spikeRoot,
  "adapters",
  "redocly-core",
  "index.mjs",
);
const expectedNpmVersion = "11.6.2";

mkdirSync(evidenceRoot, { recursive: true });

const npmExecutable = process.env.npm_execpath;
if (!npmExecutable) {
  throw new Error("Run this script through `npm run inventory`.");
}
const npmVersion = runText(process.execPath, [
  npmExecutable,
  "--version",
]).trim();
if (npmVersion !== expectedNpmVersion) {
  throw new Error(
    `Expected npm ${expectedNpmVersion}, observed ${npmVersion || "unknown"}.`,
  );
}
const npmEntrypointSha256 = sha256File(npmExecutable);

const npmSbom = runJson(process.execPath, [
  npmExecutable,
  "sbom",
  "--sbom-format",
  "cyclonedx",
]);
const npmSbomPath = path.join(evidenceRoot, "npm-sbom.cdx.json");
writeFileSync(npmSbomPath, `${JSON.stringify(npmSbom, null, 2)}\n`, "utf8");

const pythonInspect = runJson(pythonExecutable, [
  "-X",
  "utf8",
  "-I",
  "-m",
  "pip",
  "inspect",
  "--local",
]);
if (pythonInspect.environment?.implementation_version !== "3.14.2") {
  throw new Error(
    `Expected Python 3.14.2, observed ${String(
      pythonInspect.environment?.implementation_version,
    )}.`,
  );
}
const pythonPackages = inventoryPythonPackages(
  pythonInspect,
  pythonRequirementsLock,
);

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

const libopenapiAdapterBuild = runJson("go", [
  "version",
  "-m",
  "-json",
  libopenapiAdapterBinary,
]);
writeFileSync(
  path.join(evidenceRoot, "libopenapi-adapter-build.json"),
  `${JSON.stringify(libopenapiAdapterBuild, null, 2)}\n`,
  "utf8",
);
assertGoBuild(
  vacuumBuild,
  "github.com/daveshanley/vacuum",
  "v0.29.10",
  "Vacuum",
);
assertGoBuild(
  libopenapiAdapterBuild,
  "github.com/SpecArgus/PROOF/spikes/openapi-validator/adapters/libopenapi",
  "(devel)",
  "libopenapi adapter",
);
for (const [modulePath, expectedVersion] of [
  ["github.com/pb33f/libopenapi", "v0.38.7"],
  ["github.com/pb33f/libopenapi-validator", "v0.14.0"],
]) {
  const observed = linkedModuleVersion(
    linkedGoModules(libopenapiAdapterBuild),
    modulePath,
  );
  if (observed !== expectedVersion) {
    throw new Error(
      `Expected ${modulePath}@${expectedVersion}, observed ${String(observed)}.`,
    );
  }
}

const vacuumModules = linkedGoModules(vacuumBuild);
const vacuumLicenses = licenseGoModules(vacuumModules);
const libopenapiAdapterModules = linkedGoModules(libopenapiAdapterBuild);
const libopenapiAdapterLicenses = licenseGoModules(
  libopenapiAdapterModules,
);

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
    ["spectral", ["@stoplight/spectral-cli@6.16.2"]],
    ["redocly", ["@redocly/cli@2.40.0"]],
    [
      "redoclyCoreAdapter",
      ["@redocly/openapi-core@2.40.0", "jsonc-parser@3.3.1"],
    ],
  ].map(([candidate, rootRefs]) => {
    for (const rootRef of rootRefs) {
      if (!dependencyGraph.has(rootRef)) {
        throw new Error(
          `npm SBOM dependency graph is missing candidate root ${rootRef}.`,
        );
      }
      if (!nodeLicenseByRef.has(rootRef)) {
        throw new Error(
          `npm SBOM component list is missing candidate root ${rootRef}.`,
        );
      }
    }
    const refs = new Set(
      rootRefs.flatMap((rootRef) => [
        ...dependencyClosure(rootRef, dependencyGraph),
      ]),
    );
    const missingComponents = [...refs].filter(
      (ref) => !nodeLicenseByRef.has(ref),
    );
    if (missingComponents.length > 0) {
      throw new Error(
        `${candidate} SBOM closure is missing ${missingComponents.join(", ")}.`,
      );
    }
    const components = [...refs].map((ref) => nodeLicenseByRef.get(ref));
    return [
      candidate,
      {
        componentCount: components.length,
        components: components
          .map(({ name, version, purl, licenses }) => ({
            name,
            version,
            purl,
            licenses,
          }))
          .sort(
            (left, right) =>
              left.name.localeCompare(right.name, "en") ||
              left.version.localeCompare(right.version, "en"),
          ),
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
  provenance: {
    evaluationInputSha256: evaluationInputSha256(),
    stageOneInputSha256: stageOneInputSha256(),
    packageLockSha256: sha256File(
      path.join(spikeRoot, "package-lock.json"),
    ),
    inventoryScriptSha256: sha256File(scriptFile),
    npmVersion,
    npmEntrypointSha256,
  },
  environment: {
    platform: process.platform,
    architecture: process.arch,
    node: process.version,
  },
  candidates: {
    vacuum: "0.29.10",
    spectral: "6.16.2",
    redocly: "2.40.0",
    libopenapi: "0.38.7",
    libopenapiValidator: "0.14.0",
    redoclyCore: "2.40.0",
    jsoncParser: "3.3.1",
    openapiSpecValidator: "0.9.0",
  },
  npm: {
    toolVersion: npmVersion,
    toolEntrypointSha256: npmEntrypointSha256,
    sbomFormat: npmSbom.bomFormat,
    specVersion: npmSbom.specVersion,
    componentCount: nodeComponents.length,
    candidateArtifactSha256: {
      spectral: sha256File(spectralCliEntrypoint),
      redocly: sha256File(redoclyCliEntrypoint),
      redoclyCoreAdapter: sha256File(redoclyCoreAdapterEntrypoint),
    },
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
    moduleCount: vacuumModules.length,
    licenseCounts: countValues(vacuumLicenses.map((item) => item.license)),
    unknownLicenseModules: vacuumLicenses
      .filter((item) => item.license === "UNKNOWN")
      .map((item) => `${item.path}@${item.version}`),
  },
  libopenapiAdapter: {
    sha256: sha256File(libopenapiAdapterBinary),
    bytes: statSync(libopenapiAdapterBinary).size,
    goVersion: libopenapiAdapterBuild.GoVersion,
    moduleCount: libopenapiAdapterModules.length,
    selectedModules: {
      libopenapi: linkedModuleVersion(
        libopenapiAdapterModules,
        "github.com/pb33f/libopenapi",
      ),
      libopenapiValidator: linkedModuleVersion(
        libopenapiAdapterModules,
        "github.com/pb33f/libopenapi-validator",
      ),
    },
    licenseCounts: countValues(
      libopenapiAdapterLicenses.map((item) => item.license),
    ),
    unknownLicenseModules: libopenapiAdapterLicenses
      .filter((item) => item.license === "UNKNOWN")
      .map((item) => `${item.path}@${item.version}`),
  },
  openapiSpecValidatorAdapter: {
    adapterSha256: sha256File(pythonAdapterEntrypoint),
    requirementsLockSha256: sha256File(pythonRequirementsLock),
    pythonExecutableSha256: sha256File(pythonExecutable),
    pythonVersion:
      pythonInspect.environment?.implementation_version ?? null,
    implementation:
      pythonInspect.environment?.implementation_name ?? null,
    platform: pythonInspect.environment?.platform_system ?? null,
    environmentSha256: pythonEnvironmentSha256(pythonInspect),
    componentCount: pythonPackages.length,
    licenseCounts: countValues(
      pythonPackages.map(({ license }) => license),
    ),
    unknownLicenseComponents: pythonPackages
      .filter(({ license }) => license === "UNKNOWN")
      .map(({ name, version }) => `${name}@${version}`),
  },
  limitations: [
    "npm sbom records the installed Node graph but does not prove package contents match declared licenses.",
    "Go license detection is a local source-cache heuristic, not a legal conclusion.",
    "go version -m inventories modules linked into the binary but is not a complete SPDX or CycloneDX SBOM.",
    "The bundled Redocly CLI is one npm SBOM component; its THIRD_PARTY_NOTICES package list must be reconciled separately.",
    "The Redocly Core adapter closure includes jsonc-parser because strict JSON parsing is an adapter control, not a Redocly Core dependency.",
    "The Python inventory compares the isolated virtual environment with the exact requirements lock and reports package metadata; declared licenses are not a legal conclusion or a content audit.",
  ],
};

writeFileSync(
  path.join(evidenceRoot, "inventory-summary.json"),
  `${JSON.stringify(inventory, null, 2)}\n`,
  "utf8",
);
writeFileSync(
  path.join(evidenceRoot, "vacuum-license-inventory.json"),
  `${JSON.stringify(vacuumLicenses, null, 2)}\n`,
  "utf8",
);
writeFileSync(
  path.join(evidenceRoot, "libopenapi-adapter-license-inventory.json"),
  `${JSON.stringify(libopenapiAdapterLicenses, null, 2)}\n`,
  "utf8",
);
writeFileSync(
  path.join(evidenceRoot, "openapi-spec-validator-python-packages.json"),
  `${JSON.stringify(pythonPackages, null, 2)}\n`,
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
console.log(
  `libopenapi adapter: ${inventory.libopenapiAdapter.moduleCount} linked Go modules; ` +
    `${inventory.libopenapiAdapter.unknownLicenseModules.length} unresolved license heuristics.`,
);
console.log(
  `openapi-spec-validator adapter: ${inventory.openapiSpecValidatorAdapter.componentCount} locked Python packages; ` +
    `${inventory.openapiSpecValidatorAdapter.unknownLicenseComponents.length} without recognized declared licenses.`,
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
      GOCACHE: goBuildCache,
      GOMODCACHE: goModuleCache,
      GOTOOLCHAIN: "go1.25.12",
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

function linkedGoModules(build) {
  return [build.Main, ...(build.Deps ?? [])].filter(
    (module) => module?.Path && module?.Version,
  );
}

function licenseGoModules(modules) {
  return modules.map((module) => {
    if (
      module.Version === "(devel)" &&
      module.Path ===
        "github.com/SpecArgus/PROOF/spikes/openapi-validator/adapters/libopenapi"
    ) {
      return {
        path: module.Path,
        version: module.Version,
        sum: null,
        license: "Apache-2.0",
        licenseSource: "repository LICENSE",
      };
    }
    const directory = path.join(
      goModuleCache,
      `${escapeGoModule(module.Path)}@${escapeGoModule(module.Version)}`,
    );
    return {
      path: module.Path,
      version: module.Version,
      sum: module.Sum ?? null,
      license: detectDirectoryLicense(directory),
      licenseSource: "local Go module cache heuristic",
    };
  });
}

function linkedModuleVersion(modules, modulePath) {
  return modules.find((module) => module.Path === modulePath)?.Version ?? null;
}

function assertGoBuild(build, modulePath, version, label) {
  if (
    build?.Main?.Path !== modulePath ||
    build?.Main?.Version !== version ||
    build?.GoVersion !== "go1.25.12"
  ) {
    throw new Error(
      `${label} build identity mismatch: expected ${modulePath}@${version} with go1.25.12, observed ${String(
        build?.Main?.Path,
      )}@${String(build?.Main?.Version)} with ${String(build?.GoVersion)}.`,
    );
  }
}

function inventoryPythonPackages(inspect, requirementsLock) {
  if (!Array.isArray(inspect?.installed)) {
    throw new Error("pip inspect output is missing the installed package list.");
  }
  const locked = new Map(
    [...readFileSync(requirementsLock, "utf8").matchAll(
      /^([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s\\]+)\s*\\/gm,
    )].map((match) => [normalizePythonName(match[1]), match[2]]),
  );
  if (locked.size === 0) {
    throw new Error("Python requirements lock contains no pinned packages.");
  }

  const installed = inspect.installed
    .map(({ metadata, requested }) => ({
      name: metadata?.name,
      normalizedName: normalizePythonName(metadata?.name ?? ""),
      version: metadata?.version,
      requested: requested === true,
      license: pythonLicense(metadata),
    }))
    .filter(({ normalizedName }) => !["pip", "setuptools"].includes(normalizedName))
    .sort((left, right) => left.normalizedName.localeCompare(
      right.normalizedName,
      "en",
    ));
  const installedByName = new Map(
    installed.map((component) => [component.normalizedName, component]),
  );
  const missing = [...locked].filter(
    ([name, version]) => installedByName.get(name)?.version !== version,
  );
  const unexpected = installed.filter(
    ({ normalizedName }) => !locked.has(normalizedName),
  );
  if (missing.length > 0 || unexpected.length > 0) {
    throw new Error(
      `Python environment differs from requirements.lock; missing or mismatched: ${missing
        .map(([name, version]) => `${name}==${version}`)
        .join(", ") || "none"}; unexpected: ${unexpected
        .map(({ name, version }) => `${name}==${version}`)
        .join(", ") || "none"}.`,
    );
  }
  return installed.map(
    ({ normalizedName: _normalizedName, ...component }) => component,
  );
}

function normalizePythonName(value) {
  return String(value).toLowerCase().replace(/[-_.]+/g, "-");
}

function pythonLicense(metadata) {
  const expression = metadata?.license_expression;
  if (typeof expression === "string" && expression.trim()) {
    return expression.trim();
  }
  const declared = metadata?.license;
  if (
    typeof declared === "string" &&
    declared.trim() &&
    declared.length <= 100 &&
    !/unknown/i.test(declared)
  ) {
    return declared.trim();
  }
  const classifier = (
    metadata?.classifier ??
    metadata?.classifiers ??
    []
  ).find((value) =>
    String(value).startsWith("License ::"),
  );
  return classifier ? String(classifier).split(" :: ").at(-1) : "UNKNOWN";
}
