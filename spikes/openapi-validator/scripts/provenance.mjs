import { createHash } from "node:crypto";
import {
  lstatSync,
  readFileSync,
  readdirSync,
  readlinkSync,
} from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

export const spikeRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);

const evaluationInputs = [
  "package.json",
  "package-lock.json",
  "adapters",
  path.join("corpus", "adapter-cases"),
  path.join("scripts", "evaluate-adapters.mjs"),
  path.join("scripts", "python-runtime.mjs"),
  path.join("scripts", "provenance.mjs"),
];

const stageOneInputs = [
  "package.json",
  "package-lock.json",
  "candidates",
  path.join("corpus", "manifest.json"),
  path.join("corpus", "cases"),
  path.join("corpus", "templates"),
  path.join("scripts", "evaluate.mjs"),
  path.join("scripts", "provenance.mjs"),
];

export function evaluationInputSha256() {
  return sha256Paths(evaluationInputs.map((entry) => path.join(spikeRoot, entry)));
}

export function stageOneInputSha256() {
  return sha256Paths(stageOneInputs.map((entry) => path.join(spikeRoot, entry)));
}

export function sha256File(filename) {
  return createHash("sha256").update(readFileSync(filename)).digest("hex");
}

export function sha256Paths(entries) {
  const files = [];
  for (const entry of entries) {
    collect(entry, files);
  }
  files.sort((left, right) =>
    portablePath(left.relative).localeCompare(portablePath(right.relative), "en"),
  );

  const hash = createHash("sha256");
  for (const file of files) {
    hash.update(portablePath(file.relative));
    hash.update("\0");
    hash.update(file.kind);
    hash.update("\0");
    hash.update(file.content);
    hash.update("\0");
  }
  return hash.digest("hex");
}

function collect(entry, files) {
  const stats = lstatSync(entry);
  const relative = path.relative(spikeRoot, entry);
  if (stats.isSymbolicLink()) {
    files.push({
      relative,
      kind: "symlink",
      content: Buffer.from(readlinkSync(entry), "utf8"),
    });
    return;
  }
  if (stats.isDirectory()) {
    for (const name of readdirSync(entry).sort((left, right) =>
      left.localeCompare(right, "en"),
    )) {
      collect(path.join(entry, name), files);
    }
    return;
  }
  if (!stats.isFile()) {
    throw new Error(`Unsupported provenance input type: ${entry}`);
  }
  files.push({
    relative,
    kind: "file",
    content: readFileSync(entry),
  });
}

function portablePath(value) {
  return value.split(path.sep).join("/");
}
