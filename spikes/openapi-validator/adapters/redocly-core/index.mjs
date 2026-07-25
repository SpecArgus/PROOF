import {
  BaseResolver,
  ResolveError,
  Source,
  YamlParseError,
  createConfig,
  getLineColLocation,
  lintDocument,
} from '@redocly/openapi-core';
import jsoncParser from 'jsonc-parser';
import { createHash } from 'node:crypto';
import {
  constants as fsConstants,
  promises as fs,
  realpathSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { TextDecoder } from 'node:util';

const ADAPTER_NAME = 'redocly-core';
const SCHEMA_VERSION = 1;
const DEFAULT_LIMITS = Object.freeze({
  maxEntrypointBytes: 1024 * 1024,
  maxFiles: 100,
  maxTotalBytes: 20 * 1024 * 1024,
  maxDepth: 32,
  maxDiagnostics: 100,
});
const DENIAL_TOKEN =
  /\[PROOF:(parse|policy|limit|reference):([a-z0-9.-]+)\]\s*(.*)$/;
const { printParseErrorCode, visit: visitJson } = jsoncParser;
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true });
const READ_CHUNK_BYTES = 64 * 1024;

class ContractError extends Error {}

class ControlledResolverError extends Error {
  constructor(category, code, message, location = {}) {
    super(`[PROOF:${category}:${code}] ${message}`);
    this.category = category;
    this.code = code;
    this.source = location.source ?? null;
    this.line = location.line ?? null;
    this.col = location.column ?? null;
    this.pointer = location.pointer ?? null;
  }
}

function toPosix(value) {
  return value.replaceAll('\\', '/');
}

function isWithin(root, target) {
  const relative = path.relative(root, target);
  return (
    relative === '' ||
    (!relative.startsWith(`..${path.sep}`) &&
      relative !== '..' &&
      !path.isAbsolute(relative))
  );
}

function isSamePath(left, right) {
  return path.relative(left, right) === '' && path.relative(right, left) === '';
}

function isSameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

async function readHandleBounded(fileHandle, maxBytes) {
  const chunks = [];
  let totalBytes = 0;

  while (true) {
    const remaining = maxBytes - totalBytes;
    const bytesToRead = Math.min(READ_CHUNK_BYTES, remaining + 1);
    const chunk = Buffer.allocUnsafe(bytesToRead);
    const { bytesRead } = await fileHandle.read(
      chunk,
      0,
      bytesToRead,
      null,
    );
    if (bytesRead === 0) {
      return {
        content: Buffer.concat(chunks, totalBytes),
        exceeded: false,
      };
    }
    if (bytesRead > remaining) {
      return { content: null, exceeded: true };
    }
    chunks.push(chunk.subarray(0, bytesRead));
    totalBytes += bytesRead;
  }
}

function denial(category, code, message) {
  return { category, code, message };
}

function escapePointerSegment(value) {
  return String(value).replaceAll('~', '~0').replaceAll('/', '~1');
}

/**
 * Classify a non-fragment reference before Redocly resolves it.
 *
 * OpenAPI references are URI references, so both POSIX and Windows absolute
 * spellings are rejected on every host. Relative references are resolved only
 * beneath repositoryRoot.
 */
export function classifyReference({ base, ref, repositoryRoot }) {
  if (typeof ref !== 'string' || ref.length === 0 || ref.includes('\0')) {
    return denial('policy', 'ref.scheme-denied', 'Invalid references are denied.');
  }

  let decodedRef;
  try {
    decodedRef = decodeURIComponent(ref);
  } catch {
    return denial(
      'policy',
      'ref.scheme-denied',
      'Malformed percent-encoded references are disabled.',
    );
  }
  if (
    decodedRef.includes('\0') ||
    decodedRef.includes('?') ||
    decodedRef.includes('#')
  ) {
    return denial(
      'policy',
      'ref.scheme-denied',
      'Query, fragment, and null-byte path references are disabled.',
    );
  }

  if (/^https?:/i.test(decodedRef)) {
    return denial('policy', 'ref.scheme-denied', 'Remote references are disabled.');
  }
  if (/^file:/i.test(decodedRef)) {
    return denial('policy', 'ref.scheme-denied', 'File URL references are disabled.');
  }
  if (/^\/\//.test(decodedRef)) {
    return denial(
      'policy',
      'ref.scheme-denied',
      'Protocol-relative references are disabled.',
    );
  }
  if (/^\\\\/.test(decodedRef)) {
    return denial('policy', 'ref.scheme-denied', 'UNC references are disabled.');
  }
  if (path.posix.isAbsolute(decodedRef) || path.win32.isAbsolute(decodedRef)) {
    return denial('policy', 'ref.scheme-denied', 'Absolute references are disabled.');
  }
  if (/^[a-z][a-z0-9+.-]*:/i.test(decodedRef)) {
    return denial('policy', 'ref.scheme-denied', 'URI scheme references are disabled.');
  }

  const baseDirectory = base ? path.dirname(base) : repositoryRoot;
  const candidate = path.resolve(
    baseDirectory,
    decodedRef.replaceAll('\\', path.sep),
  );
  if (!isWithin(repositoryRoot, candidate)) {
    return denial(
      'policy',
      'ref.path-outside-root',
      'References outside the repository root are disabled.',
    );
  }

  return { candidate };
}

async function nearestExistingRealPath(target) {
  let current = target;
  while (true) {
    try {
      return await fs.realpath(current);
    } catch (error) {
      if (error?.code !== 'ENOENT') {
        throw error;
      }
      const parent = path.dirname(current);
      if (parent === current) {
        throw error;
      }
      current = parent;
    }
  }
}

function firstStrictJsonIssue(body) {
  const issues = [];
  const objectProperties = [];
  visitJson(
    body,
    {
      onObjectBegin() {
        objectProperties.push(new Set());
      },
      onObjectProperty(property, offset, _length, line, column) {
        const properties = objectProperties.at(-1);
        if (properties?.has(property)) {
          issues.push({
            offset,
            line: line + 1,
            column: column + 1,
            code: 'parse.duplicate-key',
            message: 'Duplicate JSON object keys are not allowed.',
          });
        }
        properties?.add(property);
      },
      onObjectEnd() {
        objectProperties.pop();
      },
      onError(error, offset, _length, line, column) {
        issues.push({
          offset,
          line: line + 1,
          column: column + 1,
          code: 'parse.invalid-json',
          message: `Invalid JSON (${printParseErrorCode(error)}).`,
        });
      },
    },
    {
      allowEmptyContent: false,
      allowTrailingComma: false,
      disallowComments: true,
    },
  );
  return issues.sort((left, right) => left.offset - right.offset)[0] ?? null;
}

function multipleYamlDocumentLocation(body) {
  const lines = body.split(/\r\n|[\n\r]/g);
  const documentStarts = [];
  let meaningfulContentBeforeFirstStart = false;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (/^---(?:[ \t]+#.*)?[ \t]*$/.test(line)) {
      documentStarts.push({ line: index + 1, column: 1 });
      continue;
    }
    if (
      documentStarts.length === 0 &&
      line.trim() !== '' &&
      !/^[ \t]*#/.test(line)
    ) {
      meaningfulContentBeforeFirstStart = true;
    }
  }

  if (meaningfulContentBeforeFirstStart) {
    return documentStarts[0] ?? { line: 1, column: 1 };
  }
  return documentStarts[1] ?? documentStarts[0] ?? { line: 1, column: 1 };
}

class RepositoryResolver extends BaseResolver {
  constructor(repositoryRoot, limits) {
    super({ http: { headers: [] } });
    this.repositoryRoot = path.resolve(repositoryRoot);
    this.realRepositoryRoot = realpathSync(this.repositoryRoot);
    this.limits = limits;
    this.deniedReferences = new Map();
    this.depthBySource = new Map();
    this.referenceSites = new Map();
    this.referenceCalls = new Map();
    this.referenceSiteByTarget = new Map();
    this.controlledSites = new Map();
    this.attemptedFiles = new Set();
    this.loadedFiles = new Map();
    this.totalBytes = 0;
    this.entrypointBytes = 0;
    this.referencesSeen = 0;
    this.maxDepthObserved = 0;
    this.policyDenials = 0;
    this.limitDenials = 0;
    this.limitCode = null;
  }

  indexReferenceSites(document) {
    const seen = new WeakSet();
    const active = new WeakSet();
    const stack = [{ type: 'visit', node: document.parsed, pointer: '' }];

    while (stack.length > 0) {
      const task = stack.pop();
      if (task.type === 'leave') {
        active.delete(task.node);
        continue;
      }
      if (task.type === 'property') {
        const { key, value, pointer: childPointer } = task;
        if (
          (key === '$ref' || key === 'externalValue') &&
          typeof value === 'string' &&
          !value.startsWith('#')
        ) {
          let location = null;
          try {
            location = getLineColLocation({
              source: document.source,
              pointer: `#${childPointer}`,
              reportOnKey: true,
            });
          } catch {
            // A missing AST location is represented as null coordinates.
          }
          const site = {
            source: document.source.absoluteRef,
            line: location?.start?.line ?? null,
            column: location?.start?.col ?? null,
            pointer: childPointer,
          };
          const referenceKey = `${document.source.absoluteRef}\0${value.split('#', 1)[0]}`;
          const sites = this.referenceSites.get(referenceKey) ?? [];
          sites.push(site);
          this.referenceSites.set(referenceKey, sites);
          this.referencesSeen += 1;
        }
        stack.push({ type: 'visit', node: value, pointer: childPointer });
        continue;
      }

      const { node, pointer } = task;
      if (node === null || typeof node !== 'object') {
        continue;
      }
      if (active.has(node)) {
        let location = null;
        try {
          location = getLineColLocation({
            source: document.source,
            pointer: `#${pointer}`,
            reportOnKey: false,
          });
        } catch {
          // The pointer remains useful if the parser has no AST coordinate.
        }
        const site = {
          source: document.source.absoluteRef,
          line: location?.start?.line ?? null,
          column: location?.start?.col ?? null,
          pointer,
        };
        this.recordControlledSite('parse.cyclic-alias', site);
        throw new ControlledResolverError(
          'parse',
          'parse.cyclic-alias',
          'Cyclic YAML aliases are not supported.',
          site,
        );
      }
      if (seen.has(node)) {
        continue;
      }
      seen.add(node);
      active.add(node);
      stack.push({ type: 'leave', node });

      if (Array.isArray(node)) {
        for (let index = node.length - 1; index >= 0; index -= 1) {
          stack.push({
            type: 'visit',
            node: node[index],
            pointer: `${pointer}/${index}`,
          });
        }
        continue;
      }

      const entries = Object.entries(node);
      for (let index = entries.length - 1; index >= 0; index -= 1) {
        const [key, value] = entries[index];
        stack.push({
          type: 'property',
          key,
          value,
          pointer: `${pointer}/${escapePointerSegment(key)}`,
        });
      }
    }
  }

  nextReferenceSite(base, ref) {
    if (base === null) {
      return null;
    }
    const key = `${base}\0${ref}`;
    const call = this.referenceCalls.get(key) ?? 0;
    this.referenceCalls.set(key, call + 1);
    const sites = this.referenceSites.get(key) ?? [];
    return sites[Math.min(Math.floor(call / 2), Math.max(sites.length - 1, 0))] ?? null;
  }

  recordControlledSite(code, site) {
    if (!site) {
      return;
    }
    const sites = this.controlledSites.get(code) ?? [];
    sites.push(site);
    this.controlledSites.set(code, sites);
  }

  takeControlledSite(code) {
    return this.controlledSites.get(code)?.shift() ?? null;
  }

  recordLimit(code) {
    this.limitDenials += 1;
    this.limitCode ??= code;
  }

  createDeniedPath(base, ref, decision, site) {
    const digest = createHash('sha256')
      .update(`${base ?? '<root>'}\0${ref}\0${decision.code}`)
      .digest('hex');
    const deniedPath = path.join(
      this.repositoryRoot,
      '.redocly-adapter-denied',
      `${digest}.yaml`,
    );
    if (this.deniedReferences.has(deniedPath)) {
      return deniedPath;
    }
    this.deniedReferences.set(deniedPath, decision);
    this.recordControlledSite(decision.code, site);
    if (decision.category === 'policy') {
      this.policyDenials += 1;
    } else {
      this.recordLimit(decision.code);
    }
    return deniedPath;
  }

  resolveExternalRef(base, ref) {
    const site = this.nextReferenceSite(base, ref);
    const decision = classifyReference({
      base,
      ref,
      repositoryRoot: this.repositoryRoot,
    });
    if (!decision.candidate) {
      return this.createDeniedPath(base, ref, decision, site);
    }

    const knownDepth = this.depthBySource.get(decision.candidate);
    if (knownDepth !== undefined) {
      return decision.candidate;
    }

    const baseDepth = base === null ? -1 : (this.depthBySource.get(base) ?? 0);
    const candidateDepth = baseDepth + 1;
    this.maxDepthObserved = Math.max(this.maxDepthObserved, candidateDepth);
    if (candidateDepth > this.limits.maxDepth) {
      return this.createDeniedPath(
        base,
        ref,
        denial(
          'limit',
          'ref.depth-exceeded',
          `Reference depth exceeds the configured maximum of ${this.limits.maxDepth}.`,
        ),
        site,
      );
    }

    this.depthBySource.set(decision.candidate, candidateDepth);
    if (site && !this.referenceSiteByTarget.has(decision.candidate)) {
      this.referenceSiteByTarget.set(decision.candidate, site);
    }
    return decision.candidate;
  }

  controlledSiteFor(absoluteRef) {
    return this.referenceSiteByTarget.get(absoluteRef) ?? null;
  }

  makePolicyError(code, message, absoluteRef) {
    const site = this.controlledSiteFor(absoluteRef);
    this.policyDenials += 1;
    this.recordControlledSite(code, site);
    return new ControlledResolverError('policy', code, message, site ?? {});
  }

  makeLimitError(code, message, absoluteRef) {
    const site = this.controlledSiteFor(absoluteRef);
    this.recordLimit(code);
    this.recordControlledSite(code, site);
    return new ControlledResolverError('limit', code, message, site ?? {});
  }

  async revalidateOpenedTarget(
    absoluteRef,
    expectedRealTarget,
    openedStat,
  ) {
    const currentRealTarget = await fs.realpath(absoluteRef);
    if (!isWithin(this.realRepositoryRoot, currentRealTarget)) {
      throw this.makePolicyError(
        'ref.path-outside-root',
        'The reference resolved outside the repository while it was being read.',
        absoluteRef,
      );
    }
    if (!isSamePath(expectedRealTarget, currentRealTarget)) {
      throw this.makePolicyError(
        'ref.path-changed',
        'The referenced path changed while it was being read.',
        absoluteRef,
      );
    }
    const currentStat = await fs.stat(currentRealTarget);
    if (!isSameFileIdentity(openedStat, currentStat)) {
      throw this.makePolicyError(
        'ref.path-changed',
        'The referenced file identity changed while it was being read.',
        absoluteRef,
      );
    }
  }

  async loadExternalRef(absoluteRef) {
    const denied = this.deniedReferences.get(absoluteRef);
    if (denied) {
      throw new ResolveError(
        new ControlledResolverError(denied.category, denied.code, denied.message),
      );
    }

    if (
      !this.attemptedFiles.has(absoluteRef) &&
      this.attemptedFiles.size >= this.limits.maxFiles
    ) {
      throw new ResolveError(
        this.makeLimitError(
          'ref.file-count-exceeded',
          `Reference attempts exceed the configured maximum of ${this.limits.maxFiles}.`,
          absoluteRef,
        ),
      );
    }
    this.attemptedFiles.add(absoluteRef);

    try {
      const realTarget = await fs.realpath(absoluteRef);
      if (!isWithin(this.realRepositoryRoot, realTarget)) {
        throw this.makePolicyError(
          'ref.path-outside-root',
          'Symlinked references outside the repository root are disabled.',
          absoluteRef,
        );
      }

      const cachedContent = this.loadedFiles.get(realTarget);
      if (cachedContent !== undefined) {
        return new Source(absoluteRef, cachedContent);
      }

      const targetStat = await fs.lstat(realTarget);
      if (!targetStat.isFile()) {
        const site = this.controlledSiteFor(absoluteRef);
        this.recordControlledSite('reference.not-regular-file', site);
        throw new ControlledResolverError(
          'reference',
          'reference.not-regular-file',
          'References must resolve to regular files.',
          site ?? {},
        );
      }

      const openFlags =
        fsConstants.O_RDONLY |
        (fsConstants.O_NOFOLLOW ?? 0) |
        (fsConstants.O_NONBLOCK ?? 0);
      const fileHandle = await fs.open(realTarget, openFlags);
      let content;
      try {
        const openedStat = await fileHandle.stat();
        if (!openedStat.isFile()) {
          const site = this.controlledSiteFor(absoluteRef);
          this.recordControlledSite('reference.not-regular-file', site);
          throw new ControlledResolverError(
            'reference',
            'reference.not-regular-file',
            'References must resolve to regular files.',
            site ?? {},
          );
        }

        await this.revalidateOpenedTarget(
          absoluteRef,
          realTarget,
          openedStat,
        );

        const isEntrypoint = this.depthBySource.get(absoluteRef) === 0;
        const remainingTotalBytes =
          this.limits.maxTotalBytes - this.totalBytes;
        const entrypointBudget = isEntrypoint
          ? this.limits.maxEntrypointBytes
          : Number.MAX_SAFE_INTEGER;

        if (isEntrypoint && openedStat.size > entrypointBudget) {
          throw this.makeLimitError(
            'input.entrypoint-bytes-exceeded',
            `Entrypoint bytes exceed the configured maximum of ${this.limits.maxEntrypointBytes}.`,
            absoluteRef,
          );
        }
        if (openedStat.size > remainingTotalBytes) {
          throw this.makeLimitError(
            'ref.aggregate-bytes-exceeded',
            `Loaded bytes exceed the configured maximum of ${this.limits.maxTotalBytes}.`,
            absoluteRef,
          );
        }

        const byteBudget = Math.min(
          entrypointBudget,
          remainingTotalBytes,
        );
        const boundedRead = await readHandleBounded(fileHandle, byteBudget);
        if (boundedRead.exceeded) {
          if (isEntrypoint && entrypointBudget <= remainingTotalBytes) {
            throw this.makeLimitError(
              'input.entrypoint-bytes-exceeded',
              `Entrypoint bytes exceed the configured maximum of ${this.limits.maxEntrypointBytes}.`,
              absoluteRef,
            );
          }
          throw this.makeLimitError(
            'ref.aggregate-bytes-exceeded',
            `Loaded bytes exceed the configured maximum of ${this.limits.maxTotalBytes}.`,
            absoluteRef,
          );
        }
        content = boundedRead.content;

        await this.revalidateOpenedTarget(
          absoluteRef,
          realTarget,
          openedStat,
        );
      } finally {
        await fileHandle.close();
      }

      let decodedContent;
      try {
        decodedContent = UTF8_DECODER.decode(content);
      } catch {
        const location = {
          source: absoluteRef,
          line: 1,
          column: 1,
          pointer: null,
        };
        this.recordControlledSite('parse.invalid-utf8', location);
        throw new ControlledResolverError(
          'parse',
          'parse.invalid-utf8',
          'Input is not valid UTF-8.',
          location,
        );
      }
      const normalizedContent = decodedContent.replace(/\r\n/g, '\n');
      this.loadedFiles.set(realTarget, normalizedContent);
      this.totalBytes += content.byteLength;
      if (this.depthBySource.get(absoluteRef) === 0) {
        this.entrypointBytes = content.byteLength;
      }
      return new Source(absoluteRef, normalizedContent);
    } catch (error) {
      if (error instanceof ResolveError) {
        throw error;
      }
      if (error instanceof ControlledResolverError) {
        throw new ResolveError(error);
      }

      if (error?.code === 'ENOENT') {
        const nearest = await nearestExistingRealPath(absoluteRef);
        if (!isWithin(this.realRepositoryRoot, nearest)) {
          throw new ResolveError(
            this.makePolicyError(
              'ref.path-outside-root',
              'Symlinked references outside the repository root are disabled.',
              absoluteRef,
            ),
          );
        }
      }

      const stableError = new Error(normalizeMessage(error?.message ?? String(error), this));
      stableError.code = error?.code;
      throw new ResolveError(stableError);
    }
  }

  parseDocument(source, isRoot = false) {
    if (path.extname(source.absoluteRef).toLowerCase() === '.json') {
      const issue = firstStrictJsonIssue(source.body);
      if (issue) {
        throw new YamlParseError(
          new Error(
            `[PROOF:parse:${issue.code}] ${issue.message} (${issue.line}:${issue.column})`,
          ),
          source,
        );
      }
      let parsed;
      try {
        parsed = JSON.parse(source.body);
      } catch {
        throw new YamlParseError(
          new Error(
            '[PROOF:parse:parse.invalid-json] Invalid JSON. (1:1)',
          ),
          source,
        );
      }
      const document = { source, parsed };
      this.indexReferenceSites(document);
      return document;
    }
    let document;
    try {
      document = super.parseDocument(source, isRoot);
    } catch (error) {
      if (
        error instanceof YamlParseError &&
        /expected a single document/i.test(error.message)
      ) {
        const location = multipleYamlDocumentLocation(source.body);
        error.line = location.line;
        error.col = location.column;
      }
      throw error;
    }
    this.indexReferenceSites(document);
    return document;
  }
}

function parseControlledError(error) {
  const candidates = [
    error?.originalError,
    error?.cause,
    error,
  ];
  for (const candidate of candidates) {
    const match =
      typeof candidate?.message === 'string'
        ? candidate.message.match(DENIAL_TOKEN)
        : null;
    if (match) {
      return {
        category: match[1],
        code: match[2],
        message: match[3],
        detail: candidate,
      };
    }
  }
  return null;
}

function normalizeMessage(message, resolver) {
  let normalized = String(message).replace(/\r?\n/g, ' ');
  const roots = new Set([
    toPosix(resolver.repositoryRoot),
    toPosix(resolver.realRepositoryRoot),
  ]);
  normalized = toPosix(normalized);
  for (const root of roots) {
    normalized = normalized.replaceAll(root, '<repository>');
  }
  return normalized.replace(/\s+/g, ' ').trim();
}

function normalizeSource(source, resolver) {
  const sourcePath =
    typeof source === 'string' ? source : source?.absoluteRef;
  if (!sourcePath) {
    return null;
  }
  const absolute = path.resolve(sourcePath);
  if (!isWithin(resolver.repositoryRoot, absolute)) {
    return null;
  }
  return toPosix(path.relative(resolver.repositoryRoot, absolute));
}

function pointerWithoutHash(pointer) {
  if (typeof pointer !== 'string') {
    return null;
  }
  if (pointer === '#') {
    return '';
  }
  return pointer.startsWith('#') ? pointer.slice(1) : pointer;
}

function normalizeProblem(problem, resolver) {
  const rawLocation = problem.location?.[0];
  const controlled = parseControlledError({ message: problem.message });
  const controlledSite = controlled
    ? resolver.takeControlledSite(controlled.code)
    : null;
  const code =
    controlled?.code ??
    (problem.ruleId === 'no-unresolved-refs' ? 'ref.unresolved' : 'oas.schema');
  const kind =
    controlled?.category ??
    (problem.ruleId === 'no-unresolved-refs' ? 'reference' : 'schema');
  let lineLocation = rawLocation;
  if (rawLocation?.pointer !== undefined) {
    try {
      lineLocation = getLineColLocation({
        ...rawLocation,
        reportOnKey: kind === 'schema' ? true : rawLocation.reportOnKey,
      });
    } catch {
      lineLocation = rawLocation;
    }
  }

  const rawPointer =
    controlledSite?.pointer ?? pointerWithoutHash(rawLocation?.pointer);
  const pointer =
    (kind === 'reference' || kind === 'policy' || kind === 'limit') &&
    rawPointer !== null &&
    !rawPointer.endsWith('/$ref')
      ? `${rawPointer}/$ref`.replace('//', '/')
      : rawPointer;

  return {
    source: normalizeSource(
      controlledSite?.source ?? rawLocation?.source?.absoluteRef,
      resolver,
    ),
    line: controlledSite?.line ?? lineLocation?.start?.line ?? null,
    column: controlledSite?.column ?? lineLocation?.start?.col ?? null,
    pointer,
    code,
    severity: problem.severity === 'warn' ? 'warning' : 'error',
    kind,
    message: normalizeMessage(controlled?.message ?? problem.message, resolver),
  };
}

function normalizeThrownDiagnostic(error, source, resolver) {
  const controlled = parseControlledError(error);
  if (controlled) {
    const detail = controlled.detail;
    return {
      source: normalizeSource(detail?.source, resolver) ?? source,
      line: Number.isFinite(detail?.line)
        ? detail.line
        : Number.isFinite(error?.line)
          ? error.line
          : null,
      column: Number.isFinite(detail?.col)
        ? detail.col
        : Number.isFinite(error?.col)
          ? error.col
          : null,
      pointer: detail?.pointer ?? null,
      code: controlled.code,
      severity: 'error',
      kind: controlled.category,
      message: normalizeMessage(controlled.message, resolver),
    };
  }

  if (error instanceof YamlParseError) {
    const duplicateKey = /duplicated mapping key/i.test(error.message);
    const multipleDocuments = /expected a single document/i.test(error.message);
    const jsonInput = path.extname(error.source?.absoluteRef ?? '').toLowerCase() === '.json';
    return {
      source: normalizeSource(error.source?.absoluteRef, resolver) ?? source,
      line: Number.isFinite(error.line) ? error.line : null,
      column: Number.isFinite(error.col) ? error.col : null,
      pointer: null,
      code: duplicateKey
        ? 'parse.duplicate-key'
        : multipleDocuments
          ? 'parse.multiple-documents'
        : jsonInput
          ? 'parse.invalid-json'
          : 'parse.invalid-yaml',
      severity: 'error',
      kind: 'parse',
      message: normalizeMessage(error.message, resolver),
    };
  }

  return null;
}

function outcomeForDiagnostic(diagnostic) {
  if (diagnostic.kind === 'limit') {
    return 'limit-exceeded';
  }
  if (diagnostic.kind === 'policy') {
    return 'policy-denied';
  }
  if (diagnostic.kind === 'parse') {
    return 'parse-error';
  }
  return 'invalid';
}

function compareNullable(a, b) {
  if (a === b) return 0;
  if (a === null) return 1;
  if (b === null) return -1;
  return a < b ? -1 : 1;
}

function sortDiagnostics(diagnostics) {
  const keys = [
    'source',
    'line',
    'column',
    'pointer',
    'code',
    'severity',
    'kind',
    'message',
  ];
  return diagnostics.sort((left, right) => {
    for (const key of keys) {
      const comparison = compareNullable(left[key], right[key]);
      if (comparison !== 0) return comparison;
    }
    return 0;
  });
}

function deduplicateDiagnostics(diagnostics) {
  const seen = new Set();
  return diagnostics.filter((diagnostic) => {
    const key = JSON.stringify([
      diagnostic.source,
      diagnostic.line,
      diagnostic.column,
      diagnostic.pointer,
      diagnostic.code,
      diagnostic.severity,
      diagnostic.kind,
      diagnostic.message,
    ]);
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function makeStats(resolver, limits, diagnosticsTotal, diagnosticsEmitted) {
  const diagnosticsTruncated = diagnosticsTotal - diagnosticsEmitted;
  return {
    filesAttempted: resolver.attemptedFiles.size,
    filesLoaded: resolver.loadedFiles.size,
    filesRead: resolver.loadedFiles.size,
    entrypointBytes: resolver.entrypointBytes,
    totalBytes: resolver.totalBytes,
    aggregateBytesRead: resolver.totalBytes,
    referencesSeen: resolver.referencesSeen,
    maxDepthObserved: resolver.maxDepthObserved,
    maximumDepthObserved: resolver.maxDepthObserved,
    raw: diagnosticsTotal,
    emitted: diagnosticsEmitted,
    truncated: diagnosticsTruncated > 0,
    truncatedCount: diagnosticsTruncated,
    diagnosticsRaw: diagnosticsTotal,
    diagnosticsEmitted,
    diagnosticsTruncated,
    isTruncated: diagnosticsTruncated > 0,
    policyDenials: resolver.policyDenials,
    limitDenials: resolver.limitDenials,
    limitCode: resolver.limitCode,
    limits,
  };
}

function finalize({ diagnostics, resolver, limits, forcedOutcome }) {
  const sorted = deduplicateDiagnostics(sortDiagnostics(diagnostics));
  const emitted = sorted.slice(0, limits.maxDiagnostics);
  const diagnosticsLimitExceeded = sorted.length > emitted.length;
  if (diagnosticsLimitExceeded) {
    resolver.recordLimit('diagnostics.limit-exceeded');
    resolver.limitCode = 'diagnostics.limit-exceeded';
  }
  const outcome =
    diagnosticsLimitExceeded
      ? 'limit-exceeded'
      : forcedOutcome ??
        (resolver.limitDenials > 0
          ? 'limit-exceeded'
          : resolver.policyDenials > 0
            ? 'policy-denied'
            : sorted.some((diagnostic) => diagnostic.kind === 'parse')
              ? 'parse-error'
            : sorted.some((diagnostic) => diagnostic.severity === 'error')
              ? 'invalid'
              : 'valid');

  return {
    schemaVersion: SCHEMA_VERSION,
    adapter: ADAPTER_NAME,
    outcome,
    diagnostics: emitted,
    stats: makeStats(resolver, limits, sorted.length, emitted.length),
  };
}

function assertLimit(name, value, { allowZero = false } = {}) {
  const parsed = Number(value);
  const minimum = allowZero ? 0 : 1;
  if (!Number.isSafeInteger(parsed) || parsed < minimum) {
    throw new ContractError(`${name} must be a safe integer greater than or equal to ${minimum}.`);
  }
  return parsed;
}

export function parseArguments(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (!argument.startsWith('--')) {
      throw new ContractError(`Unexpected positional argument: ${argument}`);
    }
    const name = argument.slice(2);
    const value = argv[index + 1];
    if (value === undefined || value.startsWith('--')) {
      throw new ContractError(`Missing value for --${name}.`);
    }
    if (Object.hasOwn(options, name)) {
      throw new ContractError(`Duplicate option: --${name}.`);
    }
    options[name] = value;
    index += 1;
  }

  const allowed = new Set([
    'entrypoint',
    'repository-root',
    'max-entrypoint-bytes',
    'max-files',
    'max-total-bytes',
    'max-depth',
    'max-diagnostics',
  ]);
  for (const name of Object.keys(options)) {
    if (!allowed.has(name)) {
      throw new ContractError(`Unknown option: --${name}.`);
    }
  }
  if (!options.entrypoint) {
    throw new ContractError('--entrypoint is required.');
  }
  if (!options['repository-root']) {
    throw new ContractError('--repository-root is required.');
  }

  return {
    entrypoint: options.entrypoint,
    repositoryRoot: options['repository-root'],
    maxEntrypointBytes:
      options['max-entrypoint-bytes'] === undefined
        ? DEFAULT_LIMITS.maxEntrypointBytes
        : assertLimit('--max-entrypoint-bytes', options['max-entrypoint-bytes'], {
            allowZero: true,
          }),
    maxFiles:
      options['max-files'] === undefined
        ? DEFAULT_LIMITS.maxFiles
        : assertLimit('--max-files', options['max-files'], { allowZero: true }),
    maxTotalBytes:
      options['max-total-bytes'] === undefined
        ? DEFAULT_LIMITS.maxTotalBytes
        : assertLimit('--max-total-bytes', options['max-total-bytes'], { allowZero: true }),
    maxDepth:
      options['max-depth'] === undefined
        ? DEFAULT_LIMITS.maxDepth
        : assertLimit('--max-depth', options['max-depth'], { allowZero: true }),
    maxDiagnostics:
      options['max-diagnostics'] === undefined
        ? DEFAULT_LIMITS.maxDiagnostics
        : assertLimit('--max-diagnostics', options['max-diagnostics'], { allowZero: true }),
  };
}

export async function validateEntrypoint({
  entrypoint,
  repositoryRoot,
  maxEntrypointBytes = DEFAULT_LIMITS.maxEntrypointBytes,
  maxFiles = DEFAULT_LIMITS.maxFiles,
  maxTotalBytes = DEFAULT_LIMITS.maxTotalBytes,
  maxDepth = DEFAULT_LIMITS.maxDepth,
  maxDiagnostics = DEFAULT_LIMITS.maxDiagnostics,
}) {
  const limits = {
    maxEntrypointBytes: assertLimit(
      'maxEntrypointBytes',
      maxEntrypointBytes,
      { allowZero: true },
    ),
    maxFiles: assertLimit('maxFiles', maxFiles, { allowZero: true }),
    maxTotalBytes: assertLimit('maxTotalBytes', maxTotalBytes, { allowZero: true }),
    maxDepth: assertLimit('maxDepth', maxDepth, { allowZero: true }),
    maxDiagnostics: assertLimit('maxDiagnostics', maxDiagnostics, { allowZero: true }),
  };
  const resolvedRoot = path.resolve(repositoryRoot);
  let resolver;
  try {
    resolver = new RepositoryResolver(resolvedRoot, limits);
  } catch (error) {
    throw new ContractError(`Repository root is not readable: ${error?.code ?? 'unknown error'}.`);
  }

  const absoluteEntrypoint = path.isAbsolute(entrypoint)
    ? path.resolve(entrypoint)
    : path.resolve(resolver.repositoryRoot, entrypoint);
  if (!isWithin(resolver.repositoryRoot, absoluteEntrypoint)) {
    const diagnostic = {
      source: null,
      line: null,
      column: null,
      pointer: null,
      code: 'ref.path-outside-root',
      severity: 'error',
      kind: 'policy',
      message: 'The entrypoint must be inside the repository root.',
    };
    resolver.policyDenials += 1;
    return finalize({
      diagnostics: [diagnostic],
      resolver,
      limits,
      forcedOutcome: 'policy-denied',
    });
  }

  const entrypointSource = normalizeSource(absoluteEntrypoint, resolver);
  const relativeEntrypoint = path.relative(resolver.repositoryRoot, absoluteEntrypoint);
  let document;
  try {
    document = await resolver.resolveDocument(null, relativeEntrypoint, true);
  } catch (error) {
    const diagnostic = normalizeThrownDiagnostic(error, entrypointSource, resolver);
    if (diagnostic) {
      return finalize({
        diagnostics: [diagnostic],
        resolver,
        limits,
        forcedOutcome: outcomeForDiagnostic(diagnostic),
      });
    }
    throw new ContractError(
      `Entrypoint could not be loaded: ${normalizeMessage(error?.message ?? String(error), resolver)}`,
    );
  }

  const config = await createConfig(
    { extends: ['spec'] },
    { externalRefResolver: resolver },
  );
  let problems;
  try {
    problems = await lintDocument({
      document,
      config,
      externalRefResolver: resolver,
    });
  } catch (error) {
    const diagnostic = normalizeThrownDiagnostic(error, entrypointSource, resolver);
    if (diagnostic) {
      return finalize({
        diagnostics: [diagnostic],
        resolver,
        limits,
        forcedOutcome: outcomeForDiagnostic(diagnostic),
      });
    }
    throw error;
  }

  return finalize({
    diagnostics: problems.map((problem) => normalizeProblem(problem, resolver)),
    resolver,
    limits,
  });
}

function contractFailure(error) {
  return {
    schemaVersion: SCHEMA_VERSION,
    adapter: ADAPTER_NAME,
    outcome: 'invalid',
    diagnostics: [
      {
        source: null,
        line: null,
        column: null,
        pointer: null,
        code: error instanceof ContractError ? 'adapter-contract-error' : 'adapter-internal-error',
        severity: 'error',
        kind: error instanceof ContractError ? 'contract' : 'internal',
        message:
          error instanceof ContractError
            ? error.message
            : 'The adapter failed unexpectedly. See the process error stream.',
      },
    ],
    stats: {
      filesAttempted: 0,
      filesLoaded: 0,
      filesRead: 0,
      totalBytes: 0,
      aggregateBytesRead: 0,
      maxDepthObserved: 0,
      maximumDepthObserved: 0,
      raw: 1,
      emitted: 1,
      truncated: false,
      truncatedCount: 0,
      diagnosticsRaw: 1,
      diagnosticsEmitted: 1,
      diagnosticsTruncated: 0,
      isTruncated: false,
      policyDenials: 0,
      limitDenials: 0,
      limits: null,
    },
  };
}

async function main() {
  try {
    const result = await validateEntrypoint(parseArguments(process.argv.slice(2)));
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stdout.write(`${JSON.stringify(contractFailure(error))}\n`);
    if (!(error instanceof ContractError)) {
      process.stderr.write(`${error?.stack ?? error}\n`);
    }
    process.exitCode = 2;
  }
}

const isMain =
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));
if (isMain) {
  await main();
}
