import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { promises as fs } from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  classifyReference,
  validateEntrypoint,
} from './index.mjs';

const adapterDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(adapterDirectory, '../../../..');
const corpus = path.join(repositoryRoot, 'spikes/openapi-validator/corpus');
const adapterCases = path.join(corpus, 'adapter-cases');
const casePath = (...segments) => path.join(corpus, ...segments);

const baseOptions = {
  repositoryRoot,
  maxEntrypointBytes: 1024 * 1024,
  maxFiles: 100,
  maxTotalBytes: 20 * 1024 * 1024,
  maxDepth: 32,
  maxDiagnostics: 100,
};

async function validate(entrypoint, overrides = {}) {
  return validateEntrypoint({
    ...baseOptions,
    ...overrides,
    entrypoint,
  });
}

async function withTemporaryRepository(prefix, callback) {
  const temporaryBase = await fs.realpath(os.tmpdir());
  const temporaryRoot = await fs.mkdtemp(path.join(temporaryBase, prefix));
  assert.equal(path.dirname(temporaryRoot), temporaryBase);
  try {
    return await callback(temporaryRoot);
  } finally {
    await fs.rm(temporaryRoot, { recursive: true, force: true });
  }
}

const valid = await validate(casePath('cases/oas30-valid.yaml'));
assert.equal(valid.adapter, 'redocly-core');
assert.equal(valid.outcome, 'valid');
assert.deepEqual(valid.diagnostics, []);
assert.equal(valid.stats.filesLoaded, 1);

const invalid = await validate(casePath('cases/oas30-invalid-structure.yaml'));
assert.equal(invalid.outcome, 'invalid');
assert.ok(invalid.diagnostics.some((item) => item.code === 'oas.schema'));
assert.ok(invalid.diagnostics.some((item) => item.pointer === '/paths/~1pets/get'));
assert.ok(invalid.diagnostics.every((item) => item.line !== null));

const malformed = await validate(casePath('cases/malformed.yaml'));
assert.equal(malformed.outcome, 'parse-error');
assert.equal(malformed.diagnostics[0].kind, 'parse');
assert.equal(malformed.diagnostics[0].code, 'parse.invalid-yaml');
assert.ok(malformed.diagnostics[0].line > 0);
assert.ok(malformed.diagnostics[0].column > 0);

const truncatedMalformed = await validate(casePath('cases/malformed.yaml'), {
  maxDiagnostics: 0,
});
assert.equal(truncatedMalformed.outcome, 'limit-exceeded');
assert.equal(truncatedMalformed.stats.diagnosticsRaw, 1);
assert.equal(truncatedMalformed.stats.diagnosticsEmitted, 0);

const validLocalRef = await validate(casePath('cases/local-ref/root.yaml'));
assert.equal(validLocalRef.outcome, 'valid');
assert.equal(validLocalRef.stats.filesLoaded, 2);

const invalidLocalRef = await validate(casePath('cases/local-ref-invalid/root.yaml'));
assert.equal(invalidLocalRef.outcome, 'invalid');
assert.ok(
  invalidLocalRef.diagnostics.some((item) =>
    item.source?.endsWith('local-ref-invalid/components.yaml')),
);
assert.ok(invalidLocalRef.diagnostics.some((item) => /type/i.test(item.message)));

const missingLocalRef = await validate(casePath('cases/missing-ref.yaml'));
assert.equal(missingLocalRef.outcome, 'invalid');
assert.ok(missingLocalRef.diagnostics.some((item) => item.kind === 'reference'));
assert.ok(
  missingLocalRef.diagnostics.every(
    (item) => !item.message.includes(repositoryRoot) && !item.message.includes('\\'),
  ),
);

const remote = await validate(casePath('templates/remote-ref.yaml'));
assert.equal(remote.outcome, 'policy-denied');
assert.ok(
  remote.diagnostics.some(
    (item) => item.code === 'ref.scheme-denied' && item.kind === 'policy',
  ),
);
assert.equal(remote.stats.filesLoaded, 1);

const temporaryBase = await fs.realpath(os.tmpdir());
const transitiveRoot = await fs.mkdtemp(
  path.join(temporaryBase, 'proof-redocly-core-'),
);
assert.equal(path.dirname(transitiveRoot), temporaryBase);
const canary = http.createServer((_request, response) => {
  canary.requests += 1;
  response.writeHead(200, { 'content-type': 'application/yaml' });
  response.end('type: string\n');
});
canary.requests = 0;
await new Promise((resolve, reject) => {
  canary.once('error', reject);
  canary.listen(0, '127.0.0.1', resolve);
});
try {
  const address = canary.address();
  assert.notEqual(address, null);
  await fs.writeFile(
    path.join(transitiveRoot, 'root.yaml'),
    [
      'openapi: 3.1.0',
      'info:',
      '  title: Transitive remote denial',
      '  version: 1.0.0',
      'paths: {}',
      'components:',
      '  schemas:',
      '    Pet:',
      '      $ref: "./components.yaml#/RemotePet"',
      '',
    ].join('\n'),
  );
  await fs.writeFile(
    path.join(transitiveRoot, 'components.yaml'),
    [
      'RemotePet:',
      `  $ref: "http://127.0.0.1:${address.port}/remote.yaml"`,
      '',
    ].join('\n'),
  );
  const transitiveRemote = await validateEntrypoint({
    ...baseOptions,
    repositoryRoot: transitiveRoot,
    entrypoint: 'root.yaml',
  });
  assert.equal(transitiveRemote.outcome, 'policy-denied');
  assert.equal(transitiveRemote.diagnostics[0].source, 'components.yaml');
  assert.equal(transitiveRemote.diagnostics[0].code, 'ref.scheme-denied');
  assert.equal(transitiveRemote.stats.filesLoaded, 2);
  assert.equal(canary.requests, 0);
} finally {
  await new Promise((resolve) => canary.close(resolve));
  await fs.rm(transitiveRoot, { recursive: true, force: true });
}

const maxFiles = await validate(casePath('cases/local-ref/root.yaml'), {
  maxFiles: 1,
});
assert.equal(maxFiles.outcome, 'limit-exceeded');
assert.ok(maxFiles.diagnostics.some((item) => item.code === 'ref.file-count-exceeded'));

const maxBytes = await validate(casePath('cases/oas30-valid.yaml'), {
  maxTotalBytes: 0,
});
assert.equal(maxBytes.outcome, 'limit-exceeded');
assert.equal(maxBytes.diagnostics[0].code, 'ref.aggregate-bytes-exceeded');

const maxEntrypointBytes = await validate(casePath('cases/oas30-valid.yaml'), {
  maxEntrypointBytes: 0,
});
assert.equal(maxEntrypointBytes.outcome, 'limit-exceeded');
assert.equal(
  maxEntrypointBytes.diagnostics[0].code,
  'input.entrypoint-bytes-exceeded',
);
assert.equal(
  maxEntrypointBytes.stats.limitCode,
  'input.entrypoint-bytes-exceeded',
);

const maxDepth = await validate(casePath('cases/local-ref/root.yaml'), {
  maxDepth: 0,
});
assert.equal(maxDepth.outcome, 'limit-exceeded');
assert.ok(maxDepth.diagnostics.some((item) => item.code === 'ref.depth-exceeded'));

const truncated = await validate(casePath('cases/oas30-invalid-structure.yaml'), {
  maxDiagnostics: 0,
});
assert.equal(truncated.outcome, 'limit-exceeded');
assert.equal(truncated.diagnostics.length, 0);
assert.ok(truncated.stats.diagnosticsTruncated > 0);
assert.equal(Number.isInteger(truncated.stats.diagnosticsTruncated), true);
assert.equal(truncated.stats.limitCode, 'diagnostics.limit-exceeded');

const first = await validate(casePath('cases/local-ref-invalid/root.yaml'));
const second = await validate(casePath('cases/local-ref-invalid/root.yaml'));
assert.deepEqual(first, second);

const duplicateKey = await validateEntrypoint({
  ...baseOptions,
  repositoryRoot: path.join(adapterCases, 'parse'),
  entrypoint: 'duplicate-key.yaml',
});
assert.equal(duplicateKey.outcome, 'parse-error');
assert.equal(duplicateKey.diagnostics[0].code, 'parse.duplicate-key');
assert.equal(duplicateKey.diagnostics[0].line, 5);
assert.equal(duplicateKey.diagnostics[0].column, 3);

const malformedJson = await validateEntrypoint({
  ...baseOptions,
  repositoryRoot: path.join(adapterCases, 'parse'),
  entrypoint: 'malformed.json',
});
assert.equal(malformedJson.outcome, 'parse-error');
assert.equal(malformedJson.diagnostics[0].code, 'parse.invalid-json');
assert.equal(malformedJson.diagnostics[0].line, 5);
assert.equal(malformedJson.diagnostics[0].column, 16);

await withTemporaryRepository('proof-redocly-invalid-utf8-', async (root) => {
  await fs.writeFile(
    path.join(root, 'root.json'),
    Buffer.concat([
      Buffer.from('{"openapi":"3.1.0","info":'),
      Buffer.from([0xff]),
      Buffer.from('}\n'),
    ]),
  );
  const result = await validateEntrypoint({
    ...baseOptions,
    repositoryRoot: root,
    entrypoint: 'root.json',
  });
  assert.equal(result.outcome, 'parse-error');
  assert.equal(result.diagnostics[0].code, 'parse.invalid-utf8');
  assert.equal(result.diagnostics[0].source, 'root.json');
  assert.equal(result.diagnostics[0].line, 1);
  assert.equal(result.diagnostics[0].column, 1);
});

const multipleDocuments = await validateEntrypoint({
  ...baseOptions,
  repositoryRoot: path.join(adapterCases, 'strict/multiple-documents'),
  entrypoint: 'root.yaml',
});
assert.equal(multipleDocuments.outcome, 'parse-error');
assert.equal(multipleDocuments.diagnostics[0].code, 'parse.multiple-documents');
assert.equal(multipleDocuments.diagnostics[0].source, 'root.yaml');
assert.equal(multipleDocuments.diagnostics[0].line, 6);
assert.equal(multipleDocuments.diagnostics[0].column, 1);

const cyclicAlias = await validateEntrypoint({
  ...baseOptions,
  repositoryRoot: path.join(adapterCases, 'strict/cyclic-alias'),
  entrypoint: 'root.yaml',
});
assert.equal(cyclicAlias.outcome, 'parse-error');
assert.equal(cyclicAlias.diagnostics[0].code, 'parse.cyclic-alias');
assert.equal(cyclicAlias.diagnostics[0].source, 'root.yaml');
assert.ok(cyclicAlias.diagnostics[0].line > 0);
assert.ok(cyclicAlias.diagnostics[0].column > 0);

const cyclicAliasCli = spawnSync(
  process.execPath,
  [
    path.join(adapterDirectory, 'index.mjs'),
    '--entrypoint',
    'root.yaml',
    '--repository-root',
    path.join(adapterCases, 'strict/cyclic-alias'),
  ],
  { encoding: 'utf8', timeout: 2000 },
);
assert.equal(cyclicAliasCli.error, undefined);
assert.equal(cyclicAliasCli.status, 0, cyclicAliasCli.stderr);
assert.equal(
  JSON.parse(cyclicAliasCli.stdout).diagnostics[0].code,
  'parse.cyclic-alias',
);

await withTemporaryRepository('proof-redocly-acyclic-alias-', async (root) => {
  await fs.writeFile(
    path.join(root, 'root.yaml'),
    [
      'openapi: 3.1.0',
      'info:',
      '  title: Acyclic aliases',
      '  version: 1.0.0',
      'paths: {}',
      'x-shared: &shared',
      '  enabled: true',
      'x-copy: *shared',
      '',
    ].join('\n'),
  );
  const result = await validateEntrypoint({
    ...baseOptions,
    repositoryRoot: root,
    entrypoint: 'root.yaml',
  });
  assert.equal(result.outcome, 'valid');
});

await withTemporaryRepository('proof-redocly-non-regular-', async (root) => {
  await fs.mkdir(path.join(root, 'root.yaml'));
  const result = await validateEntrypoint({
    ...baseOptions,
    repositoryRoot: root,
    entrypoint: 'root.yaml',
  });
  assert.equal(result.outcome, 'invalid');
  assert.equal(result.diagnostics[0].code, 'reference.not-regular-file');
  assert.equal(result.stats.filesRead, 0);
  assert.equal(result.stats.totalBytes, 0);
});

if (process.platform !== 'win32') {
  await withTemporaryRepository('proof-redocly-fifo-', async (root) => {
    const fifoPath = path.join(root, 'root.yaml');
    const mkfifo = spawnSync('mkfifo', [fifoPath], {
      encoding: 'utf8',
      timeout: 2000,
    });
    assert.equal(mkfifo.status, 0, mkfifo.stderr);
    const fifo = spawnSync(
      process.execPath,
      [
        path.join(adapterDirectory, 'index.mjs'),
        '--entrypoint',
        'root.yaml',
        '--repository-root',
        root,
      ],
      { encoding: 'utf8', timeout: 2000 },
    );
    assert.equal(fifo.error, undefined);
    assert.equal(fifo.status, 0, fifo.stderr);
    const result = JSON.parse(fifo.stdout);
    assert.equal(result.outcome, 'invalid');
    assert.equal(result.diagnostics[0].code, 'reference.not-regular-file');
  });
}

await withTemporaryRepository('proof-redocly-reference-work-', async (root) => {
  await fs.writeFile(
    path.join(root, 'root.yaml'),
    [
      'openapi: 3.1.0',
      'info:',
      '  title: Bounded missing references',
      '  version: 1.0.0',
      'paths: {}',
      'components:',
      '  schemas:',
      '    One:',
      '      $ref: "./missing-1.yaml"',
      '    Two:',
      '      $ref: "./missing-2.yaml"',
      '    Three:',
      '      $ref: "./missing-3.yaml"',
      '',
    ].join('\n'),
  );
  const result = await validateEntrypoint({
    ...baseOptions,
    repositoryRoot: root,
    entrypoint: 'root.yaml',
    maxFiles: 2,
  });
  assert.equal(result.outcome, 'limit-exceeded');
  assert.ok(
    result.diagnostics.some(
      (diagnostic) => diagnostic.code === 'ref.file-count-exceeded',
    ),
  );
  assert.equal(result.stats.filesAttempted, 2);
});

const pathEscape = await validateEntrypoint({
  ...baseOptions,
  repositoryRoot: path.join(adapterCases, 'security/path-escape/repository'),
  entrypoint: 'root.yaml',
});
assert.equal(pathEscape.outcome, 'policy-denied');
assert.equal(pathEscape.diagnostics[0].code, 'ref.path-outside-root');
assert.equal(pathEscape.diagnostics[0].pointer.endsWith('/$ref'), true);

const encodedPathEscape = await validateEntrypoint({
  ...baseOptions,
  repositoryRoot: path.join(adapterCases, 'security/path-escape/repository'),
  entrypoint: 'encoded.yaml',
});
assert.equal(encodedPathEscape.outcome, 'policy-denied');
assert.equal(encodedPathEscape.diagnostics[0].code, 'ref.path-outside-root');
assert.equal(encodedPathEscape.diagnostics[0].line, 14);
assert.equal(encodedPathEscape.diagnostics[0].column, 17);

const recursiveCycle = await validateEntrypoint({
  ...baseOptions,
  repositoryRoot: path.join(adapterCases, 'cycles'),
  entrypoint: 'root.json',
});
assert.equal(recursiveCycle.outcome, 'valid');
assert.equal(recursiveCycle.stats.filesLoaded, 3);
assert.equal(recursiveCycle.stats.maxDepthObserved, 2);

const deterministic = await validateEntrypoint({
  ...baseOptions,
  repositoryRoot: path.join(adapterCases, 'determinism'),
  entrypoint: 'root.yaml',
});
assert.deepEqual(
  deterministic.diagnostics.map(({ source, line, column, pointer, code }) => ({
    source,
    line,
    column,
    pointer,
    code,
  })),
  [
    { source: 'a.yaml', line: 1, column: 1, pointer: '/type', code: 'oas.schema' },
    { source: 'z.yaml', line: 1, column: 1, pointer: '/type', code: 'oas.schema' },
  ],
);

// This records a candidate limitation: Redocly's struct rule stops after the
// first invalid sibling Responses value in this fixture.
const diagnosticFlood = await validateEntrypoint({
  ...baseOptions,
  repositoryRoot: path.join(adapterCases, 'diagnostics'),
  entrypoint: 'flood.yaml',
  maxDiagnostics: 5,
});
assert.equal(diagnosticFlood.outcome, 'invalid');
assert.equal(diagnosticFlood.stats.diagnosticsRaw, 1);

const rootDocument = casePath('cases/oas30-valid.yaml');
const classify = (ref) =>
  classifyReference({ base: rootDocument, ref, repositoryRoot });
assert.equal(classify('https://example.com/openapi.yaml').code, 'ref.scheme-denied');
assert.equal(classify('file:///tmp/openapi.yaml').code, 'ref.scheme-denied');
assert.equal(classify('//example.com/openapi.yaml').code, 'ref.scheme-denied');
assert.equal(classify('\\\\server\\share\\openapi.yaml').code, 'ref.scheme-denied');
assert.equal(classify('C:\\outside\\openapi.yaml').code, 'ref.scheme-denied');
assert.equal(classify('data:text/plain,openapi').code, 'ref.scheme-denied');
assert.equal(classify('../../../../../outside.yaml').code, 'ref.path-outside-root');
assert.equal(classify('%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/outside.yaml').code, 'ref.path-outside-root');
assert.equal(classify('./openapi.yaml?raw=1').code, 'ref.scheme-denied');
assert.equal(classify('./openapi%ZZ.yaml').code, 'ref.scheme-denied');
assert.ok(classify('./oas31-valid.json').candidate);

const cli = spawnSync(
  process.execPath,
  [
    path.join(adapterDirectory, 'index.mjs'),
    '--entrypoint',
    'spikes/openapi-validator/corpus/cases/oas31-valid.json',
    '--repository-root',
    repositoryRoot,
    '--max-entrypoint-bytes',
    '1000000',
    '--max-files',
    '10',
    '--max-total-bytes',
    '1000000',
    '--max-depth',
    '10',
    '--max-diagnostics',
    '10',
  ],
  { encoding: 'utf8' },
);
assert.equal(cli.status, 0, cli.stderr);
assert.equal(cli.stdout.trim().split(/\r?\n/).length, 1);
assert.equal(JSON.parse(cli.stdout).adapter, 'redocly-core');
assert.equal(JSON.parse(cli.stdout).outcome, 'valid');

const badCli = spawnSync(
  process.execPath,
  [path.join(adapterDirectory, 'index.mjs'), '--unknown', 'value'],
  { encoding: 'utf8' },
);
assert.equal(badCli.status, 2);
assert.equal(JSON.parse(badCli.stdout).adapter, 'redocly-core');
assert.equal(JSON.parse(badCli.stdout).diagnostics[0].kind, 'contract');

process.stdout.write('redocly-core adapter tests passed\n');
