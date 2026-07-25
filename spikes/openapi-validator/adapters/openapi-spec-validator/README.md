# openapi-spec-validator adapter

This directory contains the direct `openapi-spec-validator` candidate for the
PROOF validator experiment. It is an isolated prototype, not a production
integration.

The adapter output ID is `openapi-spec-validator`. The dependency version under
evaluation is exactly `openapi-spec-validator==0.9.0`.

## Supported experiment environments

`requirements.lock` is a single hash-locked CPython 3.14 wheel set for:

- Windows x86-64
- Linux x86-64 with glibc 2.17 or newer
- macOS 11 or newer on arm64

Pure-Python artifacts have one reviewed hash. Each compiled dependency has one
reviewed wheel hash per supported platform. Pip selects the compatible wheel
and fails closed for an unlisted wheel, platform, interpreter, or hash.

From the repository root, create the ignored experiment environment and install
the lock.

PowerShell:

```powershell
$venv = "spikes/openapi-validator/.cache/openapi-spec-validator-venv-cp314"
py -3.14 -m venv $venv
& "$venv/Scripts/python.exe" -m pip install --require-hashes `
  -r "spikes/openapi-validator/adapters/openapi-spec-validator/requirements.lock"
```

Bash:

```bash
venv="spikes/openapi-validator/.cache/openapi-spec-validator-venv-cp314"
python3.14 -m venv "$venv"
"$venv/bin/python" -m pip install --require-hashes \
  -r spikes/openapi-validator/adapters/openapi-spec-validator/requirements.lock
```

## Invocation

The execution entrypoint is `adapter.py`. It writes exactly one JSON object and
a trailing newline to standard output.

PowerShell example:

```powershell
$python = "spikes/openapi-validator/.cache/openapi-spec-validator-venv-cp314/Scripts/python.exe"
& $python "spikes/openapi-validator/adapters/openapi-spec-validator/adapter.py" `
  --entrypoint "root.yaml" `
  --repository-root "C:/absolute/path/to/materialized/repository" `
  --max-entrypoint-bytes 1048576 `
  --max-files 64 `
  --max-total-bytes 8388608 `
  --max-depth 16 `
  --max-diagnostics 100
```

The five limit options are optional. `--entrypoint` and `--repository-root` are
required. A valid invocation exits zero even when the document result is
`invalid`, `parse-error`, `policy-denied`, or `limit-exceeded`. A malformed CLI
contract or unexpected internal failure exits two and still emits one contract
object.

## Security boundary

The adapter does not pass the validator library a filesystem or network
resolver.

1. A strict UTF-8 parser rejects malformed JSON, duplicate JSON/YAML keys,
   multiple YAML documents, non-JSON YAML values, and recursive aliases.
2. A preflight walk builds the full transitive local `$ref` closure. It resolves
   references relative to their defining file, requires lexical and canonical
   containment under `repositoryRoot`, opens regular files through bounded file
   descriptors, and charges distinct canonical files once.
3. Only parsed documents from that closure are exposed through an immutable
   in-memory URI allowlist. The handler mapping deliberately claims every URI
   scheme, so `jsonschema-path` cannot fall back to Requests or `urllib`.
4. File count, entrypoint bytes, aggregate bytes, external-reference depth, and
   diagnostic observation/output are bounded.
5. Findings are normalized to repository-relative sources, one-based
   coordinates, RFC 6901 pointers, stable codes, deterministic global ordering,
   and deterministic deduplication.

`openapi-spec-validator` 0.9.0 completes its meta-schema pass before its
semantic pass. Its semantic pass can raise `KeyError` for some already-invalid
structures, such as a non-object Responses value. The adapter retains the
complete structural findings already yielded in that specific situation.
Exceptions raised before any finding remain visible as internal failures.

## Tests

Run the focused tests from the repository root:

PowerShell:

```powershell
spikes/openapi-validator/.cache/openapi-spec-validator-venv-cp314/Scripts/python.exe `
  spikes/openapi-validator/adapters/openapi-spec-validator/test_adapter.py
```

Bash:

```bash
spikes/openapi-validator/.cache/openapi-spec-validator-venv-cp314/bin/python \
  spikes/openapi-validator/adapters/openapi-spec-validator/test_adapter.py
```

The tests cover OpenAPI 3.0 and 3.1 local references, strict parsing, root
confinement, a zero-request loopback canary, inclusive closure limits, recursive
reference termination, relocated deterministic diagnostics, exact integer
diagnostic truncation, the deny-by-default resolver, and the CLI contract.

The committed lock was additionally verified with `pip download
--require-hashes` while targeting CPython 3.14 `win_amd64`,
`manylinux_2_17_x86_64`, and `macosx_11_0_arm64`. A native Windows installation
from the same lock was used for the test run.

## Prototype limits

- Only OpenAPI 3.0 and 3.1 are accepted by this experiment.
- The process timeout, CPU cap, and operating-system sandbox remain the
  responsibility of the common harness or production worker.
- The hash lock intentionally supports only the three experiment targets listed
  above. Adding another platform requires downloading, reviewing, and adding
  its compiled wheel hashes.
- This adapter is evidence for candidate selection. Unselected adapter code and
  its evaluation evidence should remain on the experiment-preservation branch,
  not in the production `develop` merge.
