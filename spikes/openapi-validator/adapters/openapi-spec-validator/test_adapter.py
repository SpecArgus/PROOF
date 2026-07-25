#!/usr/bin/env python3
"""Focused contract and hardening tests for the Python adapter."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.metadata import version
from pathlib import Path
from typing import Any


ADAPTER_ROOT = Path(__file__).resolve().parent
SPIKE_ROOT = ADAPTER_ROOT.parents[1]
CORPUS_ROOT = SPIKE_ROOT / "corpus" / "adapter-cases"
sys.path.insert(0, str(ADAPTER_ROOT))

import adapter  # noqa: E402


def configured_limits(**overrides: int) -> adapter.Limits:
    values = {
        "max_entrypoint_bytes": adapter.DEFAULT_MAX_ENTRYPOINT_BYTES,
        "max_files": adapter.DEFAULT_MAX_FILES,
        "max_total_bytes": adapter.DEFAULT_MAX_TOTAL_BYTES,
        "max_depth": adapter.DEFAULT_MAX_DEPTH,
        "max_diagnostics": adapter.DEFAULT_MAX_DIAGNOSTICS,
    }
    values.update(overrides)
    return adapter.Limits(**values)


def validate(
    repository_root: Path,
    entrypoint: str,
    **limit_overrides: int,
) -> dict[str, Any]:
    return adapter.validate_entrypoint(
        adapter.Options(
            entrypoint=entrypoint,
            repository_root=str(repository_root),
            limits=configured_limits(**limit_overrides),
        )
    )


class CountingHandler(BaseHTTPRequestHandler):
    requests_seen = 0

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        type(self).requests_seen += 1
        body = b'{"type":"object"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *args: object) -> None:
        del args


class AdapterTests(unittest.TestCase):
    maxDiff = None

    def assert_finding(
        self,
        result: dict[str, Any],
        *,
        outcome: str,
        code: str,
        source: str | None = None,
        line: int | None = None,
        column: int | None = None,
        pointer: str | None = None,
    ) -> dict[str, Any]:
        self.assertEqual(result["adapter"], "openapi-spec-validator")
        self.assertEqual(result["outcome"], outcome)
        self.assertEqual(len(result["diagnostics"]), 1)
        finding = result["diagnostics"][0]
        self.assertEqual(finding["code"], code)
        if source is not None:
            self.assertEqual(finding["source"], source)
        if line is not None:
            self.assertEqual(finding["line"], line)
        if column is not None:
            self.assertEqual(finding["column"], column)
        if pointer is not None:
            self.assertEqual(finding["pointer"], pointer)
        return finding

    def test_locked_validator_version(self) -> None:
        self.assertEqual(version("openapi-spec-validator"), "0.9.0")
        lock = (ADAPTER_ROOT / "requirements.lock").read_text(encoding="utf-8")
        self.assertIn("openapi-spec-validator==0.9.0", lock)
        self.assertIn("Windows x86-64", lock)
        self.assertIn("Linux x86-64", lock)
        self.assertIn("macOS 11 or newer on arm64", lock)

    def test_oas30_and_oas31_local_references(self) -> None:
        cases = (
            ("baseline/oas30-local", "root.yaml"),
            ("baseline/oas31-local", "root.json"),
        )
        for relative_root, entrypoint in cases:
            with self.subTest(entrypoint=entrypoint):
                result = validate(CORPUS_ROOT / relative_root, entrypoint)
                self.assertEqual(result["outcome"], "valid")
                self.assertEqual(result["diagnostics"], [])
                self.assertEqual(result["stats"]["filesRead"], 2)

    def test_strict_committed_parse_cases(self) -> None:
        cases = (
            (
                "parse",
                "duplicate-key.yaml",
                "parse.duplicate-key",
                "duplicate-key.yaml",
                5,
                3,
            ),
            (
                "parse",
                "malformed.json",
                "parse.invalid-json",
                "malformed.json",
                5,
                16,
            ),
            (
                "strict/multiple-documents",
                "root.yaml",
                "parse.multiple-documents",
                "root.yaml",
                None,
                None,
            ),
            (
                "strict/cyclic-alias",
                "root.yaml",
                "parse.cyclic-alias",
                "root.yaml",
                None,
                None,
            ),
        )
        for relative_root, entrypoint, code, source, line, column in cases:
            with self.subTest(code=code):
                result = validate(CORPUS_ROOT / relative_root, entrypoint)
                self.assert_finding(
                    result,
                    outcome="parse-error",
                    code=code,
                    source=source,
                    line=line,
                    column=column,
                )

    def test_invalid_utf8_and_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "invalid.json").write_bytes(
                b'{"openapi":"3.1.0","info":{"title":"\xff"}}'
            )
            (root / "duplicate.json").write_text(
                (
                    '{"openapi":"3.1.0","info":{"title":"one"},'
                    '"info":{"title":"two"},"paths":{}}'
                ),
                encoding="utf-8",
            )

            invalid_utf8 = validate(root, "invalid.json")
            self.assert_finding(
                invalid_utf8,
                outcome="parse-error",
                code="parse.invalid-utf8",
                source="invalid.json",
                line=1,
            )

            duplicate = validate(root, "duplicate.json")
            self.assert_finding(
                duplicate,
                outcome="parse-error",
                code="parse.duplicate-key",
                source="duplicate.json",
            )

    def test_root_confinement_and_scheme_policy(self) -> None:
        pointer = (
            "/paths/~1pets/get/responses/200/content/"
            "application~1json/schema/$ref"
        )
        path_root = CORPUS_ROOT / "security" / "path-escape" / "repository"
        cases = (
            (
                path_root,
                "root.yaml",
                "ref.path-outside-root",
                "root.yaml",
            ),
            (
                path_root,
                "encoded.yaml",
                "ref.path-outside-root",
                "encoded.yaml",
            ),
            (
                CORPUS_ROOT / "security" / "file-uri" / "repository",
                "root.yaml",
                "ref.scheme-denied",
                "root.yaml",
            ),
        )
        for root, entrypoint, code, source in cases:
            with self.subTest(entrypoint=entrypoint, code=code):
                result = validate(root, entrypoint)
                self.assert_finding(
                    result,
                    outcome="policy-denied",
                    code=code,
                    source=source,
                    line=14,
                    column=17,
                    pointer=pointer,
                )

    def test_transitive_remote_reference_never_reaches_canary(self) -> None:
        source = CORPUS_ROOT / "security" / "transitive-remote"
        CountingHandler.requests_seen = 0
        server = ThreadingHTTPServer(("127.0.0.1", 0), CountingHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                materialized = Path(temporary) / "case"
                shutil.copytree(source, materialized)
                repository = materialized / "repository"
                template = repository / "components.template.yaml"
                contents = template.read_text(encoding="utf-8").replace(
                    "{{REMOTE_REF_URL}}",
                    f"http://127.0.0.1:{server.server_port}/schema.json",
                )
                (repository / "components.yaml").write_text(
                    contents,
                    encoding="utf-8",
                    newline="\n",
                )
                result = validate(repository, "root.yaml")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assert_finding(
            result,
            outcome="policy-denied",
            code="ref.scheme-denied",
            source="components.yaml",
            line=4,
            column=7,
            pointer="/components/schemas/RemotePet/$ref",
        )
        self.assertEqual(result["stats"]["filesRead"], 2)
        self.assertEqual(CountingHandler.requests_seen, 0)

    def test_reference_closure_limits_are_inclusive(self) -> None:
        within_depth = validate(
            CORPUS_ROOT / "depth" / "within-limit",
            "root.yaml",
            max_depth=3,
        )
        self.assertEqual(within_depth["outcome"], "valid")
        self.assertEqual(within_depth["stats"]["maximumDepthObserved"], 3)

        over_depth = validate(
            CORPUS_ROOT / "depth" / "over-limit",
            "root.yaml",
            max_depth=3,
        )
        self.assert_finding(
            over_depth,
            outcome="limit-exceeded",
            code="ref.depth-exceeded",
            source="level-3.yaml",
            line=1,
            column=1,
            pointer="/$ref",
        )
        self.assertEqual(over_depth["stats"]["filesRead"], 4)

        closure_root = CORPUS_ROOT / "limits" / "reference-closure"
        at_files = validate(closure_root, "root.yaml", max_files=4)
        self.assertEqual(at_files["outcome"], "valid")
        self.assertEqual(at_files["stats"]["filesRead"], 4)

        over_files = validate(closure_root, "root.yaml", max_files=3)
        self.assert_finding(
            over_files,
            outcome="limit-exceeded",
            code="ref.file-count-exceeded",
            source="two.yaml",
            line=1,
            column=1,
            pointer="/$ref",
        )
        self.assertEqual(over_files["stats"]["filesRead"], 3)

        at_bytes = validate(closure_root, "root.yaml", max_total_bytes=379)
        self.assertEqual(at_bytes["outcome"], "valid")
        self.assertEqual(at_bytes["stats"]["aggregateBytesRead"], 379)

        over_bytes = validate(closure_root, "root.yaml", max_total_bytes=378)
        self.assert_finding(
            over_bytes,
            outcome="limit-exceeded",
            code="ref.aggregate-bytes-exceeded",
            source="two.yaml",
            line=1,
            column=1,
            pointer="/$ref",
        )
        self.assertEqual(over_bytes["stats"]["aggregateBytesRead"], 308)

    def test_entrypoint_byte_limit_is_inclusive(self) -> None:
        root = CORPUS_ROOT / "baseline" / "oas30-local"
        size = (root / "root.yaml").stat().st_size
        at_limit = validate(root, "root.yaml", max_entrypoint_bytes=size)
        self.assertEqual(at_limit["outcome"], "valid")

        over_limit = validate(root, "root.yaml", max_entrypoint_bytes=size - 1)
        self.assert_finding(
            over_limit,
            outcome="limit-exceeded",
            code="input.entrypoint-bytes-exceeded",
            source="root.yaml",
        )
        self.assertEqual(over_limit["stats"]["filesRead"], 0)
        self.assertEqual(over_limit["stats"]["aggregateBytesRead"], 0)

    def test_recursive_cycle_terminates(self) -> None:
        result = validate(CORPUS_ROOT / "cycles", "root.json")
        self.assertEqual(result["outcome"], "valid")
        self.assertEqual(result["stats"]["filesRead"], 3)
        self.assertEqual(result["stats"]["maximumDepthObserved"], 2)

    def test_defining_file_diagnostics_are_deterministic(self) -> None:
        source = CORPUS_ROOT / "determinism"
        serializations: list[str] = []
        for _ in range(3):
            with tempfile.TemporaryDirectory() as temporary:
                materialized = Path(temporary) / "case"
                shutil.copytree(source, materialized)
                result = validate(materialized, "root.yaml")
                serializations.append(
                    json.dumps(result, sort_keys=True, separators=(",", ":"))
                )

        self.assertEqual(len(set(serializations)), 1)
        self.assertEqual(result["outcome"], "invalid")
        self.assertEqual(
            [
                (
                    finding["source"],
                    finding["line"],
                    finding["column"],
                    finding["pointer"],
                )
                for finding in result["diagnostics"]
            ],
            [
                ("a.yaml", 1, 1, "/type"),
                ("z.yaml", 1, 1, "/type"),
            ],
        )

    def test_diagnostic_limit_reports_exact_integer_truncation(self) -> None:
        result = validate(
            CORPUS_ROOT / "diagnostics",
            "flood.yaml",
            max_diagnostics=5,
        )
        self.assertEqual(result["outcome"], "limit-exceeded")
        self.assertEqual(len(result["diagnostics"]), 5)
        self.assertEqual(
            [finding["pointer"] for finding in result["diagnostics"]],
            [
                "/paths/~1p11/get/responses",
                "/paths/~1p10/get/responses",
                "/paths/~1p09/get/responses",
                "/paths/~1p08/get/responses",
                "/paths/~1p07/get/responses",
            ],
        )
        stats = result["stats"]
        self.assertEqual(stats["diagnosticsRaw"], 12)
        self.assertEqual(stats["diagnosticsEmitted"], 5)
        self.assertIs(type(stats["diagnosticsTruncated"]), int)
        self.assertEqual(stats["diagnosticsTruncated"], 7)
        self.assertEqual(stats["limitCode"], "diagnostics.limit-exceeded")

    def test_closed_handler_claims_every_scheme_without_fallback(self) -> None:
        handlers = adapter.ClosedMemoryHandlers({})
        for scheme in ("", "file", "http", "https", "unknown"):
            self.assertIn(scheme, handlers)
            with self.assertRaises(adapter.NoSuchResource):
                handlers[scheme](f"{scheme}://not-allowed.invalid/schema")

    def test_cli_emits_one_json_line_and_contract_errors_exit_two(self) -> None:
        command = [
            sys.executable,
            str(ADAPTER_ROOT / "adapter.py"),
            "--entrypoint",
            "root.yaml",
            "--repository-root",
            str(CORPUS_ROOT / "baseline" / "oas30-local"),
        ]
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(len(completed.stdout.splitlines()), 1)
        self.assertEqual(json.loads(completed.stdout)["outcome"], "valid")

        failed = subprocess.run(
            [sys.executable, str(ADAPTER_ROOT / "adapter.py"), "--unknown", "1"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(failed.returncode, 2)
        self.assertEqual(len(failed.stdout.splitlines()), 1)
        self.assertEqual(
            json.loads(failed.stdout)["diagnostics"][0]["code"],
            "adapter-contract-error",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
