"""Non-interactive orchestration for the first local PROOF scan command."""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, TextIO

from proof_core import (
    ConfigurationError,
    InputClosureError,
    NormalizedRun,
    RunAssemblyError,
    ScanConfigurationOverrides,
    assemble_configuration_error_run,
    assemble_input_closure_run,
    assemble_input_error_run,
    build_input_closure,
    load_local_scan_configuration,
    match_specifications,
)
from proof_rulepack import RulePackIdentity

from proof_cli.reporters import ReportFormat, render_report

EXIT_OK = 0
EXIT_BLOCKED = 1
EXIT_INPUT_ERROR = 2
EXIT_INTERNAL_ERROR = 3

_EVALUATION_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_FAIL_ON = ("error", "high", "medium", "low", "none")
_MAX_SELECTION_LABEL = 256


@dataclass(frozen=True, slots=True)
class InvocationSelection:
    """Invocation-only selection labels excluded from normalized result v1."""

    git_ref: str | None = None
    policy_ref: str | None = None

    def __post_init__(self) -> None:
        for value in (self.git_ref, self.policy_ref):
            if value is None:
                continue
            if (
                not value
                or len(value) > _MAX_SELECTION_LABEL
                or any(
                    ord(character) < 0x20 or ord(character) == 0x7F
                    for character in value
                )
            ):
                raise ValueError("selection labels must be bounded printable text")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="specargus",
        description=(
            "Deterministic static analysis for repository OpenAPI files. "
            "PROOF reads but never executes repository content, rejects remote "
            "references, and blocks error/high findings by default."
        ),
    )
    products = parser.add_subparsers(dest="product", required=True)
    proof = products.add_parser(
        "proof",
        help="analyze OpenAPI operations intended for agents or MCP tools",
    )
    commands = proof.add_subparsers(dest="command", required=True)
    scan = commands.add_parser(
        "scan",
        help="scan repository-relative OpenAPI JSON or YAML files",
        description=(
            "Static only: never executes repository content. Remote and file: "
            "references are rejected."
        ),
    )
    scan.add_argument(
        "specifications",
        nargs="*",
        metavar="SPECIFICATION",
        help=(
            "repository-relative path or selector; when supplied, replaces the "
            "configuration specifications list"
        ),
    )
    scan.add_argument(
        "--repository",
        default=".",
        metavar="PATH",
        help="repository root to scan (default: current directory)",
    )
    scan.add_argument(
        "--config",
        default="proof.yaml",
        metavar="PATH",
        help="repository-relative configuration path (default: proof.yaml)",
    )
    scan.add_argument(
        "--output",
        metavar="PATH",
        help=(
            "atomically write the selected report to regular file PATH "
            "instead of standard output"
        ),
    )
    scan.add_argument(
        "--format",
        choices=("json", "console"),
        default="json",
        help="report format (default: json, preserving result-v1 canonical bytes)",
    )
    scan.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="console color mode; presentation-only (default: auto)",
    )
    scan.add_argument(
        "--fail-on",
        choices=_FAIL_ON,
        help="override the blocking severity (default configuration value: high)",
    )
    scan.add_argument("--rule-pack-name", help="override rule-pack artifact name")
    scan.add_argument("--rule-pack-version", help="override rule-pack version")
    scan.add_argument("--rule-pack-digest", help="override exact sha256 identity")
    scan.add_argument(
        "--git-ref",
        help="validated invocation git selection label; excluded from result v1",
    )
    scan.add_argument(
        "--policy-ref",
        help="validated invocation policy selection label; excluded from result v1",
    )
    scan.add_argument(
        "--evaluation-time",
        metavar="UTC",
        help=(
            "canonical UTC whole-second analysis time "
            "(YYYY-MM-DDTHH:MM:SSZ); defaults to invocation start"
        ),
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: BinaryIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run the CLI and return its stable process exit code."""

    parser = _parser()
    arguments = parser.parse_args(argv)
    output = stdout if stdout is not None else sys.stdout.buffer
    errors = stderr if stderr is not None else sys.stderr
    if arguments.command == "scan":
        color = _console_color_enabled(arguments, injected_stdout=stdout)
        return _scan(arguments, output, errors, color=color)
    parser.error("a command is required")
    return EXIT_INPUT_ERROR


def _scan(
    arguments: argparse.Namespace, stdout: BinaryIO, stderr: TextIO, *, color: bool
) -> int:
    evaluation_time = arguments.evaluation_time or _invocation_time()
    if not _valid_evaluation_time(evaluation_time):
        return _usage_failure(
            stderr, "evaluation time must use canonical UTC whole-second form"
        )
    try:
        InvocationSelection(arguments.git_ref, arguments.policy_ref)
        rule_pack = _rule_pack_override(arguments)
    except ValueError:
        return _usage_failure(stderr, "invocation selection inputs are invalid")
    try:
        _reject_input_output_alias(
            root=arguments.repository,
            config_path=arguments.config,
            output_path=arguments.output,
            resource_paths=(),
        )
    except OSError, ValueError:
        stderr.write("PROOF could not safely select the normalized output path.\n")
        return EXIT_INTERNAL_ERROR

    overrides = ScanConfigurationOverrides(
        specifications=(
            tuple(arguments.specifications) if arguments.specifications else None
        ),
        rule_pack=rule_pack,
        fail_on=arguments.fail_on,
    )
    root = arguments.repository
    try:
        configuration = load_local_scan_configuration(
            root,
            arguments.config,
            overrides=overrides,
        )
    except ConfigurationError as error:
        run = assemble_configuration_error_run(
            evaluation_time=evaluation_time,
            error=error,
        )
        return _finish(
            run, arguments.output, arguments.format, stdout, stderr, color=color
        )

    try:
        entrypoints = match_specifications(root, configuration)
    except ConfigurationError as error:
        run = assemble_configuration_error_run(
            evaluation_time=evaluation_time,
            error=error,
        )
        return _finish(
            run, arguments.output, arguments.format, stdout, stderr, color=color
        )

    try:
        closure = build_input_closure(root, entrypoints)
    except InputClosureError as error:
        run = assemble_input_error_run(
            evaluation_time=evaluation_time,
            error=error,
            configuration=configuration,
        )
        return _finish(
            run, arguments.output, arguments.format, stdout, stderr, color=color
        )

    try:
        _reject_input_output_alias(
            root=root,
            config_path=arguments.config,
            output_path=arguments.output,
            resource_paths=tuple(item.path for item in closure.resources),
        )
        run = assemble_input_closure_run(
            evaluation_time=evaluation_time,
            configuration=configuration,
            closure=closure,
        )
    except OSError, RunAssemblyError, ValueError:
        stderr.write("PROOF failed internally before producing a normalized result.\n")
        return EXIT_INTERNAL_ERROR
    return _finish(run, arguments.output, arguments.format, stdout, stderr, color=color)


def _rule_pack_override(arguments: argparse.Namespace) -> RulePackIdentity | None:
    values = (
        arguments.rule_pack_name,
        arguments.rule_pack_version,
        arguments.rule_pack_digest,
    )
    if not any(value is not None for value in values):
        return None
    if not all(isinstance(value, str) and value for value in values):
        raise ValueError("all rule-pack identity fields are required")
    assert all(isinstance(value, str) for value in values)
    if not _DIGEST.fullmatch(values[2]):
        raise ValueError("rule-pack digest is invalid")
    return RulePackIdentity(values[0], values[1], values[2])


def _valid_evaluation_time(value: str) -> bool:
    if not _EVALUATION_TIME.fullmatch(value):
        return False
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return False
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ") == value


def _invocation_time() -> str:
    return datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _reject_input_output_alias(
    *,
    root: str,
    config_path: str,
    output_path: str | None,
    resource_paths: tuple[str, ...],
) -> None:
    if output_path is None:
        return
    repository = Path(root).resolve(strict=False)
    output = Path(output_path).resolve(strict=False)
    protected = {
        repository.joinpath(*path.split("/")).resolve(strict=False)
        for path in (config_path, *resource_paths)
    }
    if any(_paths_alias(output, path) for path in protected):
        raise ValueError("output path aliases an analysis input")


def _paths_alias(left: Path, right: Path) -> bool:
    try:
        return os.path.samefile(left, right)
    except FileNotFoundError:
        return os.path.normcase(os.path.abspath(left)) == os.path.normcase(
            os.path.abspath(right)
        )


def _finish(
    run: NormalizedRun,
    output_path: str | None,
    report_format: ReportFormat,
    stdout: BinaryIO,
    stderr: TextIO,
    *,
    color: bool,
) -> int:
    try:
        payload = render_report(run, report_format, color=color)
        if output_path is None:
            stdout.write(payload)
            stdout.flush()
        else:
            _write_atomically(Path(output_path), payload)
    except Exception:
        stderr.write("PROOF could not write the normalized result.\n")
        return EXIT_INTERNAL_ERROR
    return _exit_code(run)


def _write_atomically(output_path: Path, payload: bytes) -> None:
    """Atomically replace a regular output after fully writing its temporary."""

    temporary: Path | None = None
    try:
        mode = _output_file_mode(output_path)
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            delete=False,
        ) as output:
            temporary = Path(output.name)
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, output_path)
        temporary = None
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def _output_file_mode(output_path: Path) -> int:
    try:
        metadata = output_path.lstat()
    except FileNotFoundError:
        current_umask = os.umask(0)
        os.umask(current_umask)
        return 0o666 & ~current_umask
    if not stat.S_ISREG(metadata.st_mode):
        raise OSError("output target must be a regular file")
    return stat.S_IMODE(metadata.st_mode)


def _console_color_enabled(
    arguments: argparse.Namespace, *, injected_stdout: BinaryIO | None
) -> bool:
    if arguments.format != "console" or arguments.color == "never":
        return False
    if arguments.color == "always":
        if arguments.output is None and injected_stdout is None and sys.stdout.isatty():
            return _enable_windows_virtual_terminal()
        return True
    if (
        arguments.output is not None
        or injected_stdout is not None
        or not sys.stdout.isatty()
        or "NO_COLOR" in os.environ
        or os.environ.get("TERM", "").lower() == "dumb"
    ):
        return False
    return _enable_windows_virtual_terminal()


def _enable_windows_virtual_terminal() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetStdHandle.argtypes = [wintypes.DWORD]
        kernel32.GetStdHandle.restype = wintypes.HANDLE
        kernel32.GetConsoleMode.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.GetConsoleMode.restype = wintypes.BOOL
        kernel32.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel32.SetConsoleMode.restype = wintypes.BOOL
        handle = kernel32.GetStdHandle(0xFFFFFFF5)
        mode = wintypes.DWORD()
        invalid_handle = ctypes.c_void_p(-1).value
        if handle in (None, invalid_handle) or not kernel32.GetConsoleMode(
            handle, ctypes.byref(mode)
        ):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except AttributeError, OSError, ValueError:
        return False


def _exit_code(run: NormalizedRun) -> int:
    if run.status == "input-error":
        return EXIT_INPUT_ERROR
    if run.status == "internal-error":
        return EXIT_INTERNAL_ERROR
    if run.gate.outcome == "blocked":
        return EXIT_BLOCKED
    return EXIT_OK


def _usage_failure(stderr: TextIO, message: str) -> int:
    stderr.write(f"specargus proof: {message}.\n")
    return EXIT_INPUT_ERROR
