#!/usr/bin/env python3
"""Security-bounded openapi-spec-validator adapter prototype.

The validator never receives filesystem or network resolver handlers. A strict
preflight builds the complete, repository-confined local reference closure and
exposes only that immutable in-memory allowlist to jsonschema-path.
"""

from __future__ import annotations

import json
import math
import os
import re
import stat
import sys
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Any
from urllib.parse import unquote_to_bytes, urldefrag, urlsplit

# Do not let an optional jsonschema-rs installation change diagnostics.
os.environ["OPENAPI_SPEC_VALIDATOR_SCHEMA_VALIDATOR_BACKEND"] = "jsonschema"

import yaml
from jsonschema.exceptions import ValidationError
from jsonschema_path import SchemaPath
from jsonschema_path.loaders import JsonschemaSafeLoader
from referencing.exceptions import NoSuchResource
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from openapi_spec_validator import OpenAPIV30SpecValidator
from openapi_spec_validator import OpenAPIV31SpecValidator


ADAPTER_NAME = "openapi-spec-validator"
SCHEMA_VERSION = 1
DEFAULT_MAX_ENTRYPOINT_BYTES = 1024 * 1024
DEFAULT_MAX_FILES = 100
DEFAULT_MAX_TOTAL_BYTES = 20 * 1024 * 1024
DEFAULT_MAX_DEPTH = 32
DEFAULT_MAX_DIAGNOSTICS = 100

# SpecValidator.iter_errors() is backed by a CachedIterable. Limiting iterator
# consumption is therefore necessary in addition to limiting emitted output.
MAX_OBSERVED_DIAGNOSTICS = 2048
READ_CHUNK_BYTES = 64 * 1024
REQUIRED_PROPERTY_RE = re.compile(r"^'(?P<name>.*)' is a required property$")


class ContractError(Exception):
    """Invalid CLI contract or unusable adapter configuration."""


@dataclass(frozen=True)
class Limits:
    max_entrypoint_bytes: int = DEFAULT_MAX_ENTRYPOINT_BYTES
    max_files: int = DEFAULT_MAX_FILES
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    max_depth: int = DEFAULT_MAX_DEPTH
    max_diagnostics: int = DEFAULT_MAX_DIAGNOSTICS

    def as_json(self) -> dict[str, int]:
        return {
            "maxEntrypointBytes": self.max_entrypoint_bytes,
            "maxFiles": self.max_files,
            "maxTotalBytes": self.max_total_bytes,
            "maxDepth": self.max_depth,
            "maxDiagnostics": self.max_diagnostics,
        }


@dataclass(frozen=True)
class Options:
    entrypoint: str
    repository_root: str
    limits: Limits


@dataclass(frozen=True)
class Origin:
    source: str
    line: int
    column: int
    pointer: str


@dataclass(frozen=True)
class Diagnostic:
    source: str | None
    line: int | None
    column: int | None
    pointer: str | None
    code: str
    severity: str
    kind: str
    message: str

    def as_json(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "line": self.line,
            "column": self.column,
            "pointer": self.pointer,
            "code": self.code,
            "severity": self.severity,
            "kind": self.kind,
            "message": self.message,
        }


class ControlledError(Exception):
    """A deterministic parse, policy, reference, or limit result."""

    def __init__(
        self,
        *,
        outcome: str,
        code: str,
        kind: str,
        message: str,
        origin: Origin | None,
    ) -> None:
        super().__init__(message)
        self.outcome = outcome
        self.code = code
        self.kind = kind
        self.stable_message = message
        self.origin = origin

    def diagnostic(self) -> Diagnostic:
        return Diagnostic(
            source=self.origin.source if self.origin else None,
            line=self.origin.line if self.origin else None,
            column=self.origin.column if self.origin else None,
            pointer=self.origin.pointer if self.origin else None,
            code=self.code,
            severity="error",
            kind=self.kind,
            message=self.stable_message,
        )


class LocatedDict(dict[str, Any]):
    def __init__(self, origin: Origin) -> None:
        super().__init__()
        self.origin = origin


class LocatedList(list[Any]):
    def __init__(self, origin: Origin) -> None:
        super().__init__()
        self.origin = origin


class LocatedString(str):
    def __new__(cls, value: str, origin: Origin) -> "LocatedString":
        result = str.__new__(cls, value)
        result.origin = origin
        return result


class LocatedInteger(int):
    def __new__(cls, value: int, origin: Origin) -> "LocatedInteger":
        result = int.__new__(cls, value)
        result.origin = origin
        return result


class LocatedFloat(float):
    def __new__(cls, value: float, origin: Origin) -> "LocatedFloat":
        result = float.__new__(cls, value)
        result.origin = origin
        return result


@dataclass
class Document:
    logical_path: Path
    real_path: Path
    source: str
    body: bytes
    root: LocatedDict
    origins: dict[str, Origin] = field(default_factory=dict)
    values: dict[str, Any] = field(default_factory=dict)
    aliases: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class ReferenceSite:
    document: Document
    ref: str
    origin: Origin


def escape_pointer_segment(value: object) -> str:
    return str(value).replace("~", "~0").replace("/", "~1")


def append_pointer(pointer: str, segment: object) -> str:
    return f"{pointer}/{escape_pointer_segment(segment)}"


def pointer_from_parts(parts: Any) -> str:
    pointer = ""
    try:
        for part in parts:
            pointer = append_pointer(pointer, part)
    except TypeError:
        return ""
    return pointer


def path_is_within(root: Path, target: Path) -> bool:
    try:
        target.relative_to(root)
    except ValueError:
        return False
    return True


def posix_relative(root: Path, target: Path) -> str:
    return target.relative_to(root).as_posix()


def stable_message(message: object, repository_root: Path) -> str:
    normalized = str(message).replace("\r", " ").replace("\n", " ")
    candidates = {
        str(repository_root),
        str(repository_root).replace("\\", "/"),
    }
    normalized = normalized.replace("\\", "/")
    for candidate in candidates:
        normalized = normalized.replace(candidate.replace("\\", "/"), "<repository>")
    return " ".join(normalized.split())


def mark_origin(source: str, pointer: str, mark: Any) -> Origin:
    return Origin(
        source=source,
        line=int(getattr(mark, "line", 0)) + 1,
        column=int(getattr(mark, "column", 0)) + 1,
        pointer=pointer,
    )


def utf8_error_origin(source: str, body: bytes, error: UnicodeDecodeError) -> Origin:
    prefix = body[: error.start].decode("utf-8", errors="ignore")
    line = prefix.count("\n") + 1
    column = len(prefix.rsplit("\n", 1)[-1]) + 1
    return Origin(source=source, line=line, column=column, pointer="")


def parse_scalar(
    loader: JsonschemaSafeLoader,
    node: ScalarNode,
    origin: Origin,
) -> Any:
    try:
        value = loader.construct_object(node, deep=True)
    except Exception as error:
        raise ControlledError(
            outcome="parse-error",
            code="parse.invalid-yaml",
            kind="parse",
            message="The YAML scalar could not be decoded safely.",
            origin=origin,
        ) from error
    if not isinstance(value, (str, int, float, bool, type(None))):
        raise ControlledError(
            outcome="parse-error",
            code="parse.invalid-yaml",
            kind="parse",
            message="Only JSON-compatible YAML scalar values are supported.",
            origin=origin,
        )
    if isinstance(value, float) and not math.isfinite(value):
        raise ControlledError(
            outcome="parse-error",
            code="parse.invalid-yaml",
            kind="parse",
            message="Non-finite YAML numbers are not supported.",
            origin=origin,
        )
    return value


def normalize_mapping_key(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return str(value)
    raise TypeError("OpenAPI mapping keys must be scalar JSON values.")


def located_scalar(value: Any, origin: Origin) -> Any:
    if isinstance(value, str):
        return LocatedString(value, origin)
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return LocatedInteger(value, origin)
    if isinstance(value, float):
        return LocatedFloat(value, origin)
    return value


def convert_node(
    *,
    node: Node,
    pointer: str,
    source: str,
    document_origins: dict[str, Origin],
    document_values: dict[str, Any],
    loader: JsonschemaSafeLoader,
    visiting: set[int],
    root_origin: Origin | None = None,
) -> Any:
    origin = root_origin or mark_origin(source, pointer, node.start_mark)
    document_origins[pointer] = origin

    node_identity = id(node)
    if node_identity in visiting:
        raise ControlledError(
            outcome="parse-error",
            code="parse.cyclic-alias",
            kind="parse",
            message="Recursive YAML aliases are not supported.",
            origin=origin,
        )

    if isinstance(node, ScalarNode):
        value = located_scalar(parse_scalar(loader, node, origin), origin)
        document_values[pointer] = value
        return value

    visiting.add(node_identity)
    try:
        if isinstance(node, SequenceNode):
            result = LocatedList(origin)
            document_values[pointer] = result
            for index, child in enumerate(node.value):
                child_pointer = append_pointer(pointer, index)
                result.append(
                    convert_node(
                        node=child,
                        pointer=child_pointer,
                        source=source,
                        document_origins=document_origins,
                        document_values=document_values,
                        loader=loader,
                        visiting=visiting,
                    )
                )
            return result

        if isinstance(node, MappingNode):
            result = LocatedDict(origin)
            document_values[pointer] = result
            for key_node, value_node in node.value:
                if not isinstance(key_node, ScalarNode):
                    raise ControlledError(
                        outcome="parse-error",
                        code="parse.invalid-yaml",
                        kind="parse",
                        message="Complex YAML mapping keys are not supported.",
                        origin=mark_origin(source, pointer, key_node.start_mark),
                    )
                try:
                    key_origin = mark_origin(source, pointer, key_node.start_mark)
                    key = normalize_mapping_key(
                        parse_scalar(loader, key_node, key_origin)
                    )
                except TypeError as error:
                    raise ControlledError(
                        outcome="parse-error",
                        code="parse.invalid-yaml",
                        kind="parse",
                        message=str(error),
                        origin=mark_origin(source, pointer, key_node.start_mark),
                    ) from error
                child_pointer = append_pointer(pointer, key)
                key_origin = mark_origin(source, child_pointer, key_node.start_mark)
                if key in result:
                    raise ControlledError(
                        outcome="parse-error",
                        code="parse.duplicate-key",
                        kind="parse",
                        message="Duplicate mapping keys are not allowed.",
                        origin=key_origin,
                    )
                result[key] = convert_node(
                    node=value_node,
                    pointer=child_pointer,
                    source=source,
                    document_origins=document_origins,
                    document_values=document_values,
                    loader=loader,
                    visiting=visiting,
                    root_origin=key_origin,
                )
            return result
    finally:
        visiting.remove(node_identity)

    raise ControlledError(
        outcome="parse-error",
        code="parse.invalid-yaml",
        kind="parse",
        message="Unsupported YAML node type.",
        origin=origin,
    )


def json_syntax_check(text: str, source: str) -> None:
    def invalid_constant(token: str) -> None:
        raise ValueError(token)

    try:
        json.loads(text, parse_constant=invalid_constant)
    except json.JSONDecodeError as error:
        raise ControlledError(
            outcome="parse-error",
            code="parse.invalid-json",
            kind="parse",
            message="The JSON document is not valid strict JSON.",
            origin=Origin(
                source=source,
                line=max(error.lineno, 1),
                column=max(error.colno, 1),
                pointer="",
            ),
        ) from error
    except ValueError as error:
        token = str(error)
        offset = text.find(token)
        prefix = text[: max(offset, 0)]
        raise ControlledError(
            outcome="parse-error",
            code="parse.invalid-json",
            kind="parse",
            message="Non-finite JSON numbers are not allowed.",
            origin=Origin(
                source=source,
                line=prefix.count("\n") + 1,
                column=len(prefix.rsplit("\n", 1)[-1]) + 1,
                pointer="",
            ),
        ) from error


def compose_document(text: str, source: str, is_json: bool) -> tuple[Node, JsonschemaSafeLoader]:
    if is_json:
        json_syntax_check(text, source)
    try:
        nodes = list(yaml.compose_all(text, Loader=JsonschemaSafeLoader))
    except yaml.MarkedYAMLError as error:
        mark = error.problem_mark or error.context_mark
        origin = (
            mark_origin(source, "", mark)
            if mark is not None
            else Origin(source=source, line=1, column=1, pointer="")
        )
        raise ControlledError(
            outcome="parse-error",
            code="parse.invalid-json" if is_json else "parse.invalid-yaml",
            kind="parse",
            message=(
                "The JSON document could not be parsed."
                if is_json
                else "The YAML document could not be parsed."
            ),
            origin=origin,
        ) from error

    if len(nodes) != 1:
        second = nodes[1] if len(nodes) > 1 else None
        if second is not None:
            origin = mark_origin(source, "", second.start_mark)
        else:
            marker_lines = [
                index
                for index, line in enumerate(text.splitlines(), start=1)
                if line.strip() == "---"
            ]
            line = marker_lines[1] if len(marker_lines) > 1 else 1
            origin = Origin(source=source, line=line, column=1, pointer="")
        raise ControlledError(
            outcome="parse-error",
            code="parse.multiple-documents",
            kind="parse",
            message="Exactly one YAML document is allowed.",
            origin=origin,
        )
    if nodes[0] is None:
        raise ControlledError(
            outcome="parse-error",
            code="parse.invalid-json" if is_json else "parse.invalid-yaml",
            kind="parse",
            message="The OpenAPI document must not be empty.",
            origin=Origin(source=source, line=1, column=1, pointer=""),
        )
    return nodes[0], JsonschemaSafeLoader("")


def parse_document(body: bytes, source: str, suffix: str) -> tuple[LocatedDict, dict[str, Origin], dict[str, Any]]:
    try:
        text = body.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ControlledError(
            outcome="parse-error",
            code="parse.invalid-utf8",
            kind="parse",
            message="Input files must contain valid UTF-8.",
            origin=utf8_error_origin(source, body, error),
        ) from error

    is_json = suffix.lower() == ".json"
    node, scalar_loader = compose_document(text, source, is_json)
    origins: dict[str, Origin] = {}
    values: dict[str, Any] = {}
    try:
        root = convert_node(
            node=node,
            pointer="",
            source=source,
            document_origins=origins,
            document_values=values,
            loader=scalar_loader,
            visiting=set(),
        )
    finally:
        scalar_loader.dispose()
    if not isinstance(root, LocatedDict):
        raise ControlledError(
            outcome="parse-error",
            code="parse.invalid-json" if is_json else "parse.invalid-yaml",
            kind="parse",
            message="An OpenAPI document must be a mapping object.",
            origin=origins.get("", Origin(source, 1, 1, "")),
        )
    return root, origins, values


class ClosedMemoryHandlers(Mapping[str, Any]):
    """A deny-by-default handler mapping.

    SchemaRetriever falls back to requests/urllib only when a scheme is absent
    from its mapping. This mapping deliberately claims every scheme and routes
    all lookups through a closed in-memory allowlist.
    """

    def __init__(self, resources: dict[str, Document]) -> None:
        self.resources = resources

    def __contains__(self, _scheme: object) -> bool:
        return True

    def __getitem__(self, _scheme: str) -> Any:
        return self._retrieve

    def __iter__(self) -> Iterator[str]:
        return iter(())

    def __len__(self) -> int:
        return 0

    def _retrieve(self, uri: str) -> LocatedDict:
        resource_uri, _fragment = urldefrag(uri)
        document = self.resources.get(resource_uri)
        if document is None:
            raise NoSuchResource(ref=uri)
        return document.root


class Closure:
    def __init__(self, options: Options) -> None:
        self.options = options
        try:
            self.repository_root = Path(options.repository_root).resolve(strict=True)
        except OSError as error:
            raise ContractError("Repository root is not readable.") from error
        if not self.repository_root.is_dir():
            raise ContractError("Repository root must be a directory.")

        self.documents_by_real: dict[Path, Document] = {}
        self.resources_by_uri: dict[str, Document] = {}
        self.total_bytes = 0
        self.entrypoint_bytes = 0
        self.references_seen = 0
        self.max_depth_observed = 0
        self.limit_code: str | None = None
        self.policy_denials = 0
        self.limit_denials = 0
        self.entrypoint_document: Document | None = None

    @property
    def limits(self) -> Limits:
        return self.options.limits

    def source_for(self, logical_path: Path) -> str:
        return posix_relative(self.repository_root, logical_path)

    def origin_for_path(self, logical_path: Path) -> Origin:
        source = (
            self.source_for(logical_path)
            if path_is_within(self.repository_root, logical_path)
            else ""
        )
        return Origin(source=source, line=1, column=1, pointer="")

    def record_limit(self, code: str) -> None:
        self.limit_denials += 1
        if self.limit_code is None:
            self.limit_code = code

    def controlled_limit(self, code: str, message: str, origin: Origin) -> ControlledError:
        self.record_limit(code)
        return ControlledError(
            outcome="limit-exceeded",
            code=code,
            kind="limit",
            message=message,
            origin=origin,
        )

    def controlled_policy(self, code: str, message: str, origin: Origin) -> ControlledError:
        self.policy_denials += 1
        return ControlledError(
            outcome="policy-denied",
            code=code,
            kind="policy",
            message=message,
            origin=origin,
        )

    def resolve_entrypoint(self) -> tuple[Path, Path]:
        configured = Path(self.options.entrypoint)
        logical = (
            Path(os.path.abspath(configured))
            if configured.is_absolute()
            else Path(os.path.abspath(self.repository_root / configured))
        )
        if not path_is_within(self.repository_root, logical):
            raise self.controlled_policy(
                "ref.path-outside-root",
                "The entrypoint must be inside the repository root.",
                Origin(source="", line=1, column=1, pointer=""),
            )
        try:
            real = logical.resolve(strict=True)
        except OSError as error:
            raise ContractError("Entrypoint is not readable.") from error
        if not path_is_within(self.repository_root, real):
            raise self.controlled_policy(
                "ref.path-outside-root",
                "The entrypoint resolves outside the repository root.",
                self.origin_for_path(logical),
            )
        return logical, real

    def bounded_read(
        self,
        *,
        logical_path: Path,
        real_path: Path,
        origin: Origin,
        is_entrypoint: bool,
    ) -> bytes:
        try:
            before = real_path.stat()
        except OSError as error:
            raise ControlledError(
                outcome="invalid",
                code="ref.unresolved",
                kind="reference",
                message="A referenced file could not be read.",
                origin=origin,
            ) from error
        if not stat.S_ISREG(before.st_mode):
            raise ControlledError(
                outcome="invalid",
                code="ref.unresolved",
                kind="reference",
                message="References must target regular files.",
                origin=origin,
            )

        if is_entrypoint:
            self.entrypoint_bytes = before.st_size
            if before.st_size > self.limits.max_entrypoint_bytes:
                raise self.controlled_limit(
                    "input.entrypoint-bytes-exceeded",
                    (
                        "Entrypoint bytes exceed the configured maximum of "
                        f"{self.limits.max_entrypoint_bytes}."
                    ),
                    origin,
                )

        if len(self.documents_by_real) + 1 > self.limits.max_files:
            raise self.controlled_limit(
                "ref.file-count-exceeded",
                f"Referenced file count exceeds the configured maximum of {self.limits.max_files}.",
                origin,
            )

        remaining = self.limits.max_total_bytes - self.total_bytes
        if before.st_size > remaining:
            raise self.controlled_limit(
                "ref.aggregate-bytes-exceeded",
                f"Loaded bytes exceed the configured maximum of {self.limits.max_total_bytes}.",
                origin,
            )

        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(real_path, flags)
        except OSError as error:
            raise ControlledError(
                outcome="invalid",
                code="ref.unresolved",
                kind="reference",
                message="A referenced file could not be opened safely.",
                origin=origin,
            ) from error
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise ControlledError(
                    outcome="invalid",
                    code="ref.unresolved",
                    kind="reference",
                    message="References must target regular files.",
                    origin=origin,
                )
            if (
                before.st_dev != opened.st_dev
                or (before.st_ino and opened.st_ino and before.st_ino != opened.st_ino)
            ):
                raise ControlledError(
                    outcome="invalid",
                    code="ref.unresolved",
                    kind="reference",
                    message="A referenced file changed while it was being opened.",
                    origin=origin,
                )

            chunks: list[bytes] = []
            observed = 0
            read_cap = remaining + 1
            if is_entrypoint:
                read_cap = min(read_cap, self.limits.max_entrypoint_bytes + 1)
            while observed < read_cap:
                chunk = os.read(descriptor, min(READ_CHUNK_BYTES, read_cap - observed))
                if not chunk:
                    break
                chunks.append(chunk)
                observed += len(chunk)
            body = b"".join(chunks)
        finally:
            os.close(descriptor)

        if is_entrypoint and len(body) > self.limits.max_entrypoint_bytes:
            raise self.controlled_limit(
                "input.entrypoint-bytes-exceeded",
                (
                    "Entrypoint bytes exceed the configured maximum of "
                    f"{self.limits.max_entrypoint_bytes}."
                ),
                origin,
            )
        if len(body) > remaining:
            raise self.controlled_limit(
                "ref.aggregate-bytes-exceeded",
                f"Loaded bytes exceed the configured maximum of {self.limits.max_total_bytes}.",
                origin,
            )
        if opened.st_size != len(body):
            raise ControlledError(
                outcome="invalid",
                code="ref.unresolved",
                kind="reference",
                message="A referenced file changed while it was being read.",
                origin=origin,
            )
        return body

    def add_alias(self, document: Document, uri: str) -> None:
        document.aliases.add(uri)
        self.resources_by_uri[uri] = document

    def load_document(
        self,
        *,
        logical_path: Path,
        real_path: Path,
        origin: Origin,
        request_uri: str,
        is_entrypoint: bool,
    ) -> Document:
        body = self.bounded_read(
            logical_path=logical_path,
            real_path=real_path,
            origin=origin,
            is_entrypoint=is_entrypoint,
        )
        source = self.source_for(logical_path)
        root, origins, values = parse_document(body, source, logical_path.suffix)
        document = Document(
            logical_path=logical_path,
            real_path=real_path,
            source=source,
            body=body,
            root=root,
            origins=origins,
            values=values,
        )
        self.documents_by_real[real_path] = document
        self.total_bytes += len(body)
        if is_entrypoint:
            self.entrypoint_bytes = len(body)
        self.add_alias(document, request_uri)
        self.add_alias(document, real_path.as_uri())
        return document

    def iter_references(self, document: Document) -> Iterator[ReferenceSite]:
        def walk(value: Any, pointer: str) -> Iterator[ReferenceSite]:
            if isinstance(value, dict):
                for key, child in value.items():
                    child_pointer = append_pointer(pointer, key)
                    if key == "$ref" and isinstance(child, str):
                        origin = document.origins.get(
                            child_pointer,
                            Origin(document.source, 1, 1, child_pointer),
                        )
                        yield ReferenceSite(document=document, ref=str(child), origin=origin)
                    yield from walk(child, child_pointer)
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    yield from walk(child, append_pointer(pointer, index))

        yield from walk(document.root, "")

    def classify_reference(self, site: ReferenceSite) -> tuple[Path, Path, str] | None:
        ref = site.ref
        if not ref or "\x00" in ref:
            raise self.controlled_policy(
                "ref.scheme-denied",
                "Invalid references are disabled.",
                site.origin,
            )
        if ref.startswith("#"):
            return None
        try:
            parsed = urlsplit(ref)
        except ValueError as error:
            raise self.controlled_policy(
                "ref.scheme-denied",
                "Malformed URI references are disabled.",
                site.origin,
            ) from error
        if parsed.scheme or parsed.netloc:
            raise self.controlled_policy(
                "ref.scheme-denied",
                "URI scheme and protocol-relative references are disabled.",
                site.origin,
            )
        if parsed.query:
            raise self.controlled_policy(
                "ref.scheme-denied",
                "Query-bearing references are disabled.",
                site.origin,
            )
        try:
            decoded = unquote_to_bytes(parsed.path).decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise self.controlled_policy(
                "ref.scheme-denied",
                "Malformed percent-encoded references are disabled.",
                site.origin,
            ) from error
        if (
            not decoded
            or "\x00" in decoded
            or "?" in decoded
            or "#" in decoded
            or "\\" in decoded
            or decoded.startswith("/")
            or PureWindowsPath(decoded).drive
            or PureWindowsPath(decoded).is_absolute()
        ):
            raise self.controlled_policy(
                "ref.scheme-denied",
                "Absolute and non-local references are disabled.",
                site.origin,
            )

        logical = Path(os.path.abspath(site.document.logical_path.parent / decoded))
        if not path_is_within(self.repository_root, logical):
            raise self.controlled_policy(
                "ref.path-outside-root",
                "References outside the repository root are disabled.",
                site.origin,
            )
        try:
            real = logical.resolve(strict=True)
        except FileNotFoundError as error:
            nearest = logical.resolve(strict=False)
            if not path_is_within(self.repository_root, nearest):
                raise self.controlled_policy(
                    "ref.path-outside-root",
                    "References outside the repository root are disabled.",
                    site.origin,
                ) from error
            raise ControlledError(
                outcome="invalid",
                code="ref.unresolved",
                kind="reference",
                message="A local reference target does not exist.",
                origin=site.origin,
            ) from error
        except OSError as error:
            raise ControlledError(
                outcome="invalid",
                code="ref.unresolved",
                kind="reference",
                message="A local reference target could not be resolved.",
                origin=site.origin,
            ) from error
        if not path_is_within(self.repository_root, real):
            raise self.controlled_policy(
                "ref.path-outside-root",
                "Symlinked or junction references outside the repository root are disabled.",
                site.origin,
            )
        return logical, real, logical.as_uri()

    def visit_document(self, document: Document, depth: int) -> None:
        for site in self.iter_references(document):
            self.references_seen += 1
            classified = self.classify_reference(site)
            if classified is None:
                continue
            logical, real, request_uri = classified
            existing = self.documents_by_real.get(real)
            if existing is not None:
                self.add_alias(existing, request_uri)
                continue

            next_depth = depth + 1
            self.max_depth_observed = max(self.max_depth_observed, next_depth)
            if next_depth > self.limits.max_depth:
                raise self.controlled_limit(
                    "ref.depth-exceeded",
                    f"Reference depth exceeds the configured maximum of {self.limits.max_depth}.",
                    site.origin,
                )
            child = self.load_document(
                logical_path=logical,
                real_path=real,
                origin=site.origin,
                request_uri=request_uri,
                is_entrypoint=False,
            )
            self.visit_document(child, next_depth)

    def build(self) -> Document:
        logical, real = self.resolve_entrypoint()
        origin = self.origin_for_path(logical)
        entrypoint = self.load_document(
            logical_path=logical,
            real_path=real,
            origin=origin,
            request_uri=logical.as_uri(),
            is_entrypoint=True,
        )
        self.entrypoint_document = entrypoint
        self.visit_document(entrypoint, 0)
        return entrypoint


def instance_origin(instance: Any) -> Origin | None:
    origin = getattr(instance, "origin", None)
    return origin if isinstance(origin, Origin) else None


def missing_required_property(error: ValidationError) -> str | None:
    if getattr(error, "validator", None) != "required":
        return None
    match = REQUIRED_PROPERTY_RE.match(str(getattr(error, "message", "")))
    return match.group("name") if match else None


def fallback_error_origin(error: ValidationError, closure: Closure) -> Origin:
    entrypoint = closure.entrypoint_document
    assert entrypoint is not None
    pointer = pointer_from_parts(getattr(error, "absolute_path", ()))
    candidates: list[Origin] = []
    for document in closure.documents_by_real.values():
        value = document.values.get(pointer, object())
        if value is getattr(error, "instance", None):
            candidate = document.origins.get(pointer)
            if candidate is not None:
                candidates.append(candidate)
    if len(candidates) == 1:
        return candidates[0]
    return entrypoint.origins.get(
        pointer,
        entrypoint.origins.get("", Origin(entrypoint.source, 1, 1, "")),
    )


def normalize_validation_error(error: ValidationError, closure: Closure) -> Diagnostic:
    origin = instance_origin(getattr(error, "instance", None))
    if origin is None:
        origin = fallback_error_origin(error, closure)

    pointer = origin.pointer
    missing = missing_required_property(error)
    if missing is not None:
        pointer = append_pointer(pointer, missing)
    document = next(
        (
            candidate
            for candidate in closure.documents_by_real.values()
            if candidate.source == origin.source
        ),
        None,
    )
    location = document.origins.get(pointer) if document is not None else None
    if location is None:
        location = origin

    return Diagnostic(
        source=location.source,
        line=location.line,
        column=location.column,
        pointer=pointer,
        code="oas.schema",
        severity="error",
        kind="schema",
        message=stable_message(getattr(error, "message", str(error)), closure.repository_root),
    )


def diagnostic_sort_key(diagnostic: Diagnostic) -> tuple[Any, ...]:
    def nullable(value: Any) -> tuple[int, Any]:
        return (1, "") if value is None else (0, value)

    return (
        nullable(diagnostic.source),
        nullable(diagnostic.line),
        nullable(diagnostic.column),
        nullable(diagnostic.pointer),
        diagnostic.code,
        diagnostic.severity,
        diagnostic.kind,
        diagnostic.message,
    )


def deduplicate_diagnostics(diagnostics: list[Diagnostic]) -> list[Diagnostic]:
    result: list[Diagnostic] = []
    seen: set[tuple[Any, ...]] = set()
    for diagnostic in sorted(diagnostics, key=diagnostic_sort_key):
        key = (
            diagnostic.source,
            diagnostic.line,
            diagnostic.column,
            diagnostic.pointer,
            diagnostic.code,
            diagnostic.severity,
            diagnostic.kind,
            diagnostic.message,
        )
        if key not in seen:
            seen.add(key)
            result.append(diagnostic)
    return result


def collect_validation_diagnostics(
    entrypoint: Document,
    closure: Closure,
) -> tuple[list[Diagnostic], bool]:
    version = entrypoint.root.get("openapi")
    if isinstance(version, str) and version.startswith("3.0."):
        validator_type = OpenAPIV30SpecValidator
    elif isinstance(version, str) and version.startswith("3.1."):
        validator_type = OpenAPIV31SpecValidator
    else:
        origin = entrypoint.origins.get(
            "/openapi",
            entrypoint.origins.get("", Origin(entrypoint.source, 1, 1, "")),
        )
        return (
            [
                Diagnostic(
                    source=origin.source,
                    line=origin.line,
                    column=origin.column,
                    pointer="/openapi",
                    code="oas.schema",
                    severity="error",
                    kind="schema",
                    message="Only OpenAPI 3.0 and 3.1 documents are supported.",
                )
            ],
            False,
        )

    handlers = ClosedMemoryHandlers(closure.resources_by_uri)
    schema_path = SchemaPath.from_dict(
        entrypoint.root,
        base_uri=entrypoint.logical_path.as_uri(),
        handlers=handlers,
        resolved_cache_maxsize=128,
    )
    validator = validator_type(schema_path)
    diagnostics: list[Diagnostic] = []
    overflow = False
    try:
        for index, error in enumerate(validator.iter_errors()):
            if index >= MAX_OBSERVED_DIAGNOSTICS:
                overflow = True
                break
            diagnostics.append(normalize_validation_error(error, closure))
    except Exception:
        # Version 0.9.0 performs its complete meta-schema pass before its
        # semantic pass. Some structurally invalid values (for example a
        # non-object Responses value) then make the semantic pass raise a
        # KeyError. At that point all structural findings have already been
        # yielded, so retaining them is complete and avoids turning controlled
        # invalid input into an adapter failure. An exception without a prior
        # finding is still an internal failure and must remain visible.
        if not diagnostics:
            raise
    return diagnostics, overflow


def make_stats(
    *,
    closure: Closure,
    limits: Limits,
    diagnostics_raw: int,
    diagnostics_emitted: int,
) -> dict[str, Any]:
    truncated = diagnostics_raw - diagnostics_emitted
    return {
        "filesLoaded": len(closure.documents_by_real),
        "filesRead": len(closure.documents_by_real),
        "entrypointBytes": closure.entrypoint_bytes,
        "totalBytes": closure.total_bytes,
        "aggregateBytesRead": closure.total_bytes,
        "referencesSeen": closure.references_seen,
        "maxDepthObserved": closure.max_depth_observed,
        "maximumDepthObserved": closure.max_depth_observed,
        "diagnosticsRaw": diagnostics_raw,
        "diagnosticsEmitted": diagnostics_emitted,
        "diagnosticsTruncated": truncated,
        "limitCode": closure.limit_code,
        "policyDenials": closure.policy_denials,
        "limitDenials": closure.limit_denials,
        "limits": limits.as_json(),
    }


def finalize(
    *,
    closure: Closure,
    diagnostics: list[Diagnostic],
    forced_outcome: str | None = None,
    observation_overflow: bool = False,
) -> dict[str, Any]:
    normalized = deduplicate_diagnostics(diagnostics)
    emitted = normalized[: closure.limits.max_diagnostics]
    diagnostics_raw = len(normalized) + (1 if observation_overflow else 0)
    truncated = diagnostics_raw - len(emitted)
    if truncated > 0:
        closure.record_limit("diagnostics.limit-exceeded")
        closure.limit_code = "diagnostics.limit-exceeded"
        outcome = "limit-exceeded"
    elif forced_outcome is not None:
        outcome = forced_outcome
    elif normalized:
        outcome = "invalid"
    else:
        outcome = "valid"

    return {
        "schemaVersion": SCHEMA_VERSION,
        "adapter": ADAPTER_NAME,
        "outcome": outcome,
        "diagnostics": [diagnostic.as_json() for diagnostic in emitted],
        "stats": make_stats(
            closure=closure,
            limits=closure.limits,
            diagnostics_raw=diagnostics_raw,
            diagnostics_emitted=len(emitted),
        ),
    }


def validate_entrypoint(options: Options) -> dict[str, Any]:
    closure = Closure(options)
    try:
        entrypoint = closure.build()
        diagnostics, overflow = collect_validation_diagnostics(entrypoint, closure)
        return finalize(
            closure=closure,
            diagnostics=diagnostics,
            observation_overflow=overflow,
        )
    except ControlledError as error:
        return finalize(
            closure=closure,
            diagnostics=[error.diagnostic()],
            forced_outcome=error.outcome,
        )


def parse_nonnegative_integer(name: str, value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise ContractError(f"{name} must be a non-negative integer.") from error
    if parsed < 0 or parsed > sys.maxsize:
        raise ContractError(f"{name} must be a non-negative safe integer.")
    return parsed


def parse_arguments(argv: list[str]) -> Options:
    values: dict[str, str] = {}
    index = 0
    while index < len(argv):
        argument = argv[index]
        if not argument.startswith("--"):
            raise ContractError(f"Unexpected positional argument: {argument}")
        name = argument[2:]
        if index + 1 >= len(argv) or argv[index + 1].startswith("--"):
            raise ContractError(f"Missing value for --{name}.")
        if name in values:
            raise ContractError(f"Duplicate option: --{name}.")
        values[name] = argv[index + 1]
        index += 2

    allowed = {
        "entrypoint",
        "repository-root",
        "max-entrypoint-bytes",
        "max-files",
        "max-total-bytes",
        "max-depth",
        "max-diagnostics",
    }
    unknown = sorted(set(values) - allowed)
    if unknown:
        raise ContractError(f"Unknown option: --{unknown[0]}.")
    if not values.get("entrypoint"):
        raise ContractError("--entrypoint is required.")
    if not values.get("repository-root"):
        raise ContractError("--repository-root is required.")

    def limit(option: str, default: int) -> int:
        raw = values.get(option)
        return default if raw is None else parse_nonnegative_integer(f"--{option}", raw)

    return Options(
        entrypoint=values["entrypoint"],
        repository_root=values["repository-root"],
        limits=Limits(
            max_entrypoint_bytes=limit(
                "max-entrypoint-bytes", DEFAULT_MAX_ENTRYPOINT_BYTES
            ),
            max_files=limit("max-files", DEFAULT_MAX_FILES),
            max_total_bytes=limit("max-total-bytes", DEFAULT_MAX_TOTAL_BYTES),
            max_depth=limit("max-depth", DEFAULT_MAX_DEPTH),
            max_diagnostics=limit("max-diagnostics", DEFAULT_MAX_DIAGNOSTICS),
        ),
    )


def contract_failure(error: Exception) -> dict[str, Any]:
    is_contract = isinstance(error, ContractError)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "adapter": ADAPTER_NAME,
        "outcome": "invalid",
        "diagnostics": [
            {
                "source": None,
                "line": None,
                "column": None,
                "pointer": None,
                "code": "adapter-contract-error" if is_contract else "adapter-internal-error",
                "severity": "error",
                "kind": "contract" if is_contract else "internal",
                "message": (
                    str(error)
                    if is_contract
                    else "The adapter failed unexpectedly. See the process error stream."
                ),
            }
        ],
        "stats": {
            "filesLoaded": 0,
            "filesRead": 0,
            "entrypointBytes": 0,
            "totalBytes": 0,
            "aggregateBytesRead": 0,
            "referencesSeen": 0,
            "maxDepthObserved": 0,
            "maximumDepthObserved": 0,
            "diagnosticsRaw": 1,
            "diagnosticsEmitted": 1,
            "diagnosticsTruncated": 0,
            "limitCode": None,
            "policyDenials": 0,
            "limitDenials": 0,
            "limits": None,
        },
    }


def main() -> int:
    try:
        result = validate_entrypoint(parse_arguments(sys.argv[1:]))
    except Exception as error:
        result = contract_failure(error)
        sys.stdout.write(json.dumps(result, separators=(",", ":"), ensure_ascii=False) + "\n")
        if not isinstance(error, ContractError):
            import traceback

            traceback.print_exc(file=sys.stderr)
        return 2
    sys.stdout.write(json.dumps(result, separators=(",", ":"), ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
