"""Closure-only OpenAPI validation and deterministic diagnostic normalization."""

from __future__ import annotations

import json
import math
import os
import posixpath
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, unquote_to_bytes, urldefrag, urlsplit

# An optional jsonschema-rs installation must not change the validator authority.
os.environ["OPENAPI_SPEC_VALIDATOR_SCHEMA_VALIDATOR_BACKEND"] = "jsonschema"

import yaml
from jsonschema.exceptions import ValidationError
from jsonschema_path import SchemaPath
from jsonschema_path.loaders import JsonschemaSafeLoader
from openapi_spec_validator import OpenAPIV30SpecValidator, OpenAPIV31SpecValidator
from referencing.exceptions import NoSuchResource
from yaml.events import AliasEvent, CollectionEndEvent, CollectionStartEvent
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from proof_validator_worker.protocol import (
    Diagnostic,
    ValidationRequest,
    ValidationResponse,
)

MAX_DOCUMENT_NESTING = 100
MAX_YAML_ALIASES = 50
MAX_EXPANDED_NODES = 100_000
MAX_OBSERVED_DIAGNOSTICS = 2_048
MAX_DIAGNOSTIC_MESSAGE_CHARS = 2_048
_REQUIRED_PROPERTY = re.compile(r"^'(?P<name>.*)' is a required property$")
_RESOURCE_BASE = "https://proof.invalid/repository/"


@dataclass(frozen=True, slots=True)
class Origin:
    source: str
    line: int
    column: int
    pointer: str


class LocatedDict(dict[str, Any]):
    def __init__(self, origin: Origin) -> None:
        super().__init__()
        self.origin = origin


class LocatedList(list[Any]):
    def __init__(self, origin: Origin) -> None:
        super().__init__()
        self.origin = origin


class LocatedString(str):
    def __new__(cls, value: str, origin: Origin) -> LocatedString:
        result = str.__new__(cls, value)
        result.origin = origin
        return result


class LocatedInteger(int):
    def __new__(cls, value: int, origin: Origin) -> LocatedInteger:
        result = int.__new__(cls, value)
        result.origin = origin
        return result


class LocatedFloat(float):
    def __new__(cls, value: float, origin: Origin) -> LocatedFloat:
        result = float.__new__(cls, value)
        result.origin = origin
        return result


@dataclass(slots=True)
class Document:
    path: str
    uri: str
    root: LocatedDict
    origins: dict[str, Origin] = field(default_factory=dict)
    values: dict[str, Any] = field(default_factory=dict)


class ControlledValidation(ValueError):
    def __init__(self, diagnostic: Diagnostic) -> None:
        super().__init__(diagnostic.message)
        self.diagnostic = diagnostic


class ClosedMemoryHandlers(Mapping[str, Any]):
    """Claim every URI scheme and resolve only the supplied in-memory map."""

    def __init__(self, resources: Mapping[str, Document]) -> None:
        self._resources = resources

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
        document = self._resources.get(resource_uri)
        if document is None:
            raise NoSuchResource(ref=uri)
        return document.root


def _escape_pointer(value: object) -> str:
    return str(value).replace("~", "~0").replace("/", "~1")


def _append_pointer(pointer: str, value: object) -> str:
    return f"{pointer}/{_escape_pointer(value)}"


def _pointer_from_parts(parts: Any) -> str:
    pointer = ""
    try:
        for part in parts:
            pointer = _append_pointer(pointer, part)
    except TypeError:
        return ""
    return pointer


def _origin(source: str, pointer: str, mark: Any) -> Origin:
    return Origin(
        source=source,
        line=int(getattr(mark, "line", 0)) + 1,
        column=int(getattr(mark, "column", 0)) + 1,
        pointer=pointer,
    )


def _diagnostic(
    *,
    code: str,
    kind: str,
    message: str,
    origin: Origin | None = None,
) -> Diagnostic:
    return Diagnostic(
        source=origin.source if origin else None,
        line=origin.line if origin else None,
        column=origin.column if origin else None,
        pointer=origin.pointer if origin else None,
        code=code,
        severity="error",
        kind=kind,
        message=message,
    )


def _preflight_yaml(text: str, source: str) -> None:
    aliases = 0
    depth = 0
    try:
        for event in yaml.parse(text, Loader=JsonschemaSafeLoader):
            if isinstance(event, AliasEvent):
                aliases += 1
                if aliases > MAX_YAML_ALIASES:
                    raise ControlledValidation(
                        _diagnostic(
                            code="parse.alias-limit",
                            kind="parse",
                            message="YAML aliases exceed the supported limit.",
                            origin=_origin(source, "", event.start_mark),
                        )
                    )
            elif isinstance(event, CollectionStartEvent):
                depth += 1
                if depth > MAX_DOCUMENT_NESTING:
                    raise ControlledValidation(
                        _diagnostic(
                            code="parse.nesting-limit",
                            kind="parse",
                            message="Document nesting exceeds the supported limit.",
                            origin=_origin(source, "", event.start_mark),
                        )
                    )
            elif isinstance(event, CollectionEndEvent):
                depth -= 1
    except yaml.MarkedYAMLError as error:
        mark = error.problem_mark or error.context_mark
        raise ControlledValidation(
            _diagnostic(
                code="parse.invalid-yaml",
                kind="parse",
                message="The document is not valid YAML.",
                origin=_origin(source, "", mark) if mark is not None else None,
            )
        ) from error


def _strict_json_check(text: str, source: str) -> None:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate")
            result[key] = value
        return result

    def invalid_constant(_token: str) -> None:
        raise ValueError("constant")

    try:
        json.loads(
            text,
            object_pairs_hook=unique,
            parse_constant=invalid_constant,
        )
    except json.JSONDecodeError as error:
        raise ControlledValidation(
            _diagnostic(
                code="parse.invalid-json",
                kind="parse",
                message="The document is not valid strict JSON.",
                origin=Origin(source, max(error.lineno, 1), max(error.colno, 1), ""),
            )
        ) from error
    except ValueError as error:
        raise ControlledValidation(
            _diagnostic(
                code="parse.invalid-json",
                kind="parse",
                message="JSON keys must be unique and numbers must be finite.",
                origin=Origin(source, 1, 1, ""),
            )
        ) from error


def _located_scalar(value: Any, origin: Origin) -> Any:
    if isinstance(value, str):
        return LocatedString(value, origin)
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return LocatedInteger(value, origin)
    if isinstance(value, float):
        return LocatedFloat(value, origin)
    return value


def _convert_node(
    *,
    node: Node,
    pointer: str,
    source: str,
    origins: dict[str, Origin],
    values: dict[str, Any],
    loader: JsonschemaSafeLoader,
    visiting: set[int],
    node_budget: list[int],
    forced_origin: Origin | None = None,
) -> Any:
    location = forced_origin or _origin(source, pointer, node.start_mark)
    node_budget[0] -= 1
    if node_budget[0] < 0:
        raise ControlledValidation(
            _diagnostic(
                code="parse.alias-expansion-limit",
                kind="parse",
                message="Expanded YAML nodes exceed the supported limit.",
                origin=location,
            )
        )
    origins[pointer] = location
    identity = id(node)
    if identity in visiting:
        raise ControlledValidation(
            _diagnostic(
                code="parse.cyclic-alias",
                kind="parse",
                message="Recursive YAML aliases are not supported.",
                origin=location,
            )
        )

    if isinstance(node, ScalarNode):
        try:
            raw = loader.construct_object(node, deep=True)
        except Exception as error:
            raise ControlledValidation(
                _diagnostic(
                    code="parse.invalid-yaml",
                    kind="parse",
                    message="The YAML scalar could not be decoded safely.",
                    origin=location,
                )
            ) from error
        if not isinstance(raw, (str, int, float, bool, type(None))) or (
            isinstance(raw, float) and not math.isfinite(raw)
        ):
            raise ControlledValidation(
                _diagnostic(
                    code="parse.invalid-yaml",
                    kind="parse",
                    message="Only JSON-compatible YAML scalar values are supported.",
                    origin=location,
                )
            )
        value = _located_scalar(raw, location)
        values[pointer] = value
        return value

    visiting.add(identity)
    try:
        if isinstance(node, SequenceNode):
            sequence = LocatedList(location)
            values[pointer] = sequence
            for index, child in enumerate(node.value):
                child_pointer = _append_pointer(pointer, index)
                sequence.append(
                    _convert_node(
                        node=child,
                        pointer=child_pointer,
                        source=source,
                        origins=origins,
                        values=values,
                        loader=loader,
                        visiting=visiting,
                        node_budget=node_budget,
                    )
                )
            return sequence

        if isinstance(node, MappingNode):
            mapping = LocatedDict(location)
            values[pointer] = mapping
            for key_node, value_node in node.value:
                if not isinstance(key_node, ScalarNode):
                    raise ControlledValidation(
                        _diagnostic(
                            code="parse.invalid-yaml",
                            kind="parse",
                            message="Mapping keys must be strings.",
                            origin=_origin(source, pointer, key_node.start_mark),
                        )
                    )
                key_location = _origin(source, pointer, key_node.start_mark)
                key = loader.construct_object(key_node, deep=True)
                if not isinstance(key, str) or key == "<<":
                    raise ControlledValidation(
                        _diagnostic(
                            code="parse.invalid-yaml",
                            kind="parse",
                            message=(
                                "Mapping keys must be strings and merge keys are "
                                "disabled."
                            ),
                            origin=key_location,
                        )
                    )
                child_pointer = _append_pointer(pointer, key)
                key_location = _origin(source, child_pointer, key_node.start_mark)
                if key in mapping:
                    raise ControlledValidation(
                        _diagnostic(
                            code="parse.duplicate-key",
                            kind="parse",
                            message="Duplicate mapping keys are not allowed.",
                            origin=key_location,
                        )
                    )
                mapping[key] = _convert_node(
                    node=value_node,
                    pointer=child_pointer,
                    source=source,
                    origins=origins,
                    values=values,
                    loader=loader,
                    visiting=visiting,
                    node_budget=node_budget,
                    forced_origin=key_location,
                )
            return mapping
    finally:
        visiting.remove(identity)

    raise ControlledValidation(
        _diagnostic(
            code="parse.invalid-yaml",
            kind="parse",
            message="Unsupported YAML node type.",
            origin=location,
        )
    )


def _parse_document(path: str, body: bytes) -> Document:
    try:
        text = body.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        prefix = body[: error.start].decode("utf-8", errors="ignore")
        location = Origin(
            path,
            prefix.count("\n") + 1,
            len(prefix.rsplit("\n", 1)[-1]) + 1,
            "",
        )
        raise ControlledValidation(
            _diagnostic(
                code="parse.invalid-utf8",
                kind="parse",
                message="Input resources must contain valid UTF-8.",
                origin=location,
            )
        ) from error

    is_json = path.lower().endswith(".json")
    if is_json:
        _strict_json_check(text, path)
    _preflight_yaml(text, path)
    try:
        nodes = list(yaml.compose_all(text, Loader=JsonschemaSafeLoader))
    except yaml.MarkedYAMLError as error:
        mark = error.problem_mark or error.context_mark
        raise ControlledValidation(
            _diagnostic(
                code="parse.invalid-json" if is_json else "parse.invalid-yaml",
                kind="parse",
                message="The document could not be parsed.",
                origin=_origin(path, "", mark) if mark is not None else None,
            )
        ) from error
    if len(nodes) != 1 or nodes[0] is None:
        second = nodes[1] if len(nodes) > 1 else None
        raise ControlledValidation(
            _diagnostic(
                code="parse.multiple-documents"
                if len(nodes) > 1
                else "parse.invalid-yaml",
                kind="parse",
                message="Exactly one non-empty document is required.",
                origin=_origin(path, "", second.start_mark)
                if second
                else Origin(path, 1, 1, ""),
            )
        )

    origins: dict[str, Origin] = {}
    values: dict[str, Any] = {}
    loader = JsonschemaSafeLoader("")
    try:
        root = _convert_node(
            node=nodes[0],
            pointer="",
            source=path,
            origins=origins,
            values=values,
            loader=loader,
            visiting=set(),
            node_budget=[MAX_EXPANDED_NODES],
        )
    finally:
        loader.dispose()
    if not isinstance(root, LocatedDict):
        raise ControlledValidation(
            _diagnostic(
                code="parse.invalid-document",
                kind="parse",
                message="An OpenAPI document must be a mapping object.",
                origin=origins.get("", Origin(path, 1, 1, "")),
            )
        )
    return Document(
        path=path,
        uri=_RESOURCE_BASE + quote(path, safe="/"),
        root=root,
        origins=origins,
        values=values,
    )


def _iter_references(value: Any, pointer: str = "") -> Iterator[tuple[str, str]]:
    if isinstance(value, dict):
        for key, child in value.items():
            child_pointer = _append_pointer(pointer, key)
            if key == "$ref" and isinstance(child, str):
                yield str(child), child_pointer
            yield from _iter_references(child, child_pointer)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _iter_references(child, _append_pointer(pointer, index))


def _check_reference_closure(documents: Mapping[str, Document]) -> None:
    for document in documents.values():
        for reference, pointer in _iter_references(document.root):
            location = document.origins.get(
                pointer, Origin(document.path, 1, 1, pointer)
            )
            if reference.startswith("#"):
                continue
            try:
                parsed = urlsplit(reference)
            except ValueError as error:
                raise ControlledValidation(
                    _diagnostic(
                        code="ref.scheme-denied",
                        kind="reference",
                        message="Malformed URI references are disabled.",
                        origin=location,
                    )
                ) from error
            if parsed.scheme or parsed.netloc or parsed.query or not parsed.path:
                raise ControlledValidation(
                    _diagnostic(
                        code="ref.scheme-denied",
                        kind="reference",
                        message="Only repository-local references are supported.",
                        origin=location,
                    )
                )
            try:
                decoded = unquote_to_bytes(parsed.path).decode("utf-8", errors="strict")
            except UnicodeDecodeError as error:
                raise ControlledValidation(
                    _diagnostic(
                        code="ref.scheme-denied",
                        kind="reference",
                        message="Reference paths must use valid UTF-8 encoding.",
                        origin=location,
                    )
                ) from error
            if "\\" in decoded or decoded.startswith("/") or "\x00" in decoded:
                raise ControlledValidation(
                    _diagnostic(
                        code="ref.scheme-denied",
                        kind="reference",
                        message="Absolute and non-portable references are disabled.",
                        origin=location,
                    )
                )
            target = posixpath.normpath(
                posixpath.join(posixpath.dirname(document.path), decoded)
            )
            if target == ".." or target.startswith("../"):
                raise ControlledValidation(
                    _diagnostic(
                        code="ref.path-outside-root",
                        kind="reference",
                        message="References outside the input closure are disabled.",
                        origin=location,
                    )
                )
            if target not in documents:
                raise ControlledValidation(
                    _diagnostic(
                        code="ref.unresolved",
                        kind="reference",
                        message=(
                            "A local reference target is absent from the input "
                            "closure."
                        ),
                        origin=location,
                    )
                )


def _instance_origin(instance: Any) -> Origin | None:
    location = getattr(instance, "origin", None)
    return location if isinstance(location, Origin) else None


def _normalize_message(message: object) -> str:
    value = str(message).replace("\r", " ").replace("\n", " ")
    value = value.replace(_RESOURCE_BASE, "<resource>/")
    normalized = " ".join(value.split())
    if len(normalized) > MAX_DIAGNOSTIC_MESSAGE_CHARS:
        return normalized[: MAX_DIAGNOSTIC_MESSAGE_CHARS - 3] + "..."
    return normalized


def _normalize_error(
    error: ValidationError,
    *,
    entrypoint: Document,
    documents: Mapping[str, Document],
) -> Diagnostic:
    location = _instance_origin(getattr(error, "instance", None))
    pointer = _pointer_from_parts(getattr(error, "absolute_path", ()))
    if location is None:
        candidates = [
            document.origins[pointer]
            for document in documents.values()
            if pointer in document.values
            and document.values[pointer] is getattr(error, "instance", None)
        ]
        location = (
            candidates[0]
            if len(candidates) == 1
            else entrypoint.origins.get(pointer, entrypoint.origins[""])
        )
    else:
        pointer = location.pointer

    if getattr(error, "validator", None) == "required":
        match = _REQUIRED_PROPERTY.match(str(getattr(error, "message", "")))
        if match:
            pointer = _append_pointer(pointer, match.group("name"))
    defining = documents.get(location.source)
    precise = defining.origins.get(pointer) if defining else None
    if precise is not None:
        location = precise
    return _diagnostic(
        code="oas.schema",
        kind="schema",
        message=_normalize_message(getattr(error, "message", str(error))),
        origin=Origin(location.source, location.line, location.column, pointer),
    )


def _sort_key(diagnostic: Diagnostic) -> tuple[Any, ...]:
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


def _deduplicate(diagnostics: list[Diagnostic]) -> list[Diagnostic]:
    result: list[Diagnostic] = []
    seen: set[tuple[Any, ...]] = set()
    for item in sorted(diagnostics, key=_sort_key):
        key = _sort_key(item)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _collect_diagnostics(
    entrypoint: Document, documents: Mapping[str, Document]
) -> tuple[list[Diagnostic], bool]:
    version = entrypoint.root.get("openapi")
    if isinstance(version, str) and version.startswith("3.0."):
        validator_type = OpenAPIV30SpecValidator
    elif isinstance(version, str) and version.startswith("3.1."):
        validator_type = OpenAPIV31SpecValidator
    else:
        location = entrypoint.origins.get("/openapi", entrypoint.origins[""])
        return (
            [
                _diagnostic(
                    code="oas.schema",
                    kind="schema",
                    message="Only OpenAPI 3.0 and 3.1 documents are supported.",
                    origin=Origin(
                        location.source, location.line, location.column, "/openapi"
                    ),
                )
            ],
            False,
        )

    by_uri = {document.uri: document for document in documents.values()}
    schema_path = SchemaPath.from_dict(
        entrypoint.root,
        base_uri=entrypoint.uri,
        handlers=ClosedMemoryHandlers(by_uri),
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
            diagnostics.append(
                _normalize_error(error, entrypoint=entrypoint, documents=documents)
            )
    except Exception:
        # 0.9.0 can raise KeyError in its semantic pass after it has yielded the
        # complete structural findings. Preserve those findings, but never hide
        # an exception that occurred before the first diagnostic.
        if not diagnostics:
            raise
    return diagnostics, overflow


def validate_request(request: ValidationRequest) -> ValidationResponse:
    """Validate one immutable input closure without filesystem or network I/O."""

    try:
        documents = {
            resource.path: _parse_document(resource.path, resource.content)
            for resource in request.resources
        }
        _check_reference_closure(documents)
        entrypoint = documents[request.entrypoint]
        diagnostics, overflow = _collect_diagnostics(entrypoint, documents)
    except ControlledValidation as error:
        diagnostics = [error.diagnostic]
        overflow = False

    normalized = _deduplicate(diagnostics)
    emitted = normalized[: request.max_diagnostics]
    observed = len(normalized) + (1 if overflow else 0)
    truncated = observed - len(emitted)
    if truncated:
        outcome = "limit-exceeded"
    elif normalized:
        outcome = "invalid"
    else:
        outcome = "valid"
    return ValidationResponse(
        entrypoint=request.entrypoint,
        manifest_digest=request.manifest_digest,
        outcome=outcome,
        diagnostics=tuple(emitted),
        diagnostics_observed=observed,
        diagnostics_truncated=truncated,
    )
