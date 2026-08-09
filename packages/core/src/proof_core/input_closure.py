"""Build immutable, repository-confined OpenAPI input closures."""

from __future__ import annotations

import errno
import hashlib
import heapq
import json
import math
import os
import re
import stat
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, fields
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any
from urllib.parse import unquote_to_bytes, urlsplit

import yaml
from yaml.constructor import ConstructorError
from yaml.events import AliasEvent
from yaml.nodes import MappingNode

MANIFEST_SCHEMA_VERSION = "1.0.0"
_READ_BUFFER_BYTES = 64 * 1024
_SUPPORTED_SUFFIXES = frozenset({".json", ".yaml", ".yml"})
_INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
_WINDOWS_DEVICE = re.compile(
    r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$",
    re.IGNORECASE,
)


class InputClosureError(ValueError):
    """A stable, path-safe failure while preparing scan input."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        path: str | None = None,
        reference: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.path = path
        self.reference = reference

    def to_dict(self) -> dict[str, str]:
        value = {"code": self.code, "message": str(self)}
        if self.path is not None:
            value["path"] = self.path
        if self.reference is not None:
            value["reference"] = self.reference
        return value


@dataclass(frozen=True, slots=True)
class InputLimits:
    """Inclusive limits applied while constructing one input closure."""

    max_entrypoint_bytes: int = 10_000_000
    max_total_bytes: int = 20 * 1024 * 1024
    max_files: int = 100
    max_reference_depth: int = 32
    max_document_nesting: int = 100
    max_yaml_aliases: int = 50

    def __post_init__(self) -> None:
        positive = {
            "max_entrypoint_bytes",
            "max_total_bytes",
            "max_files",
            "max_document_nesting",
        }
        for field in fields(self):
            value = getattr(self, field.name)
            minimum = 1 if field.name in positive else 0
            if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
                raise ValueError(f"{field.name} must be an integer >= {minimum}")


@dataclass(frozen=True, slots=True)
class InputFile:
    """Content identity recorded in an input manifest."""

    path: str
    size: int
    digest: str

    def to_dict(self) -> dict[str, str | int]:
        return {"path": self.path, "size": self.size, "digest": self.digest}


@dataclass(frozen=True, slots=True)
class InputResource:
    """Immutable bytes and identity for one repository file."""

    path: str
    content: bytes
    digest: str

    @property
    def size(self) -> int:
        return len(self.content)

    def manifest_file(self) -> InputFile:
        return InputFile(path=self.path, size=self.size, digest=self.digest)


@dataclass(frozen=True, slots=True)
class InputManifest:
    """Deterministic identity of every byte consumed by a scan."""

    entrypoints: tuple[str, ...]
    files: tuple[InputFile, ...]
    total_bytes: int
    digest: str
    schema_version: str = MANIFEST_SCHEMA_VERSION

    def content_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "entrypoints": list(self.entrypoints),
            "files": [item.to_dict() for item in self.files],
            "totalBytes": self.total_bytes,
        }

    def to_dict(self) -> dict[str, Any]:
        value = self.content_dict()
        value["digest"] = self.digest
        return value

    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.to_dict())


@dataclass(frozen=True, slots=True)
class InputClosure:
    """A manifest plus the closed immutable resource set it identifies."""

    manifest: InputManifest
    resources: tuple[InputResource, ...]

    def __post_init__(self) -> None:
        resource_files = tuple(item.manifest_file() for item in self.resources)
        if resource_files != self.manifest.files:
            raise ValueError("resources must exactly match the sorted manifest files")

    def resource_map(self) -> Mapping[str, bytes]:
        return MappingProxyType({item.path: item.content for item in self.resources})

    def read(self, path: str) -> bytes:
        for resource in self.resources:
            if resource.path == path:
                return resource.content
        raise KeyError(path)


class _DuplicateKeyError(ValueError):
    pass


class _StrictSafeLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _StrictSafeLoader,
    node: MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    if not isinstance(node, MappingNode):
        raise ConstructorError(None, None, "expected a mapping node", node.start_mark)

    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "YAML merge keys are not supported",
                key_node.start_mark,
            )
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as error:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable key",
                key_node.start_mark,
            ) from error
        if duplicate:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def build_input_closure(
    repository_root: str | os.PathLike[str],
    entrypoints: str | Iterable[str],
    *,
    limits: InputLimits | None = None,
) -> InputClosure:
    """Read entrypoints and their complete repository-local reference closure."""

    effective_limits = limits or InputLimits()
    root = _repository_root(repository_root)
    normalized_entrypoints = _normalize_entrypoints(entrypoints)

    if len(normalized_entrypoints) > effective_limits.max_files:
        raise InputClosureError(
            "file-count-limit",
            "entrypoints exceed the input-closure file-count limit",
        )

    entrypoint_set = frozenset(normalized_entrypoints)
    scheduled = {path: 0 for path in normalized_entrypoints}
    queue = [(0, path) for path in normalized_entrypoints]
    heapq.heapify(queue)
    resources: dict[str, InputResource] = {}
    total_bytes = 0

    while queue:
        depth, relative_path = heapq.heappop(queue)
        if relative_path in resources or scheduled[relative_path] != depth:
            continue

        size_limits = [
            (
                effective_limits.max_total_bytes - total_bytes,
                "total-bytes-limit",
                "input closure exceeds the aggregate byte limit",
            )
        ]
        if relative_path in entrypoint_set:
            size_limits.insert(
                0,
                (
                    effective_limits.max_entrypoint_bytes,
                    "entrypoint-bytes-limit",
                    "entrypoint exceeds the byte limit",
                ),
            )

        content = _read_stable_file(
            root,
            relative_path,
            size_limits=size_limits,
        )
        total_bytes += len(content)
        digest = f"sha256:{hashlib.sha256(content).hexdigest()}"
        resources[relative_path] = InputResource(
            path=relative_path,
            content=content,
            digest=digest,
        )

        document = _parse_document(
            relative_path,
            content,
            limits=effective_limits,
        )
        for reference in _collect_references(relative_path, document):
            target = _resolve_reference(relative_path, reference)
            if target is None or target in resources:
                continue

            next_depth = depth + 1
            previous_depth = scheduled.get(target)
            if previous_depth is not None and previous_depth <= next_depth:
                continue
            if next_depth > effective_limits.max_reference_depth:
                raise InputClosureError(
                    "reference-depth-limit",
                    "reference closure exceeds the reference-depth limit",
                    path=relative_path,
                    reference=reference,
                )
            if previous_depth is None and len(scheduled) >= effective_limits.max_files:
                raise InputClosureError(
                    "file-count-limit",
                    "input closure exceeds the file-count limit",
                    path=relative_path,
                    reference=reference,
                )
            scheduled[target] = next_depth
            heapq.heappush(queue, (next_depth, target))

    sorted_resources = tuple(resources[path] for path in sorted(resources))
    manifest_files = tuple(item.manifest_file() for item in sorted_resources)
    manifest_content = {
        "schemaVersion": MANIFEST_SCHEMA_VERSION,
        "entrypoints": list(normalized_entrypoints),
        "files": [item.to_dict() for item in manifest_files],
        "totalBytes": total_bytes,
    }
    manifest_hash = hashlib.sha256(_canonical_json(manifest_content)).hexdigest()
    manifest_digest = f"sha256:{manifest_hash}"
    manifest = InputManifest(
        entrypoints=normalized_entrypoints,
        files=manifest_files,
        total_bytes=total_bytes,
        digest=manifest_digest,
    )
    return InputClosure(manifest=manifest, resources=sorted_resources)


def build_input_manifest(
    repository_root: str | os.PathLike[str],
    entrypoints: str | Iterable[str],
    *,
    limits: InputLimits | None = None,
) -> InputManifest:
    """Build only the deterministic manifest for an input closure."""

    return build_input_closure(
        repository_root,
        entrypoints,
        limits=limits,
    ).manifest


def _repository_root(repository_root: str | os.PathLike[str]) -> Path:
    root = Path(repository_root)
    try:
        if root.is_symlink() or _is_junction(root):
            raise InputClosureError(
                "repository-root-link",
                "repository root must not be a symlink or junction",
            )
        resolved = root.resolve(strict=True)
    except InputClosureError:
        raise
    except (OSError, RuntimeError) as error:
        raise InputClosureError(
            "invalid-repository-root",
            "repository root does not exist or cannot be resolved",
        ) from error
    if not resolved.is_dir():
        raise InputClosureError(
            "invalid-repository-root",
            "repository root must be a directory",
        )
    return resolved


def _normalize_entrypoints(entrypoints: str | Iterable[str]) -> tuple[str, ...]:
    candidates = (entrypoints,) if isinstance(entrypoints, str) else tuple(entrypoints)
    if not candidates:
        raise InputClosureError(
            "missing-entrypoint",
            "at least one entrypoint is required",
        )

    normalized: set[str] = set()
    for candidate in candidates:
        if not isinstance(candidate, str):
            raise InputClosureError(
                "invalid-entrypoint",
                "entrypoints must be repository-relative strings",
            )
        split = _split_uri(candidate, path=None)
        if split.fragment or split.query:
            raise InputClosureError(
                "invalid-entrypoint",
                "entrypoints cannot contain a query or fragment",
                reference=candidate,
            )
        decoded = _decode_uri_path(split.path, path=None, reference=candidate)
        value = _normalize_relative_path((), decoded, reference=candidate)
        _require_supported_format(value, reference=candidate)
        normalized.add(value)
    return tuple(sorted(normalized))


def _read_stable_file(
    root: Path,
    relative_path: str,
    *,
    size_limits: Iterable[tuple[int, str, str]],
) -> bytes:
    candidate, resolved, pre_stat = _safe_file(root, relative_path)
    for maximum, code, message in size_limits:
        if maximum < 0 or pre_stat.st_size > maximum:
            raise InputClosureError(code, message, path=relative_path)

    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)

    try:
        descriptor = os.open(candidate, flags)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.EMLINK}:
            raise InputClosureError(
                "path-link",
                "input files cannot be symlinks or junctions",
                path=relative_path,
            ) from error
        raise InputClosureError(
            "concurrent-mutation",
            "input file changed before it could be opened",
            path=relative_path,
        ) from error

    try:
        opened_stat = os.fstat(descriptor)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise InputClosureError(
                "not-regular-file",
                "input path must identify a regular file",
                path=relative_path,
            )
        if not _same_file_state(pre_stat, opened_stat):
            raise InputClosureError(
                "concurrent-mutation",
                "input file changed while it was being opened",
                path=relative_path,
            )

        content = bytearray()
        while True:
            chunk = os.read(descriptor, _READ_BUFFER_BYTES)
            if not chunk:
                break
            content.extend(chunk)
            for maximum, code, message in size_limits:
                if len(content) > maximum:
                    raise InputClosureError(code, message, path=relative_path)

        completed_stat = os.fstat(descriptor)
        if len(content) != opened_stat.st_size or not _same_file_state(
            opened_stat,
            completed_stat,
        ):
            raise InputClosureError(
                "concurrent-mutation",
                "input file changed or was only partially read",
                path=relative_path,
            )
    finally:
        os.close(descriptor)

    try:
        _, post_resolved, post_stat = _safe_file(root, relative_path)
    except InputClosureError as error:
        raise InputClosureError(
            "concurrent-mutation",
            "input file changed after it was read",
            path=relative_path,
        ) from error
    if post_resolved != resolved or not _same_file_state(completed_stat, post_stat):
        raise InputClosureError(
            "concurrent-mutation",
            "input file identity changed after it was read",
            path=relative_path,
        )
    return bytes(content)


def _safe_file(root: Path, relative_path: str) -> tuple[Path, Path, os.stat_result]:
    candidate = root.joinpath(*PurePosixPath(relative_path).parts)
    current = root
    for part in PurePosixPath(relative_path).parts:
        try:
            directory_entries = os.listdir(current)
        except OSError as error:
            raise InputClosureError(
                "unreadable-file",
                "input file cannot be inspected safely",
                path=relative_path,
            ) from error
        if part not in directory_entries and any(
            entry.casefold() == part.casefold() for entry in directory_entries
        ):
            raise InputClosureError(
                "path-case-mismatch",
                "input path casing does not match the repository entry",
                path=relative_path,
            )
        current /= part
        try:
            path_stat = os.stat(current, follow_symlinks=False)
        except FileNotFoundError as error:
            raise InputClosureError(
                "missing-file",
                "referenced input file does not exist",
                path=relative_path,
            ) from error
        except OSError as error:
            raise InputClosureError(
                "unreadable-file",
                "input file cannot be inspected safely",
                path=relative_path,
            ) from error
        if stat.S_ISLNK(path_stat.st_mode) or _is_junction(current):
            raise InputClosureError(
                "path-link",
                "input paths cannot contain symlinks or junctions",
                path=relative_path,
            )

    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except ValueError as error:
        raise InputClosureError(
            "path-escape",
            "input path escapes the repository root",
            path=relative_path,
        ) from error
    except (OSError, RuntimeError) as error:
        raise InputClosureError(
            "unreadable-file",
            "input file cannot be resolved safely",
            path=relative_path,
        ) from error

    try:
        final_stat = os.stat(candidate, follow_symlinks=False)
    except OSError as error:
        raise InputClosureError(
            "unreadable-file",
            "input file cannot be inspected safely",
            path=relative_path,
        ) from error
    if not stat.S_ISREG(final_stat.st_mode):
        raise InputClosureError(
            "not-regular-file",
            "input path must identify a regular file",
            path=relative_path,
        )
    return candidate, resolved, final_stat


def _same_file_state(left: os.stat_result, right: os.stat_result) -> bool:
    left_change_time = None if os.name == "nt" else left.st_ctime_ns
    right_change_time = None if os.name == "nt" else right.st_ctime_ns
    return (
        left.st_dev,
        left.st_ino,
        left.st_size,
        left.st_mtime_ns,
        left_change_time,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_size,
        right.st_mtime_ns,
        right_change_time,
    )


def _is_junction(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", None)
    if is_junction is None:
        return False
    try:
        return bool(is_junction())
    except OSError:
        return False


def _parse_document(
    relative_path: str,
    content: bytes,
    *,
    limits: InputLimits,
) -> Any:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise InputClosureError(
            "invalid-utf8",
            "input document must be strict UTF-8",
            path=relative_path,
        ) from error

    suffix = PurePosixPath(relative_path).suffix.lower()
    try:
        if suffix == ".json":
            document = json.loads(
                text,
                object_pairs_hook=_unique_json_object,
                parse_constant=_reject_json_constant,
            )
        else:
            alias_count = sum(
                isinstance(event, AliasEvent)
                for event in yaml.parse(text, Loader=yaml.SafeLoader)
            )
            if alias_count > limits.max_yaml_aliases:
                raise InputClosureError(
                    "yaml-alias-limit",
                    "input document exceeds the YAML alias limit",
                    path=relative_path,
                )
            documents = list(yaml.load_all(text, Loader=_StrictSafeLoader))
            if len(documents) != 1:
                raise InputClosureError(
                    "multiple-yaml-documents",
                    "exactly one YAML document is required",
                    path=relative_path,
                )
            document = documents[0]
    except InputClosureError:
        raise
    except (
        _DuplicateKeyError,
        json.JSONDecodeError,
        yaml.YAMLError,
        RecursionError,
    ) as error:
        raise InputClosureError(
            "invalid-document",
            "input document is not valid strict JSON or YAML",
            path=relative_path,
        ) from error

    _assert_json_compatible(
        relative_path,
        document,
        max_depth=limits.max_document_nesting,
    )
    return document


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateKeyError(key)
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise _DuplicateKeyError(value)


def _assert_json_compatible(
    relative_path: str,
    value: Any,
    *,
    max_depth: int,
) -> None:
    subtree_depths: dict[int, int] = {}
    active: set[int] = set()

    def visit(item: Any, depth: int) -> int:
        if depth > max_depth:
            raise InputClosureError(
                "document-nesting-limit",
                "input document exceeds the nesting limit",
                path=relative_path,
            )
        if item is None or isinstance(item, (str, bool, int)):
            return 0
        if isinstance(item, float):
            if math.isfinite(item):
                return 0
            raise InputClosureError(
                "non-json-value",
                "input document contains a non-finite number",
                path=relative_path,
            )
        if not isinstance(item, (dict, list)):
            raise InputClosureError(
                "non-json-value",
                "YAML input must contain only JSON-compatible values",
                path=relative_path,
            )

        identity = id(item)
        if identity in active:
            raise InputClosureError(
                "document-cycle",
                "input document contains a recursive alias cycle",
                path=relative_path,
            )
        cached_depth = subtree_depths.get(identity)
        if cached_depth is not None:
            if depth + cached_depth > max_depth:
                raise InputClosureError(
                    "document-nesting-limit",
                    "input document exceeds the nesting limit",
                    path=relative_path,
                )
            return cached_depth

        active.add(identity)
        subtree_depth = 0
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise InputClosureError(
                        "non-json-value",
                        "object keys must be strings",
                        path=relative_path,
                    )
                subtree_depth = max(subtree_depth, visit(child, depth + 1) + 1)
        else:
            for child in item:
                subtree_depth = max(subtree_depth, visit(child, depth + 1) + 1)
        active.remove(identity)
        subtree_depths[identity] = subtree_depth
        return subtree_depth

    visit(value, 0)


def _collect_references(relative_path: str, document: Any) -> tuple[str, ...]:
    references: set[str] = set()
    visited: set[int] = set()

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            identity = id(value)
            if identity in visited:
                return
            visited.add(identity)
            for key, item in value.items():
                if key == "$ref":
                    if not isinstance(item, str):
                        raise InputClosureError(
                            "invalid-reference",
                            "$ref values must be strings",
                            path=relative_path,
                        )
                    references.add(item)
                visit(item)
        elif isinstance(value, list):
            identity = id(value)
            if identity in visited:
                return
            visited.add(identity)
            for item in value:
                visit(item)

    visit(document)
    return tuple(sorted(references))


def _resolve_reference(relative_path: str, reference: str) -> str | None:
    if reference == "":
        return None
    split = _split_uri(reference, path=relative_path)
    if not split.path:
        return None
    decoded = _decode_uri_path(
        split.path,
        path=relative_path,
        reference=reference,
    )
    base_parts = PurePosixPath(relative_path).parent.parts
    target = _normalize_relative_path(
        base_parts,
        decoded,
        path=relative_path,
        reference=reference,
    )
    _require_supported_format(target, path=relative_path, reference=reference)
    return target


def _split_uri(reference: str, *, path: str | None):
    if not reference or "\x00" in reference or "\\" in reference:
        raise InputClosureError(
            "invalid-reference",
            "reference must use a non-empty repository-relative URI path",
            path=path,
            reference=reference,
        )
    try:
        split = urlsplit(reference)
    except ValueError as error:
        raise InputClosureError(
            "invalid-reference",
            "reference is not a valid URI reference",
            path=path,
            reference=reference,
        ) from error
    if split.scheme or split.netloc or split.path.startswith("/"):
        raise InputClosureError(
            "unsupported-reference",
            "remote and absolute references are not supported",
            path=path,
            reference=reference,
        )
    if split.query:
        raise InputClosureError(
            "unsupported-reference",
            "reference query components are not supported",
            path=path,
            reference=reference,
        )
    return split


def _decode_uri_path(
    raw_path: str,
    *,
    path: str | None,
    reference: str,
) -> str:
    if _INVALID_PERCENT_ESCAPE.search(raw_path):
        raise InputClosureError(
            "invalid-reference",
            "reference contains an invalid percent escape",
            path=path,
            reference=reference,
        )
    try:
        decoded = unquote_to_bytes(raw_path).decode("utf-8")
    except UnicodeDecodeError as error:
        raise InputClosureError(
            "invalid-reference",
            "reference path must decode as UTF-8",
            path=path,
            reference=reference,
        ) from error
    if "\x00" in decoded or "\\" in decoded or _WINDOWS_DRIVE.match(decoded):
        raise InputClosureError(
            "unsupported-reference",
            "reference path is not a portable repository-relative path",
            path=path,
            reference=reference,
        )
    return decoded


def _normalize_relative_path(
    base_parts: Iterable[str],
    raw_path: str,
    *,
    path: str | None = None,
    reference: str,
) -> str:
    parts = list(base_parts)
    for part in PurePosixPath(raw_path).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                raise InputClosureError(
                    "path-escape",
                    "reference escapes the repository root",
                    path=path,
                    reference=reference,
                )
            parts.pop()
            continue
        if (
            part in {"/", "\\"}
            or ":" in part
            or part.endswith((" ", "."))
            or _WINDOWS_DEVICE.match(part)
            or any(ord(character) < 32 for character in part)
        ):
            raise InputClosureError(
                "unsupported-reference",
                "reference contains a non-portable path segment",
                path=path,
                reference=reference,
            )
        parts.append(part)
    if not parts:
        raise InputClosureError(
            "invalid-reference",
            "reference does not identify a repository file",
            path=path,
            reference=reference,
        )
    return PurePosixPath(*parts).as_posix()


def _require_supported_format(
    relative_path: str,
    *,
    path: str | None = None,
    reference: str,
) -> None:
    if PurePosixPath(relative_path).suffix.lower() not in _SUPPORTED_SUFFIXES:
        raise InputClosureError(
            "unsupported-format",
            "input files must use .json, .yaml, or .yml",
            path=path or relative_path,
            reference=reference,
        )


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
