"""Versioned, deterministic scan configuration shared by every execution surface."""

from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, fields
from importlib.resources import files
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Literal

from jsonschema import Draft202012Validator
from proof_rulepack import AGENT_CONTRACT_IDENTITY, RulePackIdentity

from proof_core.canonical_json import CanonicalJsonError, canonical_json_bytes
from proof_core.input_closure import (
    DocumentLimits,
    InputClosureError,
    parse_repository_document,
    read_repository_resource,
)

CONFIGURATION_SCHEMA_VERSION = "1.0.0"
DEFAULT_FAIL_ON = "high"
DEFAULT_SCOPE = "all"
DEFAULT_CONFIGURATION_PATH = "proof.yaml"
_SUPPORTED_SUFFIXES = frozenset({".json", ".yaml", ".yml"})
_FAIL_ON_VALUES = frozenset({"error", "high", "medium", "low", "none"})
_EXTENSION_NAME = re.compile(r"^x-[a-z0-9][a-z0-9._-]*$")
_WINDOWS_DEVICE = re.compile(
    r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$",
    re.IGNORECASE,
)
_VCS_DIRECTORIES = frozenset({".git", ".hg", ".svn"})

type FailOn = Literal["error", "high", "medium", "low", "none"]
type JsonValue = (
    None | bool | int | float | str | list[JsonValue] | dict[str, JsonValue]
)


class ConfigurationError(ValueError):
    """A stable, sanitized scan-configuration failure."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        path: str | None = None,
        pointer: str = "",
        source_digest: str | None = None,
        configuration_digest: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.path = path if _is_safe_source_path(path) else None
        self.pointer = pointer
        self.source_digest = source_digest
        self.configuration_digest = configuration_digest or _attempt_digest(
            source_state="unavailable"
        )

    def to_terminal_error(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "code": self.code,
            "kind": "configuration",
            "message": str(self),
            "retryable": False,
        }
        if self.path is not None:
            result["location"] = {"path": self.path, "pointer": self.pointer}
        return result

    def provenance_dict(self) -> dict[str, str]:
        """Return the content identity required for a failed run."""

        return {"digest": self.configuration_digest}


@dataclass(frozen=True, slots=True)
class ConfigurationLimits:
    """Pinned safety ceilings for configuration loading and matching."""

    max_bytes: int = 256 * 1024
    max_nesting: int = 32
    max_yaml_aliases: int = 20
    max_patterns: int = 32
    max_candidates: int = 10_000
    max_matches: int = 100
    max_path_depth: int = 32

    def __post_init__(self) -> None:
        for item in fields(self):
            value = getattr(self, item.name)
            minimum = 0 if item.name == "max_yaml_aliases" else 1
            if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
                raise ValueError(f"{item.name} must be an integer >= {minimum}")


@dataclass(frozen=True, slots=True)
class ScanConfigurationOverrides:
    """Explicit local-invocation overrides; absent values do not override."""

    specifications: tuple[str, ...] | None = None
    rule_pack: RulePackIdentity | None = None
    fail_on: FailOn | None = None


@dataclass(frozen=True, slots=True)
class EffectiveScanConfiguration:
    """The immutable analysis policy consumed by CLI and hosted workers."""

    specifications: tuple[str, ...]
    rule_pack: RulePackIdentity
    fail_on: FailOn
    extensions: Mapping[str, JsonValue] = field(repr=False)
    schema_version: str = CONFIGURATION_SCHEMA_VERSION
    scope: Literal["all"] = DEFAULT_SCOPE
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        if self.schema_version != CONFIGURATION_SCHEMA_VERSION:
            raise ConfigurationError(
                "configuration.unsupported-version",
                "configuration schemaVersion is not supported",
            )
        if self.scope != DEFAULT_SCOPE:
            raise ConfigurationError(
                "configuration.invalid-scope",
                "scope must be all for configuration v1",
            )
        if self.fail_on not in _FAIL_ON_VALUES:
            raise ConfigurationError(
                "configuration.invalid-fail-on",
                "failOn must be a supported severity or none",
            )
        if self.rule_pack != AGENT_CONTRACT_IDENTITY:
            raise ConfigurationError(
                "configuration.unsupported-rulepack",
                "effective configuration must use a supported rule pack",
            )
        normalized_patterns = _normalize_patterns(
            self.specifications,
            limit=ConfigurationLimits().max_patterns,
            path=None,
            source_digest=None,
        )
        if self.specifications != normalized_patterns:
            raise ConfigurationError(
                "configuration.non-canonical",
                "effective specification selectors must be sorted and unique",
            )
        if not isinstance(self.extensions, Mapping) or any(
            not isinstance(key, str) or not _EXTENSION_NAME.fullmatch(key)
            for key in self.extensions
        ):
            raise ConfigurationError(
                "configuration.invalid-extension",
                "effective configuration extensions must use namespaced x- fields",
            )
        frozen = MappingProxyType(
            {key: _freeze_json(value) for key, value in sorted(self.extensions.items())}
        )
        object.__setattr__(self, "extensions", frozen)
        try:
            digest = _sha256(self.canonical_bytes())
        except CanonicalJsonError as error:
            raise ConfigurationError(
                "configuration.non-canonical",
                "configuration contains a value outside the canonical JSON domain",
            ) from error
        object.__setattr__(self, "digest", digest)

    def content_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schemaVersion": self.schema_version,
            "specifications": list(self.specifications),
            "rulePack": self.rule_pack.to_dict(),
            "failOn": self.fail_on,
            "scope": self.scope,
        }
        result.update(
            {key: _thaw_json(value) for key, value in self.extensions.items()}
        )
        return result

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.content_dict())

    def provenance_dict(self) -> dict[str, str]:
        return {"digest": self.digest}


def load_scan_configuration(
    repository_root: str | os.PathLike[str],
    path: str = DEFAULT_CONFIGURATION_PATH,
    *,
    limits: ConfigurationLimits | None = None,
    supported_rulepacks: Iterable[RulePackIdentity] = (AGENT_CONTRACT_IDENTITY,),
) -> EffectiveScanConfiguration:
    """Load, validate, default, and canonicalize one repository configuration."""

    effective_limits = limits or ConfigurationLimits()
    try:
        resource = read_repository_resource(
            repository_root,
            path,
            max_bytes=effective_limits.max_bytes,
        )
    except InputClosureError as error:
        raise _from_input_error(error) from error

    try:
        document = parse_repository_document(
            resource,
            limits=DocumentLimits(
                max_bytes=effective_limits.max_bytes,
                max_document_nesting=effective_limits.max_nesting,
                max_yaml_aliases=effective_limits.max_yaml_aliases,
            ),
        )
    except InputClosureError as error:
        raise _from_input_error(error, source_digest=resource.digest) from error

    return resolve_scan_configuration(
        document.value,
        path=resource.path,
        source_digest=resource.digest,
        limits=effective_limits,
        supported_rulepacks=supported_rulepacks,
    )


def load_local_scan_configuration(
    repository_root: str | os.PathLike[str],
    path: str = DEFAULT_CONFIGURATION_PATH,
    *,
    overrides: ScanConfigurationOverrides | None = None,
    limits: ConfigurationLimits | None = None,
    supported_rulepacks: Iterable[RulePackIdentity] = (AGENT_CONTRACT_IDENTITY,),
) -> EffectiveScanConfiguration:
    """Load configuration with overrides authorized by a local CLI invocation."""

    effective_limits = limits or ConfigurationLimits()
    try:
        resource = read_repository_resource(
            repository_root,
            path,
            max_bytes=effective_limits.max_bytes,
        )
    except InputClosureError as error:
        raise _from_input_error(error, overrides=overrides) from error
    try:
        document = parse_repository_document(
            resource,
            limits=DocumentLimits(
                max_bytes=effective_limits.max_bytes,
                max_document_nesting=effective_limits.max_nesting,
                max_yaml_aliases=effective_limits.max_yaml_aliases,
            ),
        )
    except InputClosureError as error:
        raise _from_input_error(
            error,
            source_digest=resource.digest,
            overrides=overrides,
        ) from error
    return resolve_local_scan_configuration(
        document.value,
        path=resource.path,
        source_digest=resource.digest,
        overrides=overrides,
        limits=effective_limits,
        supported_rulepacks=supported_rulepacks,
    )


def resolve_scan_configuration(
    document: Any,
    *,
    path: str | None = None,
    source_digest: str | None = None,
    limits: ConfigurationLimits | None = None,
    supported_rulepacks: Iterable[RulePackIdentity] = (AGENT_CONTRACT_IDENTITY,),
) -> EffectiveScanConfiguration:
    """Resolve trusted source policy without accepting invocation overrides."""

    return _resolve_scan_configuration(
        document,
        path=path,
        source_digest=source_digest,
        limits=limits,
        supported_rulepacks=supported_rulepacks,
    )


def resolve_local_scan_configuration(
    document: Any,
    *,
    path: str | None = None,
    source_digest: str | None = None,
    overrides: ScanConfigurationOverrides | None = None,
    limits: ConfigurationLimits | None = None,
    supported_rulepacks: Iterable[RulePackIdentity] = (AGENT_CONTRACT_IDENTITY,),
) -> EffectiveScanConfiguration:
    """Resolve policy with explicit overrides authorized by the local CLI."""

    return _resolve_scan_configuration(
        document,
        path=path,
        source_digest=source_digest,
        overrides=overrides,
        limits=limits,
        supported_rulepacks=supported_rulepacks,
    )


def _resolve_scan_configuration(
    document: Any,
    *,
    path: str | None,
    source_digest: str | None,
    overrides: ScanConfigurationOverrides | None = None,
    limits: ConfigurationLimits | None,
    supported_rulepacks: Iterable[RulePackIdentity],
) -> EffectiveScanConfiguration:
    """Validate and materialize one effective configuration."""

    effective_limits = limits or ConfigurationLimits()
    configuration_digest = _attempt_digest(
        document=document,
        source_path=path,
        source_digest=source_digest,
        overrides=overrides,
    )
    try:
        canonical_json_bytes(document)
    except CanonicalJsonError as error:
        raise ConfigurationError(
            "configuration.non-canonical",
            "configuration contains a value outside the canonical JSON domain",
            path=path,
            source_digest=source_digest,
            configuration_digest=configuration_digest,
        ) from error
    _validate_document(
        document,
        path=path,
        source_digest=source_digest,
        configuration_digest=configuration_digest,
    )
    assert isinstance(document, dict)

    source_specs = tuple(document["specifications"])
    source_identity = _identity(document["rulePack"])
    candidate_specs = (
        overrides.specifications
        if overrides is not None and overrides.specifications is not None
        else source_specs
    )
    candidate_identity = (
        overrides.rule_pack
        if overrides is not None and overrides.rule_pack is not None
        else source_identity
    )
    candidate_fail_on = (
        overrides.fail_on
        if overrides is not None and overrides.fail_on is not None
        else document.get("failOn", DEFAULT_FAIL_ON)
    )

    specifications = _normalize_patterns(
        candidate_specs,
        limit=effective_limits.max_patterns,
        path=path,
        source_digest=source_digest,
        configuration_digest=configuration_digest,
    )
    if not isinstance(candidate_identity, RulePackIdentity):
        raise ConfigurationError(
            "configuration.invalid-rulepack",
            "rulePack override must be an exact artifact identity",
            path=path,
            pointer="/rulePack",
            source_digest=source_digest,
            configuration_digest=configuration_digest,
        )
    if candidate_fail_on not in _FAIL_ON_VALUES:
        raise ConfigurationError(
            "configuration.invalid-fail-on",
            "failOn must be a supported severity or none",
            path=path,
            pointer="/failOn",
            source_digest=source_digest,
            configuration_digest=configuration_digest,
        )
    _require_supported_rulepack(
        candidate_identity,
        supported_rulepacks,
        path=path,
        source_digest=source_digest,
        configuration_digest=configuration_digest,
    )
    extensions = {
        key: value for key, value in document.items() if _EXTENSION_NAME.fullmatch(key)
    }
    return EffectiveScanConfiguration(
        specifications=specifications,
        rule_pack=candidate_identity,
        fail_on=candidate_fail_on,
        extensions=extensions,
    )


def match_specifications(
    repository_root: str | os.PathLike[str],
    configuration: EffectiveScanConfiguration,
    *,
    limits: ConfigurationLimits | None = None,
) -> tuple[str, ...]:
    """Expand selectors with deterministic, case-sensitive POSIX semantics."""

    effective_limits = limits or ConfigurationLimits()
    try:
        candidates = _repository_candidates(repository_root, effective_limits)
    except ConfigurationError as error:
        raise ConfigurationError(
            error.code,
            str(error),
            path=error.path,
            pointer=error.pointer,
            source_digest=error.source_digest,
            configuration_digest=configuration.digest,
        ) from error
    selected: set[str] = set()
    for pattern in configuration.specifications:
        matches = tuple(
            candidate
            for candidate in candidates
            if PurePosixPath(candidate).full_match(pattern, case_sensitive=True)
        )
        if not matches:
            raise ConfigurationError(
                "configuration.no-specification-match",
                "a specification selector did not match any supported file",
                pointer="/specifications",
                configuration_digest=configuration.digest,
            )
        selected.update(matches)
        if len(selected) > effective_limits.max_matches:
            raise ConfigurationError(
                "configuration.specification-match-limit",
                "specification matches exceed the configured safety limit",
                pointer="/specifications",
                configuration_digest=configuration.digest,
            )
    return tuple(sorted(selected))


def _configuration_schema() -> dict[str, Any]:
    schema_path = files("proof_contracts.schemas.config.v1").joinpath(
        "config.schema.json"
    )
    return json.loads(schema_path.read_text(encoding="utf-8"))


_VALIDATOR = Draft202012Validator(_configuration_schema())


def _validate_document(
    document: Any,
    *,
    path: str | None,
    source_digest: str | None,
    configuration_digest: str,
) -> None:
    errors = sorted(
        _VALIDATOR.iter_errors(document),
        key=lambda item: (
            tuple(str(part) for part in item.absolute_path),
            item.validator,
        ),
    )
    if not errors:
        return
    error = errors[0]
    pointer = _json_pointer(error.absolute_path)
    code, message = _schema_error(error.validator, pointer)
    raise ConfigurationError(
        code,
        message,
        path=path,
        pointer=pointer,
        source_digest=source_digest,
        configuration_digest=configuration_digest,
    )


def _schema_error(validator: str, pointer: str) -> tuple[str, str]:
    if pointer == "/schemaVersion":
        return (
            "configuration.unsupported-version",
            "configuration schemaVersion is not supported",
        )
    if validator == "additionalProperties":
        return (
            "configuration.unknown-field",
            "configuration contains an unknown standard field",
        )
    if validator == "required":
        return (
            "configuration.missing-field",
            "configuration is missing a required field",
        )
    if pointer == "/specifications" and validator == "minItems":
        return (
            "configuration.empty-specifications",
            "configuration must select at least one specification",
        )
    if pointer == "/specifications" and validator == "uniqueItems":
        return (
            "configuration.duplicate-specification",
            "configuration specification selectors must be unique",
        )
    if pointer.startswith("/specifications"):
        return (
            "configuration.invalid-selector",
            "configuration contains an invalid specification selector",
        )
    return "configuration.invalid-field", "configuration contains an invalid field"


def _identity(value: Mapping[str, str]) -> RulePackIdentity:
    return RulePackIdentity(value["name"], value["version"], value["digest"])


def _require_supported_rulepack(
    identity: RulePackIdentity,
    supported: Iterable[RulePackIdentity],
    *,
    path: str | None,
    source_digest: str | None,
    configuration_digest: str,
) -> None:
    candidates = tuple(supported)
    same_release = tuple(
        item
        for item in candidates
        if item.name == identity.name and item.version == identity.version
    )
    if not same_release:
        raise ConfigurationError(
            "configuration.unsupported-rulepack",
            "configuration selects an unsupported rule-pack release",
            path=path,
            pointer="/rulePack",
            source_digest=source_digest,
            configuration_digest=configuration_digest,
        )
    if identity not in same_release:
        raise ConfigurationError(
            "configuration.rulepack-digest-mismatch",
            "configuration rule-pack digest does not match the supported release",
            path=path,
            pointer="/rulePack/digest",
            source_digest=source_digest,
            configuration_digest=configuration_digest,
        )


def _normalize_patterns(
    patterns: Iterable[str],
    *,
    limit: int,
    path: str | None,
    source_digest: str | None,
    configuration_digest: str | None = None,
) -> tuple[str, ...]:
    if isinstance(patterns, (str, bytes)):
        raise ConfigurationError(
            "configuration.invalid-selector",
            "configuration selectors must be a sequence of paths",
            path=path,
            pointer="/specifications",
            source_digest=source_digest,
            configuration_digest=configuration_digest,
        )
    values = tuple(patterns)
    if not values:
        raise ConfigurationError(
            "configuration.empty-specifications",
            "configuration must select at least one specification",
            path=path,
            pointer="/specifications",
            source_digest=source_digest,
            configuration_digest=configuration_digest,
        )
    if len(values) > limit:
        raise ConfigurationError(
            "configuration.specification-pattern-limit",
            "configuration has too many specification selectors",
            path=path,
            pointer="/specifications",
            source_digest=source_digest,
            configuration_digest=configuration_digest,
        )
    for value in values:
        if not isinstance(value, str) or not _valid_pattern(value):
            raise ConfigurationError(
                "configuration.invalid-selector",
                "configuration contains an invalid specification selector",
                path=path,
                pointer="/specifications",
                source_digest=source_digest,
                configuration_digest=configuration_digest,
            )
    return tuple(sorted(set(values)))


def _valid_pattern(value: str) -> bool:
    if (
        not value
        or len(value) > 512
        or value.startswith("/")
        or "\\" in value
        or ":" in value
        or "%" in value
        or "#" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or any(character in value for character in "[]{}")
        or PurePosixPath(value).suffix not in _SUPPORTED_SUFFIXES
    ):
        return False
    segments = value.split("/")
    if any(
        not segment
        or segment in {".", ".."}
        or segment.endswith((" ", "."))
        or _WINDOWS_DEVICE.fullmatch(segment)
        for segment in segments
    ):
        return False
    return True


def _repository_candidates(
    repository_root: str | os.PathLike[str], limits: ConfigurationLimits
) -> tuple[str, ...]:
    root = Path(repository_root)
    try:
        if root.is_symlink() or _is_junction(root):
            raise OSError
        root = root.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ConfigurationError(
            "configuration.invalid-repository-root",
            "repository root cannot be inspected safely",
        ) from error
    if not root.is_dir():
        raise ConfigurationError(
            "configuration.invalid-repository-root",
            "repository root cannot be inspected safely",
        )

    candidates: list[str] = []
    inspected_entries = 0

    def visit(directory: Path, relative: PurePosixPath, depth: int) -> None:
        nonlocal inspected_entries
        if depth > limits.max_path_depth:
            raise ConfigurationError(
                "configuration.repository-depth-limit",
                "repository tree exceeds the configured depth limit",
            )
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as error:
            raise ConfigurationError(
                "configuration.unreadable-repository",
                "repository tree cannot be inspected safely",
            ) from error
        for entry in entries:
            inspected_entries += 1
            if inspected_entries > limits.max_candidates:
                raise ConfigurationError(
                    "configuration.repository-candidate-limit",
                    "repository contains too many entries to inspect safely",
                )
            child_relative = relative / entry.name
            if entry.name in _VCS_DIRECTORIES:
                continue
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise ConfigurationError(
                    "configuration.unreadable-repository",
                    "repository tree cannot be inspected safely",
                ) from error
            child = Path(entry.path)
            if stat.S_ISLNK(info.st_mode) or _is_junction(child):
                continue
            if stat.S_ISDIR(info.st_mode):
                visit(child, child_relative, depth + 1)
            elif stat.S_ISREG(info.st_mode):
                if child_relative.suffix in _SUPPORTED_SUFFIXES:
                    candidates.append(child_relative.as_posix())

    visit(root, PurePosixPath(), 0)
    return tuple(candidates)


def _is_junction(path: Path) -> bool:
    predicate = getattr(path, "is_junction", None)
    if predicate is None:
        return False
    try:
        return bool(predicate())
    except OSError:
        return True


def _json_pointer(parts: Iterable[Any]) -> str:
    encoded = [str(part).replace("~", "~0").replace("/", "~1") for part in parts]
    return "" if not encoded else "/" + "/".join(encoded)


def _from_input_error(
    error: InputClosureError,
    *,
    source_digest: str | None = None,
    overrides: ScanConfigurationOverrides | None = None,
) -> ConfigurationError:
    code = f"configuration.{error.code}"
    message = {
        "missing-file": "configuration file does not exist",
        "invalid-document": "configuration is not valid strict JSON or YAML",
        "invalid-utf8": "configuration must be strict UTF-8",
        "utf8-bom": "configuration must use UTF-8 without a byte-order mark",
        "multiple-yaml-documents": "configuration must contain exactly one document",
    }.get(error.code, "configuration file cannot be loaded safely")
    return ConfigurationError(
        code,
        message,
        path=error.path,
        source_digest=source_digest,
        configuration_digest=_attempt_digest(
            source_state="available" if source_digest is not None else "unavailable",
            source_path=error.path,
            source_digest=source_digest,
            overrides=overrides,
        ),
    )


def _attempt_digest(
    *,
    document: Any = None,
    source_state: str | None = None,
    source_path: str | None = None,
    source_digest: str | None = None,
    overrides: ScanConfigurationOverrides | None = None,
) -> str:
    """Identify a configuration attempt without retaining source or override data."""

    if source_state is None:
        source_state = "available" if source_digest is not None else "parsed"
    source: dict[str, str] = {"state": source_state}
    if source_digest is not None:
        source["digest"] = source_digest
    elif source_state == "parsed":
        try:
            source["digest"] = _sha256(canonical_json_bytes(document))
        except CanonicalJsonError:
            source["state"] = "non-canonical"
    if _is_safe_source_path(source_path):
        source["pathDigest"] = _sha256(source_path.encode("utf-8"))

    override_projection: dict[str, str] = {"state": "absent"}
    if overrides is not None:
        try:
            value: dict[str, Any] = {}
            if overrides.specifications is not None:
                value["specifications"] = list(overrides.specifications)
            if overrides.rule_pack is not None:
                value["rulePack"] = overrides.rule_pack.to_dict()
            if overrides.fail_on is not None:
                value["failOn"] = overrides.fail_on
            override_projection = {
                "state": "available",
                "digest": _sha256(canonical_json_bytes(value)),
            }
        except (AttributeError, CanonicalJsonError, TypeError):
            override_projection = {"state": "invalid"}

    projection = {
        "attemptVersion": 1,
        "source": source,
        "localOverrides": override_projection,
    }
    return _sha256(canonical_json_bytes(projection))


def _is_safe_source_path(path: str | None) -> bool:
    if path is None:
        return False
    if (
        not isinstance(path, str)
        or not path
        or path.startswith("/")
        or "\\" in path
        or ":" in path
        or any(ord(character) < 32 or ord(character) == 127 for character in path)
    ):
        return False
    parts = path.split("/")
    return not any(
        not part
        or part in {".", ".."}
        or part.endswith((" ", "."))
        or _WINDOWS_DEVICE.fullmatch(part)
        for part in parts
    )


def _freeze_json(value: JsonValue) -> Any:
    if isinstance(value, dict):
        return MappingProxyType(
            {key: _freeze_json(item) for key, item in sorted(value.items())}
        )
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: Any) -> JsonValue:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _sha256(content: bytes) -> str:
    import hashlib

    return f"sha256:{hashlib.sha256(content).hexdigest()}"
