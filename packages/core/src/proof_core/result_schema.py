"""Runtime validation for the packaged normalized-result contract."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from functools import cache
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

_SCHEMA_PACKAGE = "proof_contracts.schemas.result.v1"
_SCHEMA_NAMES = (
    "common.schema.json",
    "finding.schema.json",
    "gate.schema.json",
    "provenance.schema.json",
    "run.schema.json",
)
_SCHEMA_ID_PREFIX = "https://specargus.github.io/PROOF/schemas/result/v1/"


class ResultSchemaError(ValueError):
    """A stable, sanitized normalized-result schema failure."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        pointer: str = "",
        keyword: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.pointer = pointer
        self.keyword = keyword


def validate_normalized_run(instance: Mapping[str, object]) -> None:
    """Validate one normalized run against the packaged result/v1 contract.

    Validation failures deliberately expose only a JSON Pointer and the trusted
    schema keyword. The rejected value and package location never cross this
    runtime boundary.
    """

    if not isinstance(instance, Mapping):
        raise ResultSchemaError(
            "result-schema.invalid-run",
            "normalized run does not satisfy result schema",
            keyword="type",
        )

    try:
        errors = sorted(
            _validator().iter_errors(dict(instance)),
            key=_error_sort_key,
        )
    except ResultSchemaError:
        raise
    except Exception:
        raise ResultSchemaError(
            "result-schema.validation-unavailable",
            "normalized run schema validation is unavailable",
        ) from None

    if not errors:
        return

    error = errors[0]
    raise ResultSchemaError(
        "result-schema.invalid-run",
        "normalized run does not satisfy result schema",
        pointer=_json_pointer(error.absolute_path),
        keyword=str(error.validator),
    ) from None


@cache
def _validator() -> Draft202012Validator:
    try:
        package = files(_SCHEMA_PACKAGE)
        schemas: dict[str, dict[str, Any]] = {}
        registry = Registry()
        for name in _SCHEMA_NAMES:
            schema = json.loads(package.joinpath(name).read_text(encoding="utf-8"))
            if not isinstance(schema, dict):
                raise TypeError
            expected_identifier = f"{_SCHEMA_ID_PREFIX}{name}"
            if schema.get("$id") != expected_identifier:
                raise ValueError
            Draft202012Validator.check_schema(schema)
            registry = registry.with_resource(
                expected_identifier,
                Resource.from_contents(schema),
            )
            schemas[name] = schema
        return Draft202012Validator(
            schemas["run.schema.json"],
            registry=registry,
            format_checker=FormatChecker(),
        )
    except Exception:
        raise ResultSchemaError(
            "result-schema.registry-unavailable",
            "normalized run schema registry is unavailable",
        ) from None


def _error_sort_key(error: Any) -> tuple[tuple[str, ...], tuple[str, ...], str]:
    return (
        tuple(str(part) for part in error.absolute_path),
        tuple(str(part) for part in error.absolute_schema_path),
        str(error.validator),
    )


def _json_pointer(parts: Iterable[object]) -> str:
    encoded = [str(part).replace("~", "~0").replace("/", "~1") for part in parts]
    return "" if not encoded else "/" + "/".join(encoded)
