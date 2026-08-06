from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from proof_core import (
    InputClosureError,
    InputLimits,
    build_input_closure,
    build_input_manifest,
)
from proof_core import input_closure as input_closure_module


def write(path: Path, content: str | bytes) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = content.encode("utf-8") if isinstance(content, str) else content
    path.write_bytes(data)
    return data


def openapi_json(**extra: object) -> str:
    value: dict[str, object] = {
        "openapi": "3.1.0",
        "info": {"title": "Example", "version": "1.0.0"},
        "paths": {},
    }
    value.update(extra)
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def limits(**overrides: int) -> InputLimits:
    values = {
        "max_entrypoint_bytes": 10_000,
        "max_total_bytes": 20_000,
        "max_files": 10,
        "max_reference_depth": 5,
        "max_document_nesting": 20,
        "max_yaml_aliases": 5,
    }
    values.update(overrides)
    return InputLimits(**values)


def test_builds_sorted_immutable_closure_and_deterministic_manifest(
    tmp_path: Path,
) -> None:
    schema = write(
        tmp_path / "components" / "schema.json",
        json.dumps({"type": "object", "properties": {"id": {"type": "string"}}}),
    )
    first = write(
        tmp_path / "a.json",
        openapi_json(
            components={"schemas": {"Item": {"$ref": "components/schema.json"}}}
        ),
    )
    second = write(
        tmp_path / "b.json",
        openapi_json(
            components={"schemas": {"Item": {"$ref": "components/schema.json"}}}
        ),
    )

    closure = build_input_closure(tmp_path, ["b.json", "a.json"], limits=limits())
    repeated = build_input_closure(tmp_path, ["a.json", "b.json"], limits=limits())

    assert closure == repeated
    assert closure.manifest.entrypoints == ("a.json", "b.json")
    assert [item.path for item in closure.resources] == [
        "a.json",
        "b.json",
        "components/schema.json",
    ]
    assert closure.resource_map() == {
        "a.json": first,
        "b.json": second,
        "components/schema.json": schema,
    }
    with pytest.raises(TypeError):
        closure.resource_map()["a.json"] = b"changed"  # type: ignore[index]
    assert closure.read("a.json") == first
    with pytest.raises(KeyError):
        closure.read("missing.json")
    assert closure.manifest.total_bytes == len(first) + len(second) + len(schema)
    assert closure.manifest.digest.startswith("sha256:")
    assert all(item.digest.startswith("sha256:") for item in closure.manifest.files)
    assert closure.manifest == build_input_manifest(
        tmp_path,
        ["b.json", "a.json"],
        limits=limits(),
    )

    manifest_content = closure.manifest.content_dict()
    canonical = json.dumps(
        manifest_content,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    assert closure.manifest.digest == f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def test_loads_yaml_and_resolves_parent_reference_within_repository(
    tmp_path: Path,
) -> None:
    schema = write(tmp_path / "shared" / "schema.yaml", "type: object\n")
    entrypoint = write(
        tmp_path / "api" / "openapi.yaml",
        """openapi: 3.0.3
info:
  title: Example
  version: 1.0.0
paths: {}
components:
  schemas:
    Item:
      $ref: ../shared/schema.yaml#/Item
""",
    )

    closure = build_input_closure(tmp_path, "api/openapi.yaml", limits=limits())

    assert closure.manifest.entrypoints == ("api/openapi.yaml",)
    assert closure.resource_map() == {
        "api/openapi.yaml": entrypoint,
        "shared/schema.yaml": schema,
    }


def test_internal_references_do_not_add_resources(tmp_path: Path) -> None:
    entrypoint = write(
        tmp_path / "openapi.json",
        openapi_json(
            components={
                "schemas": {
                    "Item": {"$ref": "#/components/schemas/Value"},
                    "Root": {"$ref": ""},
                    "Value": {"type": "string"},
                }
            }
        ),
    )

    closure = build_input_closure(tmp_path, "openapi.json", limits=limits())

    assert closure.resource_map() == {"openapi.json": entrypoint}


@pytest.mark.parametrize(
    ("reference", "code"),
    [
        ("https://example.test/schema.yaml", "unsupported-reference"),
        ("//example.test/schema.yaml", "unsupported-reference"),
        ("file:///tmp/schema.yaml", "unsupported-reference"),
        ("/absolute/schema.yaml", "unsupported-reference"),
        ("C:/schema.yaml", "unsupported-reference"),
        ("..\\schema.yaml", "invalid-reference"),
        ("../../outside.yaml", "path-escape"),
        ("%2e%2e/%2e%2e/outside.yaml", "path-escape"),
        ("NUL.yaml", "unsupported-reference"),
        ("C%3A/schema.yaml", "unsupported-reference"),
        ("schema.txt", "unsupported-format"),
        ("schema.yaml?version=1", "unsupported-reference"),
    ],
)
def test_rejects_unsafe_or_unsupported_references(
    tmp_path: Path,
    reference: str,
    code: str,
) -> None:
    write(
        tmp_path / "openapi.json",
        openapi_json(components={"schemas": {"Item": {"$ref": reference}}}),
    )

    with pytest.raises(InputClosureError) as captured:
        build_input_closure(tmp_path, "openapi.json", limits=limits())

    assert captured.value.code == code
    assert str(tmp_path) not in str(captured.value)


@pytest.mark.parametrize(
    "entrypoint",
    [
        "../outside.yaml",
        "/absolute.yaml",
        "C:/absolute.yaml",
        "folder\\openapi.yaml",
        "openapi.yaml#/fragment",
    ],
)
def test_rejects_unsafe_entrypoints(tmp_path: Path, entrypoint: str) -> None:
    with pytest.raises(InputClosureError):
        build_input_closure(tmp_path, entrypoint, limits=limits())


@pytest.mark.parametrize(
    ("target", "code"),
    [
        ("missing.yaml", "missing-file"),
        ("directory.yaml", "not-regular-file"),
    ],
)
def test_rejects_missing_and_non_file_targets(
    tmp_path: Path,
    target: str,
    code: str,
) -> None:
    (tmp_path / "directory.yaml").mkdir()
    write(
        tmp_path / "openapi.json",
        openapi_json(components={"schemas": {"Item": {"$ref": target}}}),
    )

    with pytest.raises(InputClosureError) as captured:
        build_input_closure(tmp_path, "openapi.json", limits=limits())
    assert captured.value.code == code


def test_rejects_symlinked_reference(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside.yaml"
    write(outside, "type: object\n")
    link = tmp_path / "linked.yaml"
    try:
        link.symlink_to(outside)
    except (NotImplementedError, OSError):
        pytest.skip("symlink creation is unavailable on this platform")
    write(
        tmp_path / "openapi.json",
        openapi_json(components={"schemas": {"Item": {"$ref": "linked.yaml"}}}),
    )

    with pytest.raises(InputClosureError) as captured:
        build_input_closure(tmp_path, "openapi.json", limits=limits())

    assert captured.value.code == "path-link"


def test_entrypoint_byte_limit_is_inclusive(tmp_path: Path) -> None:
    content = write(tmp_path / "openapi.json", openapi_json())

    build_input_closure(
        tmp_path,
        "openapi.json",
        limits=limits(max_entrypoint_bytes=len(content)),
    )
    with pytest.raises(InputClosureError) as captured:
        build_input_closure(
            tmp_path,
            "openapi.json",
            limits=limits(max_entrypoint_bytes=len(content) - 1),
        )
    assert captured.value.code == "entrypoint-bytes-limit"


def test_aggregate_byte_limit_is_inclusive(tmp_path: Path) -> None:
    referenced = write(tmp_path / "schema.json", '{"type":"string"}')
    entrypoint = write(
        tmp_path / "openapi.json",
        openapi_json(components={"schemas": {"Value": {"$ref": "schema.json"}}}),
    )
    exact = len(entrypoint) + len(referenced)

    build_input_closure(
        tmp_path,
        "openapi.json",
        limits=limits(max_total_bytes=exact),
    )
    with pytest.raises(InputClosureError) as captured:
        build_input_closure(
            tmp_path,
            "openapi.json",
            limits=limits(max_total_bytes=exact - 1),
        )
    assert captured.value.code == "total-bytes-limit"


def test_file_count_limit_is_inclusive(tmp_path: Path) -> None:
    write(tmp_path / "one.json", '{"type":"string"}')
    write(tmp_path / "two.json", '{"type":"number"}')
    write(
        tmp_path / "openapi.json",
        openapi_json(
            components={
                "schemas": {
                    "One": {"$ref": "one.json"},
                    "Two": {"$ref": "two.json"},
                }
            }
        ),
    )

    build_input_closure(
        tmp_path,
        "openapi.json",
        limits=limits(max_files=3),
    )
    with pytest.raises(InputClosureError) as captured:
        build_input_closure(
            tmp_path,
            "openapi.json",
            limits=limits(max_files=2),
        )
    assert captured.value.code == "file-count-limit"


def test_reference_depth_limit_is_inclusive(tmp_path: Path) -> None:
    write(tmp_path / "second.json", '{"type":"string"}')
    write(tmp_path / "first.json", '{"$ref":"second.json"}')
    write(
        tmp_path / "openapi.json",
        openapi_json(components={"schemas": {"Value": {"$ref": "first.json"}}}),
    )

    build_input_closure(
        tmp_path,
        "openapi.json",
        limits=limits(max_reference_depth=2),
    )
    with pytest.raises(InputClosureError) as captured:
        build_input_closure(
            tmp_path,
            "openapi.json",
            limits=limits(max_reference_depth=1),
        )
    assert captured.value.code == "reference-depth-limit"


@pytest.mark.parametrize(
    "content",
    [
        '{"openapi":"3.1.0","openapi":"3.0.3"}',
        "openapi: 3.1.0\nopenapi: 3.0.3\n",
        "---\nopenapi: 3.1.0\n---\nopenapi: 3.0.3\n",
        "value: .nan\n",
        "value: 2026-08-04\n",
    ],
)
def test_rejects_non_strict_documents(tmp_path: Path, content: str) -> None:
    suffix = ".json" if content.startswith("{") else ".yaml"
    path = tmp_path / f"openapi{suffix}"
    write(path, content)

    with pytest.raises(InputClosureError):
        build_input_closure(tmp_path, path.name, limits=limits())


def test_rejects_yaml_alias_limit_and_recursive_cycle(tmp_path: Path) -> None:
    write(
        tmp_path / "aliases.yaml",
        "base: &base {type: string}\na: *base\nb: *base\n",
    )
    with pytest.raises(InputClosureError) as aliases:
        build_input_closure(
            tmp_path,
            "aliases.yaml",
            limits=limits(max_yaml_aliases=1),
        )
    assert aliases.value.code == "yaml-alias-limit"

    write(tmp_path / "cycle.yaml", "value: &value [*value]\n")
    with pytest.raises(InputClosureError) as cycle:
        build_input_closure(tmp_path, "cycle.yaml", limits=limits())
    assert cycle.value.code == "document-cycle"


def test_yaml_alias_reuse_preserves_effective_nesting_depth(tmp_path: Path) -> None:
    write(
        tmp_path / "reused.yaml",
        """shared: &shared
  child:
    leaf: value
shallow: *shared
deep:
  a:
    b:
      reused: *shared
""",
    )

    build_input_closure(
        tmp_path,
        "reused.yaml",
        limits=limits(max_document_nesting=6),
    )
    with pytest.raises(InputClosureError) as captured:
        build_input_closure(
            tmp_path,
            "reused.yaml",
            limits=limits(max_document_nesting=5),
        )
    assert captured.value.code == "document-nesting-limit"


@pytest.mark.parametrize("depth,accepted", [(100, True), (101, False)])
def test_document_nesting_limit_is_inclusive(
    tmp_path: Path, depth: int, accepted: bool
) -> None:
    document = "null"
    for _ in range(depth):
        document = f'{{"value":{document}}}'
    write(tmp_path / "nested.json", document)

    if accepted:
        build_input_closure(
            tmp_path,
            "nested.json",
            limits=limits(max_document_nesting=100),
        )
    else:
        with pytest.raises(InputClosureError) as captured:
            build_input_closure(
                tmp_path,
                "nested.json",
                limits=limits(max_document_nesting=100),
            )
        assert captured.value.code == "document-nesting-limit"


@pytest.mark.parametrize("alias_count,accepted", [(50, True), (51, False)])
def test_yaml_alias_limit_is_inclusive(
    tmp_path: Path, alias_count: int, accepted: bool
) -> None:
    aliases = "\n".join(f"value{index}: *base" for index in range(alias_count))
    write(tmp_path / "aliases.yaml", f"base: &base value\n{aliases}\n")

    if accepted:
        build_input_closure(
            tmp_path,
            "aliases.yaml",
            limits=limits(max_yaml_aliases=50),
        )
    else:
        with pytest.raises(InputClosureError) as captured:
            build_input_closure(
                tmp_path,
                "aliases.yaml",
                limits=limits(max_yaml_aliases=50),
            )
        assert captured.value.code == "yaml-alias-limit"


def test_detects_partial_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write(tmp_path / "openapi.json", openapi_json(description="x" * 1000))
    original_read = input_closure_module.os.read
    calls = 0

    def partial_read(descriptor: int, count: int) -> bytes:
        nonlocal calls
        calls += 1
        if calls == 1:
            return original_read(descriptor, 10)
        return b""

    monkeypatch.setattr(input_closure_module.os, "read", partial_read)
    with pytest.raises(InputClosureError) as captured:
        build_input_closure(tmp_path, "openapi.json", limits=limits())
    assert captured.value.code == "concurrent-mutation"


def test_detects_file_state_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write(tmp_path / "openapi.json", openapi_json())
    original_fstat = input_closure_module.os.fstat
    calls = 0

    def changed_fstat(descriptor: int):
        nonlocal calls
        calls += 1
        value = original_fstat(descriptor)
        if calls < 2:
            return value
        return SimpleNamespace(
            st_mode=value.st_mode,
            st_dev=value.st_dev,
            st_ino=value.st_ino,
            st_size=value.st_size,
            st_mtime_ns=value.st_mtime_ns + 1,
            st_ctime_ns=value.st_ctime_ns,
        )

    monkeypatch.setattr(input_closure_module.os, "fstat", changed_fstat)
    with pytest.raises(InputClosureError) as captured:
        build_input_closure(tmp_path, "openapi.json", limits=limits())
    assert captured.value.code == "concurrent-mutation"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_entrypoint_bytes", 0),
        ("max_total_bytes", 0),
        ("max_files", 0),
        ("max_reference_depth", -1),
        ("max_document_nesting", 0),
        ("max_yaml_aliases", -1),
    ],
)
def test_rejects_invalid_limits(field: str, value: int) -> None:
    with pytest.raises(ValueError):
        limits(**{field: value})
