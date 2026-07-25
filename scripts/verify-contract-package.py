"""Verify that the proof-contracts wheel contains the public v1 schemas."""

import sys
from pathlib import Path
from zipfile import ZipFile

SCHEMA_ROOT = "proof_contracts/schemas/result/v1"
EXPECTED_SCHEMAS = {
    f"{SCHEMA_ROOT}/common.schema.json",
    f"{SCHEMA_ROOT}/finding.schema.json",
    f"{SCHEMA_ROOT}/gate.schema.json",
    f"{SCHEMA_ROOT}/provenance.schema.json",
    f"{SCHEMA_ROOT}/run.schema.json",
}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify-contract-package.py <build-directory>", file=sys.stderr)
        return 2

    build_directory = Path(sys.argv[1])
    wheels = sorted(build_directory.glob("proof_contracts-*.whl"))
    if len(wheels) != 1:
        print(
            f"expected exactly one proof-contracts wheel in {build_directory}, "
            f"found {len(wheels)}",
            file=sys.stderr,
        )
        return 1

    wheel = wheels[0]
    with ZipFile(wheel) as archive:
        packaged_files = set(archive.namelist())

    missing_schemas = sorted(EXPECTED_SCHEMAS - packaged_files)
    if missing_schemas:
        print(
            f"{wheel.name} is missing schemas: {', '.join(missing_schemas)}",
            file=sys.stderr,
        )
        return 1

    print(f"Verified {len(EXPECTED_SCHEMAS)} schemas in {wheel.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
