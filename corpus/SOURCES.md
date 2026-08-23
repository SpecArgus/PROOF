# Corpus public-source provenance

This file records the provenance of every public-source fixture used in the PROOF corpus.
Synthetic fixtures (sourceType: "synthetic") have no upstream source and are not listed here.

---

## OAI petstore examples

Both petstore fixtures are taken from the OpenAPI-Specification repository maintained by
the OpenAPI Initiative (OAI). The OAI repository is licensed under Apache-2.0.

### `fixtures/public/oai-petstore.yaml`

- **Upstream file**: `examples/v3.0/petstore.yaml`
- **Repository**: <https://github.com/OAI/OpenAPI-Specification>
- **License**: Apache-2.0
- **Branch/ref used**: `main`
- **Modifications**: None. File is used as-is from the upstream source.

Corpus cases derived from this fixture:
- `pub-petstore-list-pets-30` — GET /pets (negative, AGT-CTX-001)
- `pub-petstore-create-pets-30` — POST /pets (negative, AGT-RESP-001)
- `pub-petstore-show-pet-30` — GET /pets/{petId} (negative, AGT-PARAM-001)

### `fixtures/public/oai-petstore-expanded.yaml`

- **Upstream file**: `examples/v3.0/petstore-expanded.yaml`
- **Repository**: <https://github.com/OAI/OpenAPI-Specification>
- **License**: Apache-2.0
- **Branch/ref used**: `main`
- **Modifications**: None. File is used as-is from the upstream source.

Corpus cases derived from this fixture:
- `pub-petstore-exp-find-pets-30` — GET /pets (negative, AGT-CTX-001)
- `pub-petstore-exp-add-pet-30` — POST /pets (negative, AGT-RESP-001)
- `pub-petstore-exp-find-pet-id-30` — GET /pets/{id} (negative, AGT-PARAM-001)
- `pub-petstore-exp-delete-pet-30` — DELETE /pets/{id} (positive, AGT-POL-001)

---

## GitHub REST API description

Both GitHub fixtures are extracted from the github/rest-api-description repository.
That repository is licensed under Creative Commons Attribution 4.0 International (CC-BY-4.0).

### `fixtures/public/github-api-30-subset.json`

- **Upstream file**: `descriptions/api.github.com/api.github.com.json` (OAS 3.0.x)
- **Repository**: <https://github.com/github/rest-api-description>
- **License**: CC-BY-4.0
- **Branch/ref used**: `main`
- **Modifications**: Extracted paths and retained only the operations under test.
  Specifically:
  - `/repos/{owner}/{repo}` — GET only (all other methods omitted)
  - `/repos/{owner}/{repo}/hooks` — POST only
  - `/repos/{owner}/{repo}/actions/secrets` — GET only
  - `/markdown` — POST only

  The `components` section contains the complete transitive internal `$ref` closure
  reachable from the retained operations and their path-item-level parameters.
  No inline schema content has been added or modified.

Corpus cases derived from this fixture:
- `pub-github30-get-repo` — GET /repos/{owner}/{repo} (negative, AGT-CTX-001)
- `pub-github30-create-webhook` — POST /repos/{owner}/{repo}/hooks (positive, AGT-POL-001)
- `pub-github30-list-repo-secrets` — GET /repos/{owner}/{repo}/actions/secrets (positive, AGT-POL-002)
- `pub-github30-render-markdown` — POST /markdown (positive, AGT-RESP-001)

### `fixtures/public/github-api-31-subset.json`

- **Upstream file**: `descriptions-next/api.github.com/api.github.com.json` (OAS 3.1.x)
- **Repository**: <https://github.com/github/rest-api-description>
- **License**: CC-BY-4.0
- **Branch/ref used**: `main`
- **Modifications**: Extracted paths and retained only the operations under test.
  Specifically:
  - `/repos/{owner}/{repo}` — GET and DELETE (OP-5 and OP-6 share this path item; PATCH omitted)
  - `/orgs/{org}/actions/secrets` — GET only
  - `/enterprises/{enterprise}/actions/runner-groups` — POST only

  The `components` section contains the complete transitive internal `$ref` closure
  reachable from the retained operations and their path-item-level parameters.
  No inline schema content has been added or modified.

Corpus cases derived from this fixture:
- `pub-github31-get-repo` — GET /repos/{owner}/{repo} (negative, AGT-CTX-001)
- `pub-github31-delete-repo` — DELETE /repos/{owner}/{repo} (positive, AGT-POL-001)
- `pub-github31-list-org-secrets` — GET /orgs/{org}/actions/secrets (positive, AGT-POL-002)
- `pub-github31-create-runner-group` — POST /enterprises/{enterprise}/actions/runner-groups (positive, AGT-RESP-001)

---

## Licensing notes

Sources were selected on the basis of confirmed, permissive open-source licenses
(Apache-2.0, CC-BY-4.0). No source was included on the assumption that public
availability implies permissive licensing.
