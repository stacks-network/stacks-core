---
applyTo: "stackslib/src/net/api/**/*.rs,stackslib/src/net/http/**/*.rs,stackslib/src/net/httpcore.rs,stackslib/src/net/rpc.rs,stackslib/src/net/server.rs,docs/rpc/**/*,docs/rpc-endpoints.md,.github/actions/openapi/**/*,.github/scripts/openapi_validation.sh"
---

# Node RPC review guidance

This guidance covers the node's public RPC server, implemented in `stackslib/src/net/`. It does not cover the outbound burnchain RPC client under `stacks-node/src/burnchains/rpc/`.

## Public surface alignment

- For an added, removed, or changed endpoint, trace the implementation through handler registration, method and path matching, request parsing, authorization, response serialization, and endpoint tests.
- Verify the implementation, `docs/rpc/openapi.yaml`, referenced schemas and examples under `docs/rpc/components/`, and relevant descriptions in `docs/rpc-endpoints.md` agree on the public behavior.
- Compare HTTP methods and paths exactly, including path parameters, query parameters, headers, request bodies, content types, required fields, defaults, limits, and accepted encodings.
- Compare response status codes, headers, content types, body schemas, field names, optionality, nullability, enum values, numeric units, and error formats across code and documentation.
- Treat endpoint removal, path or method changes, renamed fields, stricter validation, changed defaults, new authentication requirements, and response-type changes as compatibility-sensitive.

## OpenAPI and documentation

- Verify every changed `$ref` resolves and that changed schemas, parameters, responses, and examples are registered and used by the intended operation.
- Check that OpenAPI schemas match the serialized Rust types, including Serde renames, tagged enums, omitted optional fields, numeric representations, and binary or hex encodings.
- Verify examples conform to their schemas and represent responses the implementation can actually produce.
- Keep `operationId` values unique and stable unless the PR intentionally changes the generated-client interface.
- Update `docs/rpc-endpoints.md` when it describes the affected endpoint or shared behavior; do not assume that file is an exhaustive endpoint catalog.
- Do not require a generated HTML documentation file in the repository; CI builds it from the OpenAPI sources.

## Behavior and validation

- Check endpoint tests cover the changed success response and material parsing, authorization, validation, not-found, and server-error cases.
- Verify tests assert externally visible status codes, headers, and serialized bodies rather than only internal Rust values.
- For tip- or block-specific requests, verify the documented selector semantics and defaults match the chain view used by the handler.
- Confirm OpenAPI linting and documentation generation still cover the root specification, referenced component files, and Redocly configuration.
- Do not treat successful OpenAPI linting as proof that the specification matches runtime behavior; compare it directly with the handler and tests.
