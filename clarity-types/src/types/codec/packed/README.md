# Packed Clarity Value Codec

## Scope

This module provides the stable API and version dispatch for non-consensus packed Clarity values.
Each stored stream starts with its own one-byte version discriminator. The remaining envelope and
body are interpreted only by the selected version implementation.

Packed records and value-shape descriptors are independently versioned:

- a packed record stores the active value and its equivalent consensus-serialization length; and
- an optional value-shape descriptor (`ValueShape`) stores the minimal value-derived structural
  metadata needed to reconstruct consensus bytes without a caller-supplied `TypeSignature`.

Typed decoding needs only a packed record and caller-supplied `TypeSignature`. Descriptor-guided
reconstruction needs both streams.

## Trust and integrity boundary

A packed record is intentionally not self-describing with respect to its complete Clarity type.
Typed decoding proves that the record is canonical under the supplied `TypeSignature`; it does not
authenticate that the schema belongs to that record. Storage integrations are responsible for
preserving this association.

Paths handling untrusted or possibly mismatched metadata should reconstruct through the value-shape
descriptor, perform the codec's full canonical audit, and verify any content-addressed key against
the reconstructed consensus bytes. A record's logical-length field detects truncation and many
schema mismatches, but it is not an authentication tag.

## Version registry

| Stream | Version byte | Specification | Implementation |
| ---- | ---- | ---- | ---- |
| Packed value record | `01` | [Packed Grammar V1](v1/README.md) | `packed::v1` |
| Value-shape descriptor | `01` | [Packed Grammar V1](v1/README.md) | `packed::v1` |

The matching version bytes do not couple the streams. A future record or descriptor grammar can
advance independently. Compatibility between known record and shape versions is selected explicitly
by the common reconstruction dispatcher.

## Compatibility rules

- Writers select record and shape versions explicitly; adding a version never changes existing
  call sites to a newer format implicitly.
- Readers dispatch only from the leading version byte and reject unknown versions without probing
  another grammar.
- Each implementation owns its complete envelope, body grammar, canonicality rules, and resource
  bounds.
- The common layer owns opaque record types, version selection, errors, and public dispatch.
- Packed bytes remain independent of execution epochs and inactive declared-type information.

## Rust error model

Public codec operations return `PackedValueError`. Its typed variants distinguish record grammar,
value-shape grammar, schema compatibility, reconstruction consistency, and internal invariants.
Callers that need programmatic handling should match those variants instead of display text;
contextual variants expose named expected/actual, length, count, or offending-byte fields without
retaining complete input buffers. Wrapped Clarity type and consensus serialization errors retain
their source chains.

## Adding a version

To add a packed grammar version:

1. add a sibling implementation directory such as `packed/v2`;
2. add the discriminator to the corresponding public version enum;
3. add exhaustive dispatch arms for encoding, parsing, decoding, and reconstruction;
4. declare the record/shape version combinations supported by reconstruction; and
5. add version-specific golden, canonicality, bounds, and fuzz tests; and
6. review each consumer's write and read acceptance policy, explicitly rejecting versions that its
   storage or transport format does not admit.

Existing version modules and golden vectors must remain unchanged unless that version's decoder is
being corrected to reject invalid input. A new writer format always receives a new version byte.
