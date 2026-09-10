# Packed Clarity Value Codec

## Scope

This module provides the stable API and version dispatch for non-consensus packed Clarity values.
Each packed record and value descriptor starts with its own one-byte version discriminator.
The remaining envelope and body are interpreted only by the selected version implementation.

Packed records and value descriptors are independently versioned:

- a packed record stores the active value and its equivalent consensus-serialization length; and
- an optional value descriptor (`ValueDescriptor`) stores the minimal value-derived structural
  metadata needed to reconstruct consensus bytes without a caller-supplied `TypeSignature`.

Typed decoding needs only a packed record and an **expected type** (the caller-supplied
`TypeSignature`). Descriptor-guided reconstruction needs both the record and its descriptor.
**Layout** means the physical arrangement of packed bytes, selected by the encoder from the value
alone. These terms are defined in the [V1 glossary](v1/README.md#terminology-and-notation).

## Trust and integrity boundary

A packed record is intentionally not self-describing with respect to its complete Clarity type.
Typed decoding proves that the record is canonical under the expected type; it does not
authenticate that the expected type belongs to that record. Storage integrations are responsible for
preserving this association.

Paths handling untrusted or possibly mismatched metadata should reconstruct through the value
descriptor, perform the codec's full canonical audit, and verify any content-addressed key against
the reconstructed consensus bytes. A record's logical-length field detects truncation and many
expected type mismatches, but it is not an authentication tag.

## Version registry

| Encoding | Version byte | Specification | Implementation |
| ---- | ---- | ---- | ---- |
| Packed value record | `01` | [Packed Grammar V1](v1/README.md) | `packed::v1` |
| Value descriptor | `01` | [Packed Grammar V1](v1/README.md) | `packed::v1` |

Record and descriptor versions advance independently. Compatibility between known record and
descriptor versions is selected explicitly by the common reconstruction dispatcher.

## Compatibility rules

- Writers select record and descriptor versions explicitly; adding a version never changes existing
  call sites to a newer format implicitly.
- Readers dispatch only from the leading version byte and reject unknown versions without probing
  another grammar.
- Each implementation owns its complete envelope, body grammar, canonicality rules, and resource
  bounds.
- The common layer owns opaque record types, version selection, errors, and public dispatch.
- Packed bytes remain independent of execution epochs and inactive declared-type information.

## Rust error model

Public codec operations return `PackedValueError`. Its typed variants distinguish record grammar,
descriptor grammar, expected type compatibility, reconstruction consistency, and internal invariants.
Callers that need programmatic handling should match those variants instead of display text;
contextual variants expose named expected/actual, length, count, or offending-byte fields without
retaining complete input buffers. Wrapped Clarity type and consensus serialization errors retain
their source chains.

## Adding a version

To add a packed grammar version:

1. add a sibling implementation directory such as `packed/v2`;
2. add the discriminator to the corresponding public version enum;
3. add exhaustive dispatch arms for encoding, parsing, decoding, and reconstruction;
4. declare the record/descriptor version combinations supported by reconstruction; and
5. add version-specific golden, canonicality, bounds, and fuzz tests; and
6. review each consumer's write and read acceptance policy, explicitly rejecting versions that its
   storage or transport format does not admit.

Version modules and golden vectors must remain unchanged unless that version's decoder is being
corrected to reject invalid input. Changing a writer format requires a new version byte.
