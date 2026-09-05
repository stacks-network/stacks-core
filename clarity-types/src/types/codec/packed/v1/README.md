# Canonical Packed Clarity Value Format (Packed Grammar V1)

## Status and scope

This document specifies the byte-level format emitted and accepted by the `clarity-types`
packed-value codec. It is normative for Packed Grammar V1.

The uppercase key words **MUST** and **MUST NOT** are interpreted as described by
[BCP 14](https://www.rfc-editor.org/info/bcp14), comprising
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174). They state absolute requirements and
prohibitions. Only these uppercase forms carry normative meaning in this document.

This is a compact local representation. It is not Clarity consensus serialization and does not
change value hashes, state roots, protocol costs, or values visible to contracts. A packed record
retains the byte length of its equivalent consensus serialization so existing cost accounting
remains unchanged.

The codec defines two independent byte streams:

- a packed value record, decoded with a caller-supplied `TypeSignature`; and
- an optional value-shape descriptor, used to reconstruct exact consensus bytes without a
  `TypeSignature`.

Ordinary typed reads require only the packed value record. Generic reads, integrity audits, and
compatibility reads for historical unsanitized values whose cached schema omits active data require
both streams.

Both streams are independently versioned, but neither is self-describing with respect to the
complete Clarity type. A typed decoder MUST receive the expected `TypeSignature`. A
descriptor-guided reconstructor MUST receive the value-shape descriptor. For example, the packed
body `00` can represent integer zero, unsigned integer zero, Boolean false, or optional `none`; its
enclosing `TypeSignature` or descriptor distinguishes them.

## Versioned streams

The packed record and value-shape descriptor have independent version bytes. Offsets in each table
are relative to the start of that complete stream.

### Packed record envelope

For a complete packed record of `R` bytes:

| Offset | Length | Field | Encoding | Meaning |
| ---- | ---- | ---- | ---- | ---- |
| `0` | 1 byte | Packed version | `u8` | MUST be `01` for Packed Grammar V1 |
| `1` | 3 bytes | Consensus byte length | `u24le` | Length of the equivalent canonical consensus serialization; this is not the packed-body length |
| `4` | `R - 4` bytes | Value body | Variant-specific | Packed payload; the complete record supplies its physical length |

The four-byte envelope is followed immediately by the value body. There is intentionally no
packed-body-length field.

### Value-shape descriptor envelope

For a complete value-shape descriptor of `S` bytes:

| Offset | Length | Field | Encoding | Meaning |
| ---- | ---- | ---- | ---- | ---- |
| `0` | 1 byte | Shape version | `u8` | MUST be `01` for the V1 descriptor format |
| `1` | `S - 1` bytes | Root shape | Shape-specific | Exactly one root shape node with no trailing bytes |

The packed version selects the record-envelope and value-body grammar. The shape version selects the
descriptor grammar. A change to one stream does not require changing the other when its grammar is
otherwise unchanged.

This specification makes no assumptions about how either byte stream is transported, framed,
indexed, or persisted. A containing system MUST treat the complete versioned streams as opaque
codec values and MUST NOT infer their versions from external state.

## Terminology and notation

A value-shape descriptor (`ValueShape`) is a value-derived structural schema. It records only the
active structure needed to interpret packed bytes; unlike a `TypeSignature`, it does not represent
declared bounds, inactive optional or response branches, or callable trait metadata.
"Descriptor-guided" therefore means that reconstruction uses this descriptor instead of a
caller-supplied `TypeSignature`.

The following notation is used:

| Notation | Meaning |
| ---- | ---- |
| `u8` | One unsigned byte |
| `u16le` | Two-byte unsigned little-endian integer |
| `u24le` | Three-byte unsigned little-endian integer |
| `u32le` | Four-byte unsigned little-endian integer |
| `u32be` | Four-byte unsigned big-endian integer |
| `varuint` | Minimal unsigned LEB128 integer |

An enclosing frame is the complete record body, a directory-delimited child, a fixed-width child, or
a scalar-lane element. Lengthless encodings consume the remainder of their enclosing frame.

Unless a table says otherwise, offsets are relative to the start of the body or descriptor being
described. `B` denotes that enclosing body's physical byte length, `N` a child or element count,
`W` a selected physical width, and `cursor` the offset immediately following the preceding
variable-length field.

Unless stated otherwise:

- physical lengths, list counts, and directory offsets are little-endian;
- integer value bytes are big-endian; and
- lengths reconstructed for Clarity consensus serialization are big-endian, as required by that
  existing format.

All length and offset arithmetic MUST be checked for overflow.

### Consensus serialization reference

The logical length and reconstruction rules in this document refer to Clarity's canonical consensus
serialization. Its one-byte type prefixes are included here to make reconstruction examples
self-contained. Each is the first byte of its consensus value:

| Prefix byte | Consensus value |
| ---- | ---- |
| `00` | Signed integer followed by 16 big-endian bytes |
| `01` | Unsigned integer followed by 16 big-endian bytes |
| `02` | Buffer followed by `u32be` byte length and payload |
| `03` | Boolean true |
| `04` | Boolean false |
| `05` | Standard principal followed by version and 20-byte hash |
| `06` | Contract principal or callable identity |
| `07` | Response `ok`, followed by its child value |
| `08` | Response `err`, followed by its child value |
| `09` | Optional `none` |
| `0a` | Optional `some`, followed by its child value |
| `0b` | List followed by `u32be` element count and consensus-encoded elements |
| `0c` | Tuple followed by `u32be` field count and encoded fields |
| `0d` | ASCII string followed by `u32be` byte length and payload |
| `0e` | UTF-8 string followed by `u32be` byte length and payload |

A contract principal encodes its issuer version and 20-byte hash, then its contract name as a
one-byte name length followed by name bytes. Each tuple field likewise encodes its name as a
one-byte length and name bytes before its child value. Implementations MUST use Clarity's existing
principal, `ContractName`, `ClarityName`, ASCII, and UTF-8 validity rules.

## Canonicality invariant

For a supported active Clarity `Value`, the packed bytes MUST be a pure function of the value. They
MUST NOT depend on:

- the execution epoch;
- declared sequence bounds;
- inactive optional or response types;
- callable subtype metadata; or
- any other part of the declared `TypeSignature` not present in the active value.

The expected schema is a decoding input, not a physical-layout input. Execution-epoch admission and
sanitization are caller policies outside this format. Two values with identical canonical consensus
bytes MUST produce identical packed records and identical value-shape descriptors.

Encoders MUST emit the one canonical representation described below. Packed-record decoders MUST
reject non-minimal scalar and directory widths, trailing bytes, invalid padding, and disagreement
with the declared logical consensus length. Descriptor parsing enforces its local grammar and
minimality rules; the full audit defined below additionally proves that a structurally valid
descriptor is canonical for its packed value.

## Trust and integrity boundary

A packed record is intentionally not self-describing. Typed decoding proves that the record is a
canonical value under the caller-supplied schema; it does not authenticate that the schema belongs
to that record. Some bodies are valid under more than one same-width schema. For example, four raw
bytes can decode as either `(buff 4)` or `(string-ascii 4)` when paired with the corresponding
schema.

A storage system using typed decoding MUST therefore preserve the association between a record and
its type metadata. The format does not require a content-hash check on a trusted hot path when that
association is already protected by the storage write path and authenticated index. A generic read,
integrity audit, migration, or any path handling untrusted or possibly mismatched metadata MUST
instead use the value-shape descriptor and full canonical audit below, then verify any
content-addressed key against the reconstructed consensus bytes.

The logical-length header detects truncation and many schema mismatches, but it is not a checksum or
authentication tag. Packed Grammar V1 does not attempt to detect a same-length substitution that is
otherwise canonical under the supplied schema.

## Runtime value coverage

Every supported runtime `Value` variant is represented as follows. `Sequence` and `Principal`
rows show all of their runtime subtypes.

| Runtime value | Packed body | Value-shape opcode | Required decoding context |
| ---- | ---- | ---- | ---- |
| `Int` | Minimal signed scalar | `00` | `IntType` or shape |
| `UInt` | Minimal unsigned scalar | `01` | `UIntType` or shape |
| `Bool` | `00` or `01` | `02` | `BoolType` or shape |
| `Sequence::Buffer` | Raw payload | `03` | Buffer type/bound or shape |
| `Sequence::String::ASCII` | Raw character bytes | `04` | ASCII type/bound or shape |
| `Sequence::String::UTF8` | Raw UTF-8 bytes | `05` | UTF-8 type/bound or shape |
| `Sequence::List` | Count plus one canonical element layout | `0d`, `0e`, or `0f` | List type/bound or shape |
| `Principal::Standard` | Principal kind `00`, version, hash | `06` | `PrincipalType` or shape |
| `Principal::Contract` | Principal kind `01`, issuer, name | `06` | `PrincipalType` or shape |
| `CallableContract` | Same body as contract principal | `06` | Callable schema restores trait identity |
| `Optional::None` | Tag `00` | `07` | Optional type or shape |
| `Optional::Some` | Tag `01` plus active child | `08` | Optional child type or shape |
| `Response::Err` | Tag `00` plus active child | `0a` | Error type or shape |
| `Response::Ok` | Tag `01` plus active child | `09` | Success type or shape |
| `Tuple` | Fixed concatenation or offset directory | `0c` | Field names/types or tuple shape |

`NoType` is not an active runtime value. `ListUnionType` is an analysis-only schema and cannot
describe an active runtime value.

## Packed value record

Every record uses the four-byte [packed record envelope](#packed-record-envelope) defined above.

`consensus_byte_len` is the exact length, in bytes, of the equivalent canonical Clarity consensus
serialization. It includes the consensus type prefix and any consensus length, field-name, or
container-count bytes omitted from the packed body.

The packed header is exactly four bytes: one format-version byte and three logical-length bytes.
It is not a physical payload length. The complete record's enclosing frame supplies the packed body
length.

For example, unsigned integer `u42` has a 17-byte consensus serialization but a five-byte packed
record:

| Offset | Length | Bytes | Meaning |
| ---- | ---- | ---- | ---- |
| `0` | 1 byte | `01` | Packed Grammar V1 |
| `1` | 3 bytes | `11 00 00` | Consensus byte length 17, encoded as `u24le` |
| `4` | 1 byte | `2a` | Minimal unsigned-integer body for 42 |

The logical length is retained because physical packing MUST NOT change:

- the actual consensus-serialized byte length used by existing Clarity runtime-cost accounting;
- the exact allocation bound for descriptor-guided consensus reconstruction; or
- the ability to detect a packed body, schema, or descriptor that reconstructs a different logical
  value length.

The current 2,097,152-byte consensus serialization bound fits in 24 bits. Version 1 therefore uses
the remaining three header bytes for the logical length while keeping the body at offset four.
Decoders widen `u24le` to the codec's checked `u32` length type. Increasing the consensus bound
beyond `0xff_ffff` requires a new packed version.

A typed decoder MUST compute the logical consensus length while decoding and MUST reject the record
unless it equals `consensus_byte_len`. A descriptor-guided reconstructor MUST produce exactly
`consensus_byte_len` bytes and MUST reject an append that would exceed it.

## Scalar and sequence bodies

### Signed integer

| Offset | Length | Field | Encoding | Meaning |
| ---- | ---- | ---- | ---- | ---- |
| `0` | `W` bytes, `1 <= W <= 16` | Integer bytes | Minimal two's-complement big-endian | Complete signed-integer body |

The body is the shortest non-empty two's-complement big-endian representation of the `i128`.
Redundant leading `00` or `ff` sign-extension bytes are forbidden. Zero is encoded as one `00` byte.

Consensus reconstruction prepends the Clarity integer prefix and sign-extends the body to 16 bytes.

### Unsigned integer

| Offset | Length | Field | Encoding | Meaning |
| ---- | ---- | ---- | ---- | ---- |
| `0` | `W` bytes, `1 <= W <= 16` | Integer bytes | Minimal unsigned big-endian | Complete unsigned-integer body |

The body is the shortest non-empty unsigned big-endian representation of the `u128`. A multi-byte
value MUST NOT begin with `00`. Zero is encoded as one `00` byte.

Consensus reconstruction prepends the Clarity unsigned-integer prefix and zero-extends the body to
16 bytes.

### Boolean

| Offset | Length | Field | Encoding | Meaning |
| ---- | ---- | ---- | ---- | ---- |
| `0` | 1 byte | Boolean value | `u8` | `00` is false; `01` is true |

`00` is false and `01` is true. No other value is valid.

### Buffer

| Offset | Length | Field | Encoding | Meaning |
| ---- | ---- | ---- | ---- | ---- |
| `0` | `B` bytes | Buffer payload | Raw bytes | The enclosing frame supplies `B`; an empty buffer has `B = 0` |

The enclosing frame supplies the physical length. Typed decoding MUST reject a payload exceeding the
declared buffer bound.

Consensus reconstruction prepends the buffer prefix and payload length as
`u32be`.

### ASCII string

| Offset | Length | Field | Encoding | Meaning |
| ---- | ---- | ---- | ---- | ---- |
| `0` | `B` bytes | Characters | Clarity-valid ASCII bytes | The enclosing frame supplies the byte length |

Every byte MUST satisfy Clarity's ASCII grammar: ASCII alphanumeric, punctuation, or whitespace. The
enclosing frame supplies the byte length. Typed decoding MUST also enforce the declared character
bound.

Consensus reconstruction prepends the ASCII-string prefix and byte length as `u32be`.

### UTF-8 string

| Offset | Length | Field | Encoding | Meaning |
| ---- | ---- | ---- | ---- | ---- |
| `0` | `B` bytes | String payload | Valid UTF-8 bytes | The enclosing frame supplies the byte length |

The body MUST be valid UTF-8. Typed decoding MUST enforce the declared bound in Unicode scalar
values, not bytes.

Consensus reconstruction prepends the UTF-8-string prefix and byte length as `u32be`.

## Principals and callables

Principals use a one-byte physical kind.

### Standard principal body

| Offset | Length | Field | Encoding | Meaning |
| ---- | ---- | ---- | ---- | ---- |
| `0` | 1 byte | Principal kind | `u8` | MUST be `00` |
| `1` | 1 byte | Principal version | `u8` | Network/address version; MUST be less than 32 |
| `2` | 20 bytes | Principal hash | Hash160 bytes | Standard-principal identity |

The complete body is exactly 22 bytes.

### Contract principal body

| Offset | Length | Field | Encoding | Meaning |
| ---- | ---- | ---- | ---- | ---- |
| `0` | 1 byte | Principal kind | `u8` | MUST be `01` |
| `1` | 1 byte | Issuer version | `u8` | Network/address version; MUST be less than 32 |
| `2` | 20 bytes | Issuer hash | Hash160 bytes | Contract issuer identity |
| `22` | `B - 22` bytes | Contract name | Clarity-valid UTF-8 bytes | Non-empty remainder of the enclosing frame; maximum 128 bytes |

The principal version MUST be less than 32. A contract name MUST be non-empty, valid UTF-8, no
longer than Clarity's 128-byte name bound, and accepted by the Clarity contract-name grammar.

The contract-name length is omitted because the enclosing frame supplies it. A contract-principal
body is `22 + contract_name.len()` bytes.

A callable contract MUST use the contract-principal body above. Trait identity is not stored because
it is absent from the callable's consensus bytes. Typed decoding restores callable identity from the
declared schema:

- `CallableType::Principal(expected_contract)` verifies the encoded contract identity and restores
  a callable without trait metadata;
- `CallableType::Trait(expected_trait)` restores `expected_trait`;
- `TraitReferenceType(expected_trait)` restores the historical trait view; and
- `PrincipalType` decodes the same bytes as an ordinary contract principal.

The codec does not decide whether a callable schema is legal in an execution epoch. Callers MUST
apply the appropriate epoch-aware admission policy at their typed-value boundary. This separation
lets the same bytes represent historical and current schema views without making physical decoding
depend on execution history.

Descriptor-guided reconstruction always emits the canonical contract-principal consensus bytes.
Those bytes intentionally contain no trait identity.

## Optional and response bodies

### Optional

An optional `none` body is:

| Offset | Length | Field | Encoding | Meaning |
| ---- | ---- | ---- | ---- | ---- |
| `0` | 1 byte | Optional tag | `u8` | MUST be `00`; no bytes may follow |

An optional `some` body is:

| Offset | Length | Field | Encoding | Meaning |
| ---- | ---- | ---- | ---- | ---- |
| `0` | 1 byte | Optional tag | `u8` | MUST be `01` |
| `1` | `B - 1` bytes | Active child | Packed body for the child type | Consumes the remainder of the enclosing frame |

`none` MUST contain no bytes after its tag. `some` consumes the remainder of its frame as its active
child.

### Response

A response `err` body is:

| Offset | Length | Field | Encoding | Meaning |
| ---- | ---- | ---- | ---- | ---- |
| `0` | 1 byte | Response tag | `u8` | MUST be `00` |
| `1` | `B - 1` bytes | Active error child | Packed body for the error type | Consumes the remainder of the enclosing frame |

A response `ok` body is:

| Offset | Length | Field | Encoding | Meaning |
| ---- | ---- | ---- | ---- | ---- |
| `0` | 1 byte | Response tag | `u8` | MUST be `01` |
| `1` | `B - 1` bytes | Active success child | Packed body for the success type | Consumes the remainder of the enclosing frame |

The inactive response branch contributes no physical bytes and MUST NOT affect parent framing.

## Fixed-width classification

Only the following active values are fixed-width:

- a Boolean, with width 1; and
- a tuple whose every active field is recursively fixed-width, with width equal to the checked sum
  of its field widths.

All other active values are variable-width. In particular, integers, principals, callables,
sequences, optionals, and responses remain variable-width even when one particular value happens to
have a fixed physical length. This rule prevents declared bounds and inactive branches from changing
parent layout.

## Offset directories

Variable-width tuple fields and list elements use a canonical offset directory:

Let `W` be the offset width selected by `width_code`, and let `P` be the total byte length of
`child_data`:

| Offset | Length | Field | Encoding | Meaning |
| ---- | ---- | ---- | ---- | ---- |
| `0` | 1 byte | Width code | `u8` | Selects `W` from the table below |
| `1` | `(N + 1) * W` bytes | Offsets | `N + 1` little-endian unsigned integers of width `W` | Child boundaries relative to the start of `child_data` |
| `1 + (N + 1) * W` | `P` bytes | Child data | Concatenated packed child bodies | Complete remainder of the directory frame |

The width code and encoded offset type are:

| `width_code` | Offset encoding | Allowed child-data length |
| ---- | ---- | ---- |
| `00` | `u8` | `0..=255` |
| `01` | `u16le` | `256..=65,535` |
| `02` | `u32le` | `65,536..=u32::MAX` |

The width MUST be the narrowest width capable of representing the complete `child_data` length.

Offsets are relative to the start of `child_data`. The following conditions MUST hold:

- `offsets[0] == 0`;
- `offsets[N] == child_data.len()`;
- offsets are monotonically non-decreasing; and
- every offset is within `child_data`.

Child `i` occupies `child_data[offsets[i]..offsets[i + 1]]`. Repeated offsets are valid when a child
has an empty body.

The child count is supplied by the tuple schema, value-shape descriptor, or the list's encoded
count; it is not repeated in the directory.

## Tuple body

Tuple field names and field count are omitted from the packed body. Fields are encoded in the
canonical order of the value's `ClarityName` map.

If every active field is fixed-width:

| Offset | Length | Field | Encoding | Meaning |
| ---- | ---- | ---- | ---- | ---- |
| `sum(width(field_j), j < i)` | Fixed width of field `i` | Field `i` | Packed body for field `i` | Repeated for `0 <= i < N`; no directory or padding |

Otherwise, the complete tuple body uses the [offset-directory layout](#offset-directories) with
`N` children.

Typed decoding obtains names, child types, and count from the expected tuple schema.
Descriptor-guided reconstruction obtains them from the value-shape descriptor. Field names MUST be
strictly increasing and the complete tuple body MUST be consumed.

## List body

Every list begins with its active element count:

| Offset | Length | Field | Encoding | Meaning |
| ---- | ---- | ---- | ---- | ---- |
| `0` | 4 bytes | Element count | `u32le` | Number of active list elements |
| `4` | `B - 4` bytes | Element region | Layout selected below | Packed bodies for all active elements |

An empty list has `count == 0` and an empty `element_region`.

For a non-empty list, the encoder selects exactly one layout from the active elements, in the
following order:

1. unsigned-integer lane, if every element is a `uint`;
2. signed-integer lane, if every element is an `int`;
3. Boolean lane, if every element is a Boolean;
4. fixed concatenation, if every element is fixed-width; or
5. offset-directory framing otherwise.

The declared list element type and maximum bound MUST NOT select the physical layout.

### Integer lanes

An unsigned-integer lane uses:

| Offset | Length | Field | Encoding | Meaning |
| ---- | ---- | ---- | ---- | ---- |
| `i * W` | `W` bytes | Element `i` | Unsigned big-endian, zero-extended to `W` | Repeated for `0 <= i < count`; no per-element framing |

A signed-integer lane uses:

| Offset | Length | Field | Encoding | Meaning |
| ---- | ---- | ---- | ---- | ---- |
| `i * W` | `W` bytes | Element `i` | Two's-complement big-endian, sign-extended to `W` | Repeated for `0 <= i < count`; no per-element framing |

`W` is inferred as `element_region.len() / count`; it is not stored separately. The region MUST be
non-empty and evenly divisible by the non-zero count. `W` MUST be in `1..=16`.

For an unsigned lane, `W` is the maximum minimal unsigned width of all active elements, with a
minimum lane width of one. Each element is zero-extended to `W` bytes. If `W > 1`, at least one
element's first byte MUST be non-zero.

For a signed lane, `W` is the maximum minimal two's-complement width of all active elements, with a
minimum lane width of one. Each element is sign-extended to `W` bytes. If `W > 1`, at least one
element MUST require exactly `W` bytes.

### Boolean lane

| Offset | Length | Field | Encoding | Meaning |
| ---- | ---- | ---- | ---- | ---- |
| `0` | `ceil(count / 8)` bytes | Boolean bitset | Least-significant-bit first | Element `i` is bit `i % 8` of byte `i / 8` |

Element `i` is bit `i % 8` of byte `i / 8`; the least-significant bit is used first. Unused high
bits in the final byte MUST be zero.

### Fixed-width elements

Fixed-width element bodies are concatenated with no directory. For historical heterogeneous lists,
each active element's own fixed width is used during descriptor-guided reconstruction. Ordinary
typed lists use the one width implied by their element schema.

### Variable-width elements

The element region is `directory(count)`. Each directory child is one complete packed element body.

## Encoding procedure

Given a runtime value, a canonical encoder MUST:

1. compute its exact canonical consensus byte length;
2. encode its active body recursively, selecting tuple and list layouts only from active values;
3. prefix the body with the four-byte packed record envelope; and
4. when descriptor-guided reconstruction is required, derive the canonical value-shape descriptor
   from the same active value.

The encoder MUST NOT serialize declared bounds, tuple field names, inactive optional or response
branches, or callable trait metadata into the packed body. Tuple names are present only in the
value-shape descriptor. A typed writer that already obtained the consensus length while hashing or
serializing can reuse that checked length rather than serialize the value again.

## Value-shape descriptor

The value-shape descriptor supplies only information omitted from packed bytes that is necessary for
descriptor-guided reconstruction. It uses the
[value-shape descriptor envelope](#value-shape-descriptor-envelope) defined above.

The descriptor MUST contain exactly one shape with no trailing bytes. Its total length MUST NOT
exceed `BOUND_VALUE_SHAPE_BYTES` (currently 2,097,153 bytes), and its recursive depth MUST NOT
exceed `MAX_TYPE_DEPTH` (currently 32 nodes including the root).

### Shape opcodes

Each shape starts with a one-byte opcode at offset zero. Shape-specific bytes, when present, begin
at offset one:

| Offset | Length | Opcode | Shape | Bytes following the opcode |
| ---- | ---- | ---- | ---- | ---- |
| `0` | 1 byte | `00` | Signed integer | None |
| `0` | 1 byte | `01` | Unsigned integer | None |
| `0` | 1 byte | `02` | Boolean | None |
| `0` | 1 byte | `03` | Buffer | None |
| `0` | 1 byte | `04` | ASCII string | None |
| `0` | 1 byte | `05` | UTF-8 string | None |
| `0` | 1 byte | `06` | Principal or callable identity | None |
| `0` | 1 byte | `07` | Optional `none` | None |
| `0` | 1 byte | `08` | Optional `some` | One child shape |
| `0` | 1 byte | `09` | Response `ok` only | One `ok` child shape |
| `0` | 1 byte | `0a` | Response `err` only | One `err` child shape |
| `0` | 1 byte | `0b` | Response with observed `ok` and `err` shapes | `ok` shape, then `err` shape |
| `0` | 1 byte | `0c` | Tuple | Tuple descriptor |
| `0` | 1 byte | `0d` | Empty list | None |
| `0` | 1 byte | `0e` | Non-empty list with one shared shape | One element shape |
| `0` | 1 byte | `0f` | Historical list with per-element shapes | List-elements descriptor |

Unknown opcodes MUST be rejected.

`06` deliberately merges ordinary principals and callable contracts because their canonical
consensus bytes contain the same contract-principal identity.

`0b` normally arises by merging response shapes across list elements. A shape for one standalone
response contains only its active branch.

### Tuple descriptor

Let `V` be the byte length of the encoded `field_count`. After reading the count, the decoder sets
`cursor = 1 + V` and advances it through the repeated field entries:

| Offset | Length | Field | Encoding | Meaning |
| ---- | ---- | ---- | ---- | ---- |
| `0` | 1 byte | Tuple opcode | `u8` | MUST be `0c` |
| `1` | `V` bytes | Field count | Minimal `varuint` | Non-zero number of tuple fields |
| `cursor` | 1 byte | Name length | `u8` | Byte length `L` of the following field name |
| `cursor + 1` | `L` bytes | Field name | Valid `ClarityName` bytes | Names MUST be strictly increasing |
| `cursor + 1 + L` | Shape-dependent | Child shape | One complete shape | Followed immediately by the next field entry, repeated `field_count` times |

`field_count` MUST be non-zero. Each name MUST be a valid `ClarityName`, and names MUST be strictly
increasing. The descriptor records active child shapes in the same order used by the packed tuple
body.

### List descriptors

| Variant | Offset | Length | Field | Encoding | Meaning |
| ---- | ---- | ---- | ---- | ---- | ---- |
| Empty list | `0` | 1 byte | List opcode | `u8` | MUST be `0d`; no bytes may follow |
| Shared shape | `0` | 1 byte | List opcode | `u8` | MUST be `0e` |
| Shared shape | `1` | Shape-dependent | Element shape | One complete shape | Shared by every active element |
| Per-element shapes | `0` | 1 byte | List opcode | `u8` | MUST be `0f` |
| Per-element shapes | `1` | Variable | Element count | Minimal `varuint` | Non-zero count that MUST equal the packed list count |
| Per-element shapes | `cursor` | Shape-dependent | Element shape | One complete shape | Repeated `element_count` times with no padding |

`element_count` in a per-element descriptor MUST be non-zero and MUST equal the packed list count
during reconstruction. For that variant, `cursor` starts immediately after the encoded element count
and advances by each complete element shape.

Ordinary lists MUST use one shared element shape whenever all element shapes can merge. The
per-element form is reserved for historical unsanitized lists whose element shapes cannot merge. A
parser MUST reject a per-element descriptor whose shapes are mergeable.

Shape merging follows these rules:

- identical scalar, sequence, or principal shapes merge to themselves;
- absent and present optional child shapes merge to the present shape;
- response shapes merge their observed `ok` and `err` branches independently;
- tuples merge only when names and arity match, then merge each child;
- list shapes recursively merge their element shapes; and
- incompatible shapes do not merge.

### Descriptor varuint

Tuple field counts and per-element list counts use minimal unsigned LEB128. For byte `i`:

| Offset | Length | Field | Encoding | Meaning |
| ---- | ---- | ---- | ---- | ---- |
| `i` | 1 byte | Value group `i` and continuation | Unsigned LEB128 byte | Bits `0..6` are value bits in least-significant-group-first order; bit `7` is `1` when another byte follows and `0` on the terminal byte |

The complete `varuint` additionally obeys these canonicality rules:

- the terminal byte MUST NOT contain a zero group when more than one byte was used; and
- overflow of the host `usize` MUST be rejected.

## Typed decoding

A typed decoder receives a complete packed record and expected `TypeSignature`. It MUST:

1. parse and validate the packed version, then read the three-byte logical length;
2. decode the complete body under the expected schema;
3. enforce sequence and list bounds, tuple fields, and callable schema identity;
4. enforce every canonical scalar, lane, and framing rule;
5. reject unsupported active `NoType` and analysis-only `ListUnionType` states;
6. reject missing or trailing bytes; and
7. compare its accumulated consensus length with the record header.

The expected schema provides omitted tuple names, declared bounds, inactive wrapper branches, list
element types, and callable trait identity. It MUST NOT change the physical interpretation selected
by the canonical active value. Callers are responsible for applying epoch-aware admission and
sanitization before encoding or after decoding, as appropriate for their execution context.

Consensus transcoding preserves the complete active value. Historical unsanitized values can
contain data omitted by their cached read schema, so direct typed decoding is not guaranteed for
those records. Such compatibility reads require the value-shape descriptor and descriptor-guided
reconstruction before applying the legacy sanitizing typed deserializer.

## Descriptor-guided reconstruction and audit

Descriptor-guided reconstruction receives a complete packed record and value-shape descriptor. It
MUST validate both grammars and reconstruct exactly the canonical Clarity consensus bytes described
by the pair.

Structural reconstruction alone proves that the pair is well framed and produces the declared
logical length. It does not prove that the reconstructed bytes deserialize as a valid bounded
Clarity value or that the descriptor is the most specific canonical descriptor for those bytes.
Consumers handling untrusted or possibly corrupt records MUST use the full canonical audit before
hashing, serving, or otherwise relying on the reconstructed bytes.

A full canonical audit MUST additionally:

1. deserialize the reconstructed consensus bytes as one exact untyped Clarity value;
2. reserialize it and require byte-for-byte equality;
3. re-encode its packed record and value-shape descriptor; and
4. require both outputs to equal the stored inputs byte for byte.

This catches structurally valid but over-general descriptors, non-canonical consensus encodings, and
any divergence between typed encoding and migration transcoding.

## Bounds

Version 1 enforces the following current Clarity limits:

| Item | Limit |
| ---- | ---- |
| Canonical consensus value | `BOUND_VALUE_SERIALIZATION_BYTES` = 2,097,152 bytes |
| Value-shape descriptor | `BOUND_VALUE_SHAPE_BYTES` = 2,097,153 bytes |
| Value-shape depth | `MAX_TYPE_DEPTH` = 32 |
| Integer body or lane width | 16 bytes |
| Packed directory offset | `u32::MAX` |

The packed body has a conservative expansion bound:

```text
BOUND_PACKED_VALUE_BODY_BYTES =
    BOUND_VALUE_SERIALIZATION_BYTES
    + MAX_VALUE_SIZE * (4 + 5)
    + 5
```

With the current constants, this is 11,534,341 bytes. The four-byte packed record header is not
included in that bound.

The value-shape bound is one byte larger than the maximum consensus serialization. For a canonical
descriptor derived from a legal value, every shape node and tuple name is covered by at least as
many bytes in the corresponding consensus value. Merged optional, response, and list shapes
describe multiple active values whose combined consensus bytes cover every merged child. The
descriptor's version byte is its only byte without a consensus counterpart. Parsers apply the same
bound as a conservative resource ceiling before a full canonicality audit.

## Golden examples

`packed` below means the complete, independently versioned `packed_record`. `shape` means the
complete, independently versioned value-shape descriptor. Spaces only group fields; they are not
encoded.

### Scalars and byte sequences

These vectors cover every scalar and byte-sequence shape:

| Value | Consensus-length calculation | `packed` | `shape` |
| ---- | ---- | ---- | ---- |
| `-129` | `1 + 16 = 17` | `01 11 00 00  ff 7f` | `01 00` |
| `u256` | `1 + 16 = 17` | `01 11 00 00  01 00` | `01 01` |
| `false` | `1` | `01 01 00 00  00` | `01 02` |
| `true` | `1` | `01 01 00 00  01` | `01 02` |
| `0x00ff` | `1 + 4 + 2 = 7` | `01 07 00 00  00 ff` | `01 03` |
| `"Hi"` as ASCII | `1 + 4 + 2 = 7` | `01 07 00 00  48 69` | `01 04` |
| `u"é"` as UTF-8 | `1 + 4 + 2 = 7` | `01 07 00 00  c3 a9` | `01 05` |

The integer header counts the fixed 16-byte consensus integer even though its packed body is
minimal. Sequence headers count the consensus type prefix and omitted `u32be` payload length. UTF-8
bounds count one Unicode scalar in the example, while its consensus and packed payload contain two
bytes.

The buffer, ASCII, and UTF-8 bodies are all untagged byte strings. Their schema or shape opcode is
therefore essential. For example, packed bytes alone cannot distinguish `0x4869` from ASCII
`"Hi"`.

### Principals and callable contracts

Let the example issuer have version byte `16` (hexadecimal) followed by twenty `11` hash bytes.

A standard principal has consensus length `1 + 1 + 20 = 22`:

```text
packed =
01 16 00 00  00 16
11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11
^^ ^^^^^^^^  ^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
V1 length    kind       version + hash160

shape = 01 06
```

The contract principal with name `pool` has consensus length
`1 + 1 + 20 + 1 + 4 = 27`. The packed principal kind replaces the omitted consensus prefix, and the
enclosing frame replaces the omitted one-byte contract-name length:

```text
packed =
01 1b 00 00  01 16
11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11
70 6f 6f 6c
^^ ^^^^^^^^  ^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ ^^^^^^^^^^^
V1 length    kind       version + hash160                         "pool"

shape = 01 06
```

A callable contract with this identity has exactly the same packed record and shape. Under
`PrincipalType`, typed decoding produces a contract principal. Under `CallableType::Trait`, it
produces a callable and restores the trait identifier from the schema.

### Optional and response values

Wrapper tags select only the active packed child. Inactive branches do not contribute bytes or
affect framing.

| Value and expected type | Consensus-length calculation | `packed` | `shape` |
| ---- | ---- | ---- | ---- |
| `none` as `(optional uint)` | `1` | `01 01 00 00  00` | `01 07` |
| `(some u7)` | `1 + 17 = 18` | `01 12 00 00  01 07` | `01 08 01` |
| `(ok true)` | `1 + 1 = 2` | `01 02 00 00  01 01` | `01 09 02` |
| `(err u9)` | `1 + 17 = 18` | `01 12 00 00  00 09` | `01 0a 01` |

The packed response tags are `00 = err` and `01 = ok`. They are not the Clarity consensus response
prefixes `08` and `07`.

### Fixed-width tuple

For `{ a: true, b: false }`, both active fields are fixed-width Booleans. The tuple therefore
concatenates their bodies without a directory. Its consensus length is
`5 + (1 + 1 + 1) + (1 + 1 + 1) = 11`: five bytes for the tuple prefix and field count, then a
one-byte name length, one-byte name, and one-byte Boolean for each field.

```text
packed = 01 0b 00 00  01 00
         ^^ ^^^^^^^^  ^^^^^
         V1 length    true, false

shape  = 01  0c 02  01 61 02  01 62 02
         ^^  ^^^^^  ^^^^^^^^  ^^^^^^^^
         V1  tuple   a: bool   b: bool
```

### Variable-width tuple

For `{ a: u1, b: true }`, the integer makes the tuple variable-width. Its two child bodies have
lengths one and one, so the directory uses one-byte offsets `[0, 1, 2]`. The logical consensus
length is `5 + (1 + 1 + 17) + (1 + 1 + 1) = 27`:

```text
packed = 01 1b 00 00  00  00 01 02  01 01
         ^^ ^^^^^^^^  ^^  ^^^^^^^^  ^^^^^
         V1 length    W=1 offsets   u1, true

shape  = 01  0c 02  01 61 01  01 62 02
         ^^  ^^^^^  ^^^^^^^^  ^^^^^^^^
         V1  tuple   a: uint   b: bool
```

Directory width is selected from the total child-data length, not the largest individual child.
The width changes from `u8` to `u16le` at 256 child-data bytes and from `u16le` to `u32le` at
65,536 bytes.

### Empty list

An empty list has no active element shape or element bytes. Its declared element type and maximum
bound do not affect its physical representation:

```text
packed = 01 05 00 00  00 00 00 00
         ^^ ^^^^^^^^  ^^^^^^^^^^^
         V1 length    count = 0

shape  = 01 0d
```

### Unsigned-integer lane

For `(list u0 u255 u256)`, the logical consensus length is `5 + 3 * 17 = 56`. All elements share
the maximum minimal width of two bytes:

```text
packed = 01 38 00 00  03 00 00 00  00 00  00 ff  01 00
         ^^ ^^^^^^^^  ^^^^^^^^^^^  ^^^^^  ^^^^^  ^^^^^
         V1 length    count = 3     u0     u255   u256

shape  = 01 0e 01
```

### Signed-integer lane

For `(list -129 0 127)`, the two-byte signed lane sign-extends every element to the width required
by `-129`:

```text
packed = 01 38 00 00  03 00 00 00  ff 7f  00 00  00 7f
         ^^ ^^^^^^^^  ^^^^^^^^^^^  ^^^^^  ^^^^^  ^^^^^
         V1 length    count = 3    -129    0      127

shape  = 01 0e 00
```

### Boolean lane

For `(list true false true false true false true false true)`, elements `0`, `2`, `4`, `6`, and
`8` set bits in least-significant-bit-first order. The logical length is `5 + 9 = 14`:

```text
packed = 01 0e 00 00  09 00 00 00  55 01
         ^^ ^^^^^^^^  ^^^^^^^^^^^  ^^^^^
         V1 length    count = 9     bits

shape  = 01 0e 02
```

### Fixed-width element list

For a list containing `{ a: true, b: false }` and `{ a: false, b: true }`, each tuple body is two
bytes. The element bodies are concatenated without a directory. Each tuple has consensus length 11,
so the list's logical length is `5 + 2 * 11 = 27`:

```text
packed = 01 1b 00 00  02 00 00 00  01 00  00 01
         ^^ ^^^^^^^^  ^^^^^^^^^^^  ^^^^^  ^^^^^
         V1 length    count = 2    tuple0 tuple1

shape  = 01 0e  0c 02 01 61 02 01 62 02
```

### Variable-width element list

For `(list 0x01 0x0203)`, the buffer bodies have lengths one and two. The list uses a one-byte
directory with offsets `[0, 1, 3]`. Its consensus length is
`5 + (1 + 4 + 1) + (1 + 4 + 2) = 18`:

```text
packed = 01 12 00 00  02 00 00 00  00  00 01 03  01 02 03
         ^^ ^^^^^^^^  ^^^^^^^^^^^  ^^  ^^^^^^^^  ^^^^^^^^
         V1 length    count = 2    W=1 offsets   child data

shape  = 01 0e 03
```

### Merged response shape in a list

For `(list (ok u1) (err true))`, the response elements are variable-width and use directory offsets
`[0, 2, 4]`. The shared list shape records both response branches even though each element activates
only one:

```text
packed = 01 19 00 00  02 00 00 00  00  00 02 04  01 01  00 01
         ^^ ^^^^^^^^  ^^^^^^^^^^^  ^^  ^^^^^^^^  ^^^^^  ^^^^^
         V1 length    count = 2    W=1 offsets   ok u1   err true

shape  = 01 0e 0b 01 02
         ^^ ^^ ^^ ^^ ^^
         V1 list both uint bool
```

### Historical per-element list shape

A historical unsanitized list can contain tuple elements whose field sets do not merge. For a list
containing `{ a: u1 }` and `{ a: u1, b: true }`, consensus transcoding emits:

```text
packed =
01 38 00 00  02 00 00 00  00  00 04 0a
00 00 01 01  00 00 01 02 01 01

shape =
01 0f 02
0c 01 01 61 01
0c 02 01 61 01 01 62 02
```

The packed list directory has offsets `[0, 4, 10]`. Each child is itself a variable tuple body. The
descriptor is `V1`, per-element list, element count two, followed by the two incompatible tuple
shapes. Ordinary sanitized lists MUST use a shared shape instead.

## Versioning rule

Any change that alters packed bytes emitted for an already-supported value requires a new packed
version. An incompatible change to the value-shape grammar requires a new descriptor version.

A reader MUST validate each stream's version before parsing the remainder of that stream. Readers
MUST NOT attempt to distinguish the former versionless prototype from Version 1 by inspecting the
first byte: a prototype logical-length byte can equal a valid version. Prototype data must be
re-encoded under this specification.

Readers MUST fail closed on unsupported versions. Within one version, writers MUST NOT emit two
different physical representations for the same canonical value.
