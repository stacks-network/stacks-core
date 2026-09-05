// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Structured errors returned by the packed value codec.

use thiserror::Error;

use super::{PackedValueVersion, ValueShapeVersion};
use crate::errors::ClarityTypeError;
use crate::types::serialization::SerializationError;
use crate::types::{QualifiedContractIdentifier, StandardPrincipalData};

/// Errors produced by the packed value codec.
///
/// Categories identify where a failure was detected, not whether another
/// decoding strategy can recover it. In particular, schema-directed decoding
/// can report [`Self::Record`] when valid packed bytes were encoded from a
/// value whose active shape is incompatible with the caller's narrower schema.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PackedValueError {
    /// The record declares an unsupported packed-value wire version.
    #[error("unsupported packed value version: {version}")]
    UnsupportedPackedValueVersion {
        /// Unsupported record version byte.
        version: u8,
    },
    /// The descriptor declares an unsupported value-shape wire version.
    #[error("unsupported value-shape version: {version}")]
    UnsupportedValueShapeVersion {
        /// Unsupported descriptor version byte.
        version: u8,
    },
    /// The known record and shape versions cannot be used together.
    ///
    /// This is reserved for incompatible pairs introduced by future versions.
    #[error(
        "unsupported packed/shape version combination: {}/{}",
        packed.as_u8(),
        shape.as_u8()
    )]
    UnsupportedVersionCombination {
        /// Parsed packed-record version.
        packed: PackedValueVersion,
        /// Parsed value-shape version.
        shape: ValueShapeVersion,
    },
    /// A schema is unsupported or disagrees with the packed body.
    #[error(transparent)]
    Schema(#[from] PackedSchemaError),
    /// Consensus input contains trailing or noncanonical bytes.
    #[error("consensus value is not canonically serialized")]
    NonCanonicalConsensusValue,
    /// A packed value record violates its byte grammar or canonical encoding.
    #[error(transparent)]
    Record(#[from] PackedRecordError),
    /// A value-shape descriptor violates its byte grammar or canonical encoding.
    #[error(transparent)]
    Shape(#[from] ValueShapeError),
    /// A packed record and value-shape descriptor cannot reconstruct one value.
    #[error(transparent)]
    Reconstruction(#[from] ReconstructionError),
    /// An internal encoder or decoder invariant failed.
    #[error(transparent)]
    Invariant(#[from] PackedCodecInvariant),
    /// A checked size or offset calculation overflowed.
    #[error("packed value size overflow")]
    SizeOverflow,
    /// An existing Clarity type invariant failed.
    #[error("Clarity type error: {0}")]
    ClarityType(#[from] ClarityTypeError),
    /// The current consensus serializer rejected the value.
    #[error("consensus serialization error: {0}")]
    ConsensusSerialization(#[from] SerializationError),
}

/// Unsupported or mismatched caller-supplied schema states.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum PackedSchemaError {
    /// `NoType` cannot describe an active value.
    #[error("NoType cannot describe an active packed value")]
    NoType,
    /// `ListUnionType` is analysis-only and cannot describe a runtime value.
    #[error("ListUnionType is analysis-only")]
    ListUnionType,
    /// A buffer exceeds its declared schema bound.
    #[error("buffer length {actual} exceeds declared bound {maximum}")]
    BufferExceedsBound {
        /// Packed buffer length.
        actual: usize,
        /// Maximum length admitted by the schema.
        maximum: usize,
    },
    /// An ASCII string exceeds its declared byte bound.
    #[error("ASCII string length {actual} exceeds declared bound {maximum}")]
    AsciiStringExceedsBound {
        /// Packed ASCII byte length.
        actual: usize,
        /// Maximum byte length admitted by the schema.
        maximum: usize,
    },
    /// A UTF-8 string exceeds its declared character bound.
    #[error("UTF-8 character count {actual} exceeds declared bound {maximum}")]
    Utf8StringExceedsBound {
        /// Decoded Unicode scalar count.
        actual: usize,
        /// Maximum character count admitted by the schema.
        maximum: usize,
    },
    /// A list exceeds its declared element-count bound.
    #[error("list element count {actual} exceeds declared bound {maximum}")]
    ListExceedsBound {
        /// Packed list element count.
        actual: usize,
        /// Maximum element count admitted by the schema.
        maximum: usize,
    },
    /// A callable schema decoded a non-contract principal.
    #[error("callable requires a contract principal, found {actual}")]
    CallableRequiresContractPrincipal {
        /// Standard principal found in the packed body.
        actual: StandardPrincipalData,
    },
    /// A callable principal disagrees with its schema's contract identifier.
    #[error("callable contract {actual} does not match declared contract {expected}")]
    CallableContractMismatch {
        /// Contract identifier required by the schema.
        expected: Box<QualifiedContractIdentifier>,
        /// Contract identifier decoded from the packed body.
        actual: Box<QualifiedContractIdentifier>,
    },
}

/// Malformed or noncanonical packed value-record errors.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum PackedRecordError {
    /// The record has no version byte.
    #[error("empty packed value record")]
    Empty,
    /// The V1 envelope is incomplete.
    #[error("V1 header requires {required} bytes, found {actual}")]
    TruncatedV1Header {
        /// Available record byte length.
        actual: usize,
        /// Required V1 header byte length.
        required: usize,
    },
    /// The packed body exceeds the V1 expansion bound.
    #[error("packed value body length {actual} exceeds maximum {maximum}")]
    BodyTooLarge {
        /// Actual packed body length.
        actual: usize,
        /// Maximum body length admitted by the version.
        maximum: usize,
    },
    /// The declared logical consensus length exceeds the Clarity value bound.
    #[error("declared consensus length {declared} exceeds maximum {maximum}")]
    DeclaredConsensusLengthTooLarge {
        /// Logical consensus length declared by the record.
        declared: u32,
        /// Maximum consensus value length.
        maximum: u32,
    },
    /// A principal has no kind byte.
    #[error("missing principal kind")]
    MissingPrincipalKind,
    /// A contract principal omits its issuer bytes.
    #[error("contract principal body length {actual} is shorter than issuer length {minimum}")]
    InvalidContractPrincipal {
        /// Bytes available after the principal-kind byte.
        actual: usize,
        /// Bytes required for the issuer.
        minimum: usize,
    },
    /// A principal kind byte is unknown.
    #[error("invalid principal kind byte {kind:#04x}")]
    InvalidPrincipalKind {
        /// Unsupported principal-kind byte.
        kind: u8,
    },
    /// A canonical signed scalar has no bytes.
    #[error("canonical signed integer is empty")]
    EmptySignedInteger,
    /// A signed scalar occupies more than 16 bytes.
    #[error("signed integer width {actual} exceeds maximum {maximum}")]
    SignedIntegerTooWide {
        /// Encoded scalar width.
        actual: usize,
        /// Maximum packed scalar width.
        maximum: usize,
    },
    /// A signed scalar contains redundant sign-extension bytes.
    #[error("signed integer width {actual} is not minimal; expected {minimum}")]
    NonMinimalSignedInteger {
        /// Encoded scalar width.
        actual: usize,
        /// Minimal scalar width.
        minimum: usize,
    },
    /// A canonical unsigned scalar has no bytes.
    #[error("canonical unsigned integer is empty")]
    EmptyUnsignedInteger,
    /// An unsigned scalar occupies more than 16 bytes.
    #[error("unsigned integer width {actual} exceeds maximum {maximum}")]
    UnsignedIntegerTooWide {
        /// Encoded scalar width.
        actual: usize,
        /// Maximum packed scalar width.
        maximum: usize,
    },
    /// An unsigned scalar contains redundant leading zero bytes.
    #[error("unsigned integer width {actual} is not minimal; expected {minimum}")]
    NonMinimalUnsignedInteger {
        /// Encoded scalar width.
        actual: usize,
        /// Minimal scalar width.
        minimum: usize,
    },
    /// A standard principal body has the wrong byte length.
    #[error("standard principal body length {actual} does not equal {expected}")]
    InvalidStandardPrincipalLength {
        /// Actual standard-principal body length.
        actual: usize,
        /// Required standard-principal body length.
        expected: usize,
    },
    /// A standard principal contains an invalid address-version byte.
    #[error("invalid standard principal version {version}")]
    InvalidStandardPrincipalVersion {
        /// Invalid address-version byte.
        version: u8,
    },
    /// A contract name is not valid UTF-8.
    #[error(
        "invalid contract name UTF-8 at byte {valid_up_to} (invalid sequence length: {error_len:?})"
    )]
    InvalidContractNameUtf8 {
        /// Number of valid leading bytes.
        valid_up_to: usize,
        /// Invalid sequence length, or `None` for an incomplete sequence.
        error_len: Option<usize>,
    },
    /// A contract name violates the Clarity name grammar.
    #[error("invalid contract name of length {length}")]
    InvalidContractName {
        /// Invalid contract-name byte length.
        length: usize,
    },
    /// A canonical unsigned integer lane has no elements.
    #[error("unsigned lane is empty (element count {count}, data length {data_length})")]
    EmptyUnsignedLane {
        /// Declared element count.
        count: usize,
        /// Encoded lane byte length.
        data_length: usize,
    },
    /// An unsigned integer lane occupies more than 16 bytes per element.
    #[error("unsigned lane element width {actual} exceeds maximum {maximum}")]
    UnsignedLaneTooWide {
        /// Encoded bytes per lane element.
        actual: usize,
        /// Maximum packed scalar width.
        maximum: usize,
    },
    /// An unsigned integer lane uses a wider width than any element requires.
    #[error("unsigned lane element width {actual} is not minimal; expected {minimum}")]
    NonMinimalUnsignedLane {
        /// Encoded bytes per lane element.
        actual: usize,
        /// Minimal shared lane width.
        minimum: usize,
    },
    /// A canonical signed integer lane has no elements.
    #[error("signed lane is empty (element count {count}, data length {data_length})")]
    EmptySignedLane {
        /// Declared element count.
        count: usize,
        /// Encoded lane byte length.
        data_length: usize,
    },
    /// A signed integer lane occupies more than 16 bytes per element.
    #[error("signed lane element width {actual} exceeds maximum {maximum}")]
    SignedLaneTooWide {
        /// Encoded bytes per lane element.
        actual: usize,
        /// Maximum packed scalar width.
        maximum: usize,
    },
    /// A signed integer lane uses a wider width than any element requires.
    #[error("signed lane element width {actual} is not minimal; expected {minimum}")]
    NonMinimalSignedLane {
        /// Encoded bytes per lane element.
        actual: usize,
        /// Minimal shared lane width.
        minimum: usize,
    },
    /// An integer lane cannot be divided evenly among its elements.
    #[error("integer lane length {length} is not divisible by element count {count}")]
    IndivisibleIntegerLane {
        /// Encoded lane byte length.
        length: usize,
        /// Declared lane element count.
        count: usize,
    },
    /// A boolean lane has the wrong byte length for its element count.
    #[error("boolean lane length {actual} does not equal expected length {expected}")]
    InvalidBooleanLaneLength {
        /// Encoded Boolean-lane byte length.
        actual: usize,
        /// Required byte length for the element count.
        expected: usize,
    },
    /// Unused bits in the final boolean-lane byte are nonzero.
    #[error("boolean lane byte {last_byte:#04x} contains nonzero padding mask {unused_mask:#04x}")]
    NonZeroBooleanLanePadding {
        /// Final encoded lane byte.
        last_byte: u8,
        /// Mask selecting unused bits.
        unused_mask: u8,
    },
    /// A tagged value has no discriminant byte.
    #[error("missing discriminant")]
    MissingDiscriminant,
    /// A three-byte unsigned integer is incomplete.
    #[error("u24 requires {required} bytes, found {actual}")]
    TruncatedU24 {
        /// Available byte length.
        actual: usize,
        /// Required byte length.
        required: usize,
    },
    /// A four-byte unsigned integer is incomplete.
    #[error("u32 requires {required} bytes, found {actual}")]
    TruncatedU32 {
        /// Available byte length.
        actual: usize,
        /// Required byte length.
        required: usize,
    },
    /// A boolean discriminant is not zero or one.
    #[error("invalid Boolean body of length {length} with first byte {first_byte:?}")]
    InvalidBoolean {
        /// Encoded Boolean body length.
        length: usize,
        /// First body byte, when present.
        first_byte: Option<u8>,
    },
    /// An ASCII string contains a non-ASCII byte.
    #[error("invalid ASCII byte {byte:#04x} at offset {offset}")]
    InvalidAsciiString {
        /// Offset of the first invalid byte.
        offset: usize,
        /// First invalid byte.
        byte: u8,
    },
    /// A UTF-8 string contains invalid encoded bytes.
    #[error("invalid UTF-8 string at byte {valid_up_to} (invalid sequence length: {error_len:?})")]
    InvalidUtf8String {
        /// Number of valid leading bytes.
        valid_up_to: usize,
        /// Invalid sequence length, or `None` for an incomplete sequence.
        error_len: Option<usize>,
    },
    /// An optional discriminant is not zero or one.
    #[error("invalid optional discriminant {discriminant:#04x} with child length {child_length}")]
    InvalidOptional {
        /// Encoded optional discriminant.
        discriminant: u8,
        /// Bytes following the discriminant.
        child_length: usize,
    },
    /// A response discriminant is not zero or one.
    #[error("invalid response discriminant {discriminant:#04x}")]
    InvalidResponse {
        /// Encoded response discriminant.
        discriminant: u8,
    },
    /// A fixed-width tuple omits bytes required by its schema.
    #[error("fixed tuple requires byte offset {required_end}, but body length is {actual}")]
    TruncatedFixedTuple {
        /// End offset required by the current field.
        required_end: usize,
        /// Available tuple body length.
        actual: usize,
    },
    /// A fixed-width tuple has unconsumed bytes.
    #[error("fixed tuple consumed {consumed} of {actual} body bytes")]
    FixedTupleTrailingBytes {
        /// Bytes consumed by declared fields.
        consumed: usize,
        /// Actual tuple body length.
        actual: usize,
    },
    /// An empty list contains an unexpected element region.
    #[error("empty list has an unexpected {actual}-byte element region")]
    EmptyListHasElementRegion {
        /// Unexpected element-region byte length.
        actual: usize,
    },
    /// A fixed-width list body does not match its element count.
    #[error("fixed list element region length {actual} does not equal expected {expected}")]
    FixedListLengthMismatch {
        /// Actual element-region byte length.
        actual: usize,
        /// Expected element-region byte length.
        expected: usize,
    },
    /// A directory width tag is unknown.
    #[error("invalid offset-width code {code:#04x}")]
    InvalidOffsetWidthCode {
        /// Unsupported directory width code.
        code: u8,
    },
    /// A directory has no width tag.
    #[error("missing offset-width code")]
    MissingOffsetWidthCode,
    /// A directory omits one or more encoded offsets.
    #[error("offset directory requires {required} bytes, found {actual}")]
    TruncatedOffsetDirectory {
        /// Available directory byte length.
        actual: usize,
        /// Required directory byte length.
        required: usize,
    },
    /// A directory does not use the narrowest possible offset width.
    #[error("offset width {actual} is not minimal; expected {minimum}")]
    NonMinimalOffsetWidth {
        /// Encoded bytes per offset.
        actual: usize,
        /// Minimal bytes required per offset.
        minimum: usize,
    },
    /// A directory's first or final offset does not frame its data.
    #[error("directory endpoints {first}..{last} do not frame element-region length {data_length}")]
    InvalidDirectoryEndpoints {
        /// First encoded child offset.
        first: usize,
        /// Final encoded child offset.
        last: usize,
        /// Encoded child-data byte length.
        data_length: usize,
    },
    /// A directory offset points beyond its encoded child-data region.
    #[error(
        "directory offset {current} at index {index} exceeds element-region length {data_length}"
    )]
    DirectoryOffsetOutOfRange {
        /// Index of the out-of-range offset.
        index: usize,
        /// Encoded child offset.
        current: usize,
        /// Encoded child-data byte length.
        data_length: usize,
    },
    /// Directory offsets are not monotonically increasing.
    #[error("directory offset {current} at index {index} precedes previous offset {previous}")]
    InvalidDirectoryOrdering {
        /// Index of the non-monotonic offset.
        index: usize,
        /// Previous child offset.
        previous: usize,
        /// Current child offset.
        current: usize,
    },
    /// The decoded consensus length differs from the record header.
    #[error("declared consensus length {declared} does not equal decoded length {actual}")]
    ConsensusLengthMismatch {
        /// Length declared by the packed record.
        declared: u32,
        /// Length computed from the decoded value.
        actual: u32,
    },
}

/// Malformed or noncanonical value-shape descriptor errors.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ValueShapeError {
    /// The descriptor has no version byte.
    #[error("empty value shape")]
    Empty,
    /// The descriptor exceeds its maximum encoded size.
    #[error("value-shape length {actual} exceeds maximum {maximum}")]
    TooLarge {
        /// Actual descriptor byte length.
        actual: usize,
        /// Maximum descriptor length admitted by the version.
        maximum: usize,
    },
    /// A shape opcode is unknown.
    #[error("unknown value-shape opcode {opcode:#04x}")]
    UnknownOpcode {
        /// Unsupported opcode byte.
        opcode: u8,
    },
    /// The root shape does not consume the complete descriptor.
    #[error("value shape has {trailing} trailing bytes")]
    TrailingBytes {
        /// Bytes remaining after the root shape node.
        trailing: usize,
    },
    /// Shape nesting exceeds the codec recursion bound.
    #[error("value-shape depth {actual} reaches maximum {maximum}")]
    MaximumDepthExceeded {
        /// Attempted zero-based node depth.
        actual: u8,
        /// Maximum admitted node depth.
        maximum: u8,
    },
    /// A tuple shape has no fields.
    #[error("value-shape tuple has no fields")]
    EmptyTuple,
    /// A tuple field count exceeds the remaining descriptor bytes.
    #[error(
        "value-shape tuple declares {declared} fields with only {remaining_bytes} bytes remaining"
    )]
    TupleFieldCountExceedsDescriptor {
        /// Declared tuple field count.
        declared: usize,
        /// Descriptor bytes remaining after the count.
        remaining_bytes: usize,
    },
    /// A tuple field omits some or all of its name.
    #[error("tuple name declares {declared} bytes with only {remaining} remaining")]
    TruncatedTupleName {
        /// Declared tuple-name byte length.
        declared: usize,
        /// Available descriptor bytes.
        remaining: usize,
    },
    /// A tuple field name is not valid UTF-8.
    #[error(
        "invalid tuple name UTF-8 at byte {valid_up_to} (invalid sequence length: {error_len:?})"
    )]
    InvalidTupleNameUtf8 {
        /// Number of valid leading bytes.
        valid_up_to: usize,
        /// Invalid sequence length, or `None` for an incomplete sequence.
        error_len: Option<usize>,
    },
    /// A tuple field name violates the Clarity name grammar.
    #[error("invalid Clarity tuple name of length {length}")]
    InvalidTupleName {
        /// Invalid tuple-name byte length.
        length: usize,
    },
    /// Tuple fields are not strictly ordered by name.
    #[error("tuple field {current:?} is not ordered after {previous:?}")]
    NonCanonicalTupleFields {
        /// Previous decoded tuple field name.
        previous: Box<str>,
        /// Current out-of-order or duplicate field name.
        current: Box<str>,
    },
    /// A per-element list shape count is zero or exceeds the descriptor.
    #[error(
        "per-element list shape declares {declared} elements with {remaining_bytes} bytes remaining"
    )]
    InvalidPerElementListCount {
        /// Declared per-element shape count.
        declared: usize,
        /// Remaining descriptor bytes.
        remaining_bytes: usize,
    },
    /// A per-element list descriptor was used where one shared shape suffices.
    #[error("mergeable list uses {element_count} per-element shapes")]
    MergeableListUsesPerElementShapes {
        /// Number of redundant per-element shapes.
        element_count: usize,
    },
    /// A shape varuint contains redundant groups.
    #[error("value-shape varuint uses {encoded_groups} groups for value {value}")]
    NonCanonicalVarUint {
        /// Encoded seven-bit groups.
        encoded_groups: usize,
        /// Decoded integer value.
        value: usize,
    },
    /// A shape varuint cannot be represented as a `usize`.
    #[error(
        "value-shape varuint at byte offset {offset} exceeds usize after {encoded_groups} groups"
    )]
    VarUintOverflow {
        /// Complete-descriptor offset of the first varuint byte.
        offset: usize,
        /// Encoded groups consumed before overflow was established.
        encoded_groups: usize,
    },
    /// A shape node is incomplete.
    #[error("truncated value shape at byte offset {offset}")]
    Truncated {
        /// Descriptor offset where another byte was required.
        offset: usize,
    },
}

/// Errors caused by disagreement between packed and value-shape streams.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ReconstructionError {
    /// Re-encoding reconstructed consensus produces different packed bytes.
    #[error(
        "reconstructed packed value first differs at byte {first_mismatch} (stored length {stored_length}, canonical length {canonical_length})"
    )]
    NonCanonicalPackedValue {
        /// First differing byte offset, or the shorter stream length.
        first_mismatch: usize,
        /// Stored packed-record byte length.
        stored_length: usize,
        /// Canonical re-encoded byte length.
        canonical_length: usize,
    },
    /// The descriptor is not the canonical shape for the reconstructed value.
    #[error(
        "value shape first differs at byte {first_mismatch} (stored length {stored_length}, canonical length {canonical_length})"
    )]
    NonCanonicalValueShape {
        /// First differing byte offset, or the shorter stream length.
        first_mismatch: usize,
        /// Stored descriptor byte length.
        stored_length: usize,
        /// Canonical descriptor byte length.
        canonical_length: usize,
    },
    /// Reconstructed consensus output differs from the record's declared length.
    #[error("reconstructed consensus length {actual} does not equal declared length {declared}")]
    ConsensusLengthMismatch {
        /// Logical length declared by the packed record.
        declared: usize,
        /// Reconstructed consensus byte length.
        actual: usize,
    },
    /// Reconstructed output would exceed the record's declared length.
    #[error("reconstruction would reach length {attempted}, exceeding declared length {declared}")]
    ConsensusExceedsDeclaredLength {
        /// Logical length declared by the packed record.
        declared: usize,
        /// Output length attempted by reconstruction.
        attempted: usize,
    },
    /// An optional's discriminant disagrees with its shape node.
    #[error("packed optional disagrees with value shape")]
    OptionalShapeMismatch,
    /// A response shape omits the branch selected by the record.
    #[error("response branch for discriminant {discriminant:#04x} is absent from value shape")]
    MissingResponseBranch {
        /// Packed response discriminant.
        discriminant: u8,
    },
    /// A fixed-width tuple omits bytes required by its shape.
    #[error("fixed tuple requires byte offset {required_end}, but body length is {actual}")]
    TruncatedFixedTuple {
        /// End offset required by the current field.
        required_end: usize,
        /// Available tuple body length.
        actual: usize,
    },
    /// A fixed-width tuple has unconsumed bytes.
    #[error("fixed tuple consumed {consumed} of {actual} body bytes")]
    FixedTupleTrailingBytes {
        /// Bytes consumed by shape fields.
        consumed: usize,
        /// Actual tuple body length.
        actual: usize,
    },
    /// An empty record list disagrees with its shape node.
    #[error("empty list has {shape_count} per-element value shapes")]
    EmptyListShapeMismatch {
        /// Per-element shapes supplied for the empty list.
        shape_count: usize,
    },
    /// A non-empty list has no shared or per-element shape.
    #[error("non-empty list of {record_count} elements has no element shape")]
    MissingListElementShape {
        /// Element count declared by the packed record.
        record_count: usize,
    },
    /// A record list count differs from its per-element shape count.
    #[error("list element count {record_count} does not equal shape count {shape_count}")]
    ListShapeCountMismatch {
        /// Element count declared by the packed record.
        record_count: usize,
        /// Available per-element shape count.
        shape_count: usize,
    },
    /// A fixed-width list's byte length disagrees with its shape and count.
    #[error("fixed list element region length {actual} does not equal expected {expected}")]
    FixedListLengthMismatch {
        /// Actual element-region byte length.
        actual: usize,
        /// Length required by the value shapes.
        expected: usize,
    },
}

/// Failures of invariants maintained entirely within the packed codec.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum PackedCodecInvariant {
    /// The encoder's measured body differs from its precomputed length.
    #[error("encoder measured body length {expected}, but wrote {actual} bytes")]
    EncoderBodyLengthMismatch {
        /// Body length computed before allocation.
        expected: usize,
        /// Body bytes actually written.
        actual: usize,
    },
    /// The V1 record parser received a record dispatched to another version.
    #[error("V1 record parser expected version {expected}, found {actual}")]
    IncorrectV1RecordVersion {
        /// Version required by the V1 parser.
        expected: u8,
        /// Version byte supplied to the parser.
        actual: u8,
    },
    /// The V1 parser's fixed-size header did not contain three length bytes.
    #[error("V1 length header requires {expected} bytes, found {actual}")]
    InvalidV1LengthHeader {
        /// Required length-field byte count.
        expected: usize,
        /// Supplied length-field byte count.
        actual: usize,
    },
    /// A directory helper received a slice of the wrong width.
    #[error("invalid encoded offset width {actual}")]
    InvalidEncodedOffsetWidth {
        /// Offset byte width supplied to a private helper.
        actual: usize,
    },
    /// A private directory helper was called with an invalid child index.
    #[error("directory offset index {index} exceeds maximum index {maximum}")]
    DirectoryIndexOutOfBounds {
        /// Requested offset index.
        index: usize,
        /// Maximum valid offset index.
        maximum: usize,
    },
    /// A validated directory could not address one encoded offset.
    #[error("directory offset byte range {start}..{end} exceeds encoded length {length}")]
    DirectoryOffsetOutOfBounds {
        /// Start of the requested offset bytes.
        start: usize,
        /// End of the requested offset bytes.
        end: usize,
        /// Encoded offset-table byte length.
        length: usize,
    },
    /// Validated directory offsets did not delimit an addressable child.
    #[error("directory child byte range {start}..{end} exceeds data length {length}")]
    DirectoryChildRangeOutOfBounds {
        /// Child start offset.
        start: usize,
        /// Child end offset.
        end: usize,
        /// Encoded child-data byte length.
        length: usize,
    },
    /// A directory builder observed fewer or more children than reserved.
    #[error("directory reserved {expected} children but observed {actual}")]
    DirectoryChildCountMismatch {
        /// Reserved child count.
        expected: usize,
        /// Offsets written by the builder.
        actual: usize,
    },
    /// Schema and value fixed-tuple classifiers disagreed.
    #[error("canonical fixed tuple classification changed")]
    FixedTupleClassificationChanged,
    /// Shape and value fixed-tuple classifiers disagreed.
    #[error("fixed value-shape classification changed")]
    FixedValueShapeClassificationChanged,
    /// Shape and value fixed-list classifiers disagreed.
    #[error("fixed list-shape classification changed")]
    FixedListShapeClassificationChanged,
    /// A list layout classifier selected a lane containing another value kind.
    #[error("list lane classification disagrees with element type")]
    ListLaneClassificationChanged,
    /// A fixed-width list's validated child range was not addressable.
    #[error("fixed-list child byte range {start}..{end} exceeds data length {length}")]
    FixedListChildRangeOutOfBounds {
        /// Child start offset.
        start: usize,
        /// Child end offset.
        end: usize,
        /// Element-region byte length.
        length: usize,
    },
    /// A validated per-element list shape omitted an element.
    #[error("list shape index {index} exceeds shape count {count}")]
    ListShapeIndexOutOfBounds {
        /// Requested element index.
        index: usize,
        /// Available per-element shape count.
        count: usize,
    },
    /// A validated integer width exceeded the consensus scalar width.
    #[error("validated integer width {actual} exceeds maximum {maximum}")]
    IntegerWidthTooLarge {
        /// Validated packed scalar width.
        actual: usize,
        /// Maximum packed scalar width.
        maximum: usize,
    },
    /// A validated Boolean lane omitted a requested element bit.
    #[error("Boolean lane index {index} exceeds available bit count {bit_count}")]
    BooleanLaneIndexOutOfBounds {
        /// Requested Boolean element index.
        index: usize,
        /// Bits physically available in the lane.
        bit_count: usize,
    },
    /// A V1 shape parser received a descriptor dispatched to another version.
    #[error("V1 shape parser expected version {expected}, found {actual}")]
    IncorrectV1ShapeVersion {
        /// Version required by the V1 parser.
        expected: u8,
        /// Version byte supplied to the parser.
        actual: u8,
    },
    /// An internally derived response shape has no active branch.
    #[error("response shape has no active branch")]
    ResponseShapeHasNoActiveBranch,
    /// An internally derived per-element list shape is empty.
    #[error("per-element list shape is empty")]
    EmptyPerElementListShape,
}
