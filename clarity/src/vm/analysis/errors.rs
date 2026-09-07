// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

use std::{error, fmt};

use clarity_types::errors::ClarityTypeError;
use clarity_types::representations::SymbolicExpression;
use clarity_types::types::{
    BoundedErrorString, BoundedValueString, TraitIdentifier, TupleTypeSignature, TypeSignature,
};
use stacks_common::bounded_format;
use stacks_common::types::StacksEpochId;

use crate::vm::costs::{CostErrors, ExecutionCost};
use crate::vm::diagnostic::{DiagnosableError, Diagnostic};

/// What kind of syntax binding was found to be in error?
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum SyntaxBindingErrorType {
    Let,
    Eval,
    TupleCons,
}

impl fmt::Display for SyntaxBindingErrorType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl DiagnosableError for SyntaxBindingErrorType {
    fn write_message(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::Let => f.write_str("Let-binding"),
            Self::Eval => f.write_str("Function argument definition"),
            Self::TupleCons => f.write_str("Tuple constructor"),
        }
    }

    fn suggestion(&self) -> Option<String> {
        None
    }
}

/// Syntax binding error types
#[derive(Debug, PartialEq)]
pub enum SyntaxBindingError {
    /// binding list item is not a list
    NotList(SyntaxBindingErrorType, usize),
    /// binding list item has an invalid length (e.g. not 2)
    InvalidLength(SyntaxBindingErrorType, usize),
    /// binding name is not an atom
    NotAtom(SyntaxBindingErrorType, usize),
}

impl fmt::Display for SyntaxBindingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl DiagnosableError for SyntaxBindingError {
    fn write_message(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::NotList(err_type, item_index) => {
                let item_no = item_index + 1;
                write!(f, "{err_type} item #{item_no} is not a list")
            }
            Self::InvalidLength(err_type, item_index) => {
                let item_no = item_index + 1;
                write!(f, "{err_type} item #{item_no} is not a two-element list")
            }
            Self::NotAtom(err_type, item_index) => {
                let item_no = item_index + 1;
                write!(f, "{err_type} item #{item_no}'s name is not an atom")
            }
        }
    }

    fn suggestion(&self) -> Option<String> {
        None
    }
}

impl SyntaxBindingError {
    /// Helper constructor for NotList(SyntaxBindingErrorType::Let, item_no)
    pub fn let_binding_not_list(item_no: usize) -> Self {
        Self::NotList(SyntaxBindingErrorType::Let, item_no)
    }

    /// Helper constructor for InvalidLength(SyntaxBindingErrorType::Let, item_no)
    pub fn let_binding_invalid_length(item_no: usize) -> Self {
        Self::InvalidLength(SyntaxBindingErrorType::Let, item_no)
    }

    /// Helper constructor for NotAtom(SyntaxBindingErrorType::Let, item_no)
    pub fn let_binding_not_atom(item_no: usize) -> Self {
        Self::NotAtom(SyntaxBindingErrorType::Let, item_no)
    }

    /// Helper constructor for NotList(SyntaxBindingErrorType::Eval, item_no)
    pub fn eval_binding_not_list(item_no: usize) -> Self {
        Self::NotList(SyntaxBindingErrorType::Eval, item_no)
    }

    /// Helper constructor for InvalidLength(SyntaxBindingErrorType::Eval, item_no)
    pub fn eval_binding_invalid_length(item_no: usize) -> Self {
        Self::InvalidLength(SyntaxBindingErrorType::Eval, item_no)
    }

    /// Helper constructor for NotAtom(SyntaxBindingErrorType::Eval, item_no)
    pub fn eval_binding_not_atom(item_no: usize) -> Self {
        Self::NotAtom(SyntaxBindingErrorType::Eval, item_no)
    }

    /// Helper constructor for NotList(SyntaxBindingErrorType::TupleCons, item_no)
    pub fn tuple_cons_not_list(item_no: usize) -> Self {
        Self::NotList(SyntaxBindingErrorType::TupleCons, item_no)
    }

    /// Helper constructor for InvalidLength(SyntaxBindingErrorType::TupleCons, item_no)
    pub fn tuple_cons_invalid_length(item_no: usize) -> Self {
        Self::InvalidLength(SyntaxBindingErrorType::TupleCons, item_no)
    }

    /// Helper constructor for NotAtom(SyntaxBindingErrorType::TupleCons, item_no)
    pub fn tuple_cons_not_atom(item_no: usize) -> Self {
        Self::NotAtom(SyntaxBindingErrorType::TupleCons, item_no)
    }
}

/// Converts a [`SyntaxBindingError`] into a [`StaticCheckErrorKind`].
/// Used for propagating binding errors from
/// [`crate::vm::analysis::read_only_checker::ReadOnlyChecker::check_each_expression_is_read_only`]
impl From<SyntaxBindingError> for StaticCheckErrorKind {
    fn from(e: SyntaxBindingError) -> Self {
        Self::BadSyntaxBinding(e)
    }
}

/// Converts a [`SyntaxBindingError`] into a [`CommonCheckErrorKind`].
/// Used for propagating binding errors from [`crate::vm::functions::handle_binding_list`],
/// which is utilized in both static and runtime analysis to ensure consistent error handling.
impl From<SyntaxBindingError> for CommonCheckErrorKind {
    fn from(e: SyntaxBindingError) -> Self {
        CommonCheckErrorKind::BadSyntaxBinding(e)
    }
}

/// Shared set of error variants that are between static analysis (during contract deployment)
/// and runtime checking (during contract execution), specifically for validation logic that
/// is implemented in common code paths used by both.
///
/// All these variants represent errors that can arise only from code executed in both analysis and
/// execution contexts—such as argument count checks, type size limits, or shared cost tracking logic.
/// If an error may be triggered by either context via common logic, it lives here.
///
/// Importantly, this enum does not cover all errors common to both analysis and execution.
/// There are other error shared error variants, but those are generated specifically by logic
/// that is unique to static analysis or unique to execution. These errors are defined separately
/// and do not pass through this enum. Only error cases that can possibly arise from a shared
/// validation flow will appear here.
#[derive(Debug, PartialEq)]
pub enum CommonCheckErrorKind {
    // Cost checker errors
    Cost(CostErrors),

    // Errors originating from Clarity type system layer
    ClarityType(ClarityTypeError),

    // Syntax related
    /// Expected a name (e.g., variable, function) but found an invalid or missing token.
    ExpectedName,
    /// Referenced type name does not exist or is undefined.
    /// The `String` wraps the non-existent type name.
    UnknownTypeName(String),
    /// Invalid or malformed signature in a function definition.
    DefineFunctionBadSignature,
    /// Invalid binding syntax in a generic construct (e.g., `let`, `match`).
    /// The `SyntaxBindingError` wraps the specific binding error.
    BadSyntaxBinding(SyntaxBindingError),

    // Argument counts
    /// Function requires at least the specified number of arguments, but fewer were provided.
    /// The first `usize` represents the minimum required, and the second represents the actual count.
    RequiresAtLeastArguments(usize, usize),
    /// Function requires at most the specified number of arguments, but more were provided.
    /// The first `usize` represents the maximum allowed, and the second represents the actual count.
    RequiresAtMostArguments(usize, usize),
    /// Incorrect number of arguments provided to a function.
    /// The first `usize` represents the expected count, and the second represents the actual count.
    IncorrectArgumentCount(usize, usize),
    /// Too many function parameters specified.
    /// The first `usize` represents the number of parameters found, the second represents the maximum allowed.
    TooManyFunctionParameters(usize, usize),

    // Trait related
    /// Expected a trait identifier (e.g., `.trait-name`) but found an invalid token.
    ExpectedTraitIdentifier,
    /// Invalid or malformed signature in a `(define-trait ...)` expression.
    DefineTraitBadSignature,
    /// Trait definition contains duplicate method names.
    /// The `String` wraps the duplicate method name.
    DefineTraitDuplicateMethod(String),
    /// Too many trait methods specified.
    /// The first `usize` represents the number of methods found, the second the maximum allowed.
    TraitTooManyMethods(usize, usize),
}

/// An error detected during the static analysis of a smart contract at deployment time.
///
/// These checks are performed once, before any contract execution occurs, to find issues
/// like type mismatches, invalid function signatures, or incorrect control flow.
#[derive(Debug, PartialEq)]
pub enum StaticCheckErrorKind {
    // Cost checker errors
    /// Arithmetic overflow in cost computation during type-checking, exceeding the maximum threshold.
    CostOverflow,
    /// Cumulative type-checking cost exceeds the allocated budget, indicating budget depletion.
    /// The first `ExecutionCost` represents the total consumed cost, and the second represents the budget limit.
    CostBalanceExceeded(ExecutionCost, ExecutionCost),
    /// Memory usage during type-checking exceeds the allocated budget.
    /// The first `u64` represents the total consumed memory, and the second represents the memory limit.
    MemoryBalanceExceeded(u64, u64),
    /// Failure in cost-tracking due to an unexpected condition or invalid state.
    /// The `String` wraps the specific reason for the failure.
    CostComputationFailed(String),
    /// Contract-analysis time or memory usage exceeds the allowed budget, halting analysis to ensure responsiveness.
    AnalysisResourceBudgetExceeded(String),
    /// The read-only checker recursed too deeply while checking native function calls.
    ReadOnlyCheckerRecursionLimitExceeded,
    /// Value exceeds the maximum allowed size for type-checking or serialization.
    ValueTooLarge,
    /// Value is outside the acceptable range for its type (e.g., integer bounds).
    ValueOutOfBounds,
    /// Type signature nesting depth exceeds the allowed limit during analysis.
    TypeSignatureTooDeep,
    /// A trait-reference chain exceeds the type-checker's recursion depth limit.
    TraitReferenceChainTooDeep,
    /// Expected a name (e.g., variable, function) but found an invalid or missing token.
    ExpectedName,
    /// Supertype (i.e. common denominator between two types) exceeds the maximum allowed size or complexity.
    SupertypeTooLarge,

    /// Unexpected condition or failure in the type-checker, indicating a bug or invalid state.
    Unreachable(BoundedErrorString),

    // Match expression errors
    /// Invalid syntax in an `option` match expression.
    /// The `Box<StaticCheckErrorKind>` wraps the underlying error causing the syntax issue.
    BadMatchOptionSyntax(Box<StaticCheckErrorKind>),
    /// Invalid syntax in a `response` match expression.
    /// The `Box<StaticCheckErrorKind>` wraps the underlying error causing the syntax issue.
    BadMatchResponseSyntax(Box<StaticCheckErrorKind>),
    /// Input to a `match` expression does not conform to the expected type (e.g., `Option` or `Response`).
    /// The `Box<TypeSignature>` wraps the actual type of the provided input.
    BadMatchInput(Box<TypeSignature>),

    /// Constructed list exceeds the maximum allowed length during type-checking.
    ConstructedListTooLarge,

    // Type mismatch errors
    /// Expected type does not match the actual type during analysis.
    /// The first `Box<TypeSignature>` wraps the expected type, and the second wraps the actual type.
    TypeError(Box<TypeSignature>, Box<TypeSignature>),

    /// Type description is invalid or malformed, preventing proper type-checking.
    InvalidTypeDescription,
    /// Referenced type name does not exist or is undefined.
    /// The `String` wraps the non-existent type name.
    UnknownTypeName(String),

    // Union type mismatch
    /// Type does not belong to the expected union of types during analysis.
    /// The `Vec<TypeSignature>` represents the expected types, and the `Box<TypeSignature>` wraps the actual type.
    UnionTypeError(Vec<TypeSignature>, Box<TypeSignature>),
    /// Expected an optional type but found a different type.
    /// The `Box<TypeSignature>` wraps the actual type provided.
    ExpectedOptionalType(Box<TypeSignature>),
    /// Expected a response type but found a different type.
    /// The `Box<TypeSignature>` wraps the actual type provided.
    ExpectedResponseType(Box<TypeSignature>),
    /// Expected an optional or response type but found a different type.
    /// The `Box<TypeSignature>` wraps the actual type provided.
    ExpectedOptionalOrResponseType(Box<TypeSignature>),
    /// Could not determine the type of the `ok` branch in a response type.
    CouldNotDetermineResponseOkType,
    /// Could not determine the type of the `err` branch in a response type.
    CouldNotDetermineResponseErrType,
    /// Could not determine the serialization type for a value during analysis.
    CouldNotDetermineSerializationType,
    /// Intermediary response types were not properly checked, risking type safety.
    UncheckedIntermediaryResponses,

    // Match type errors
    /// Could not determine the types for a match expression’s branches.
    CouldNotDetermineMatchTypes,
    /// Could not determine the type of an expression during analysis.
    CouldNotDetermineType,

    // Checker runtime failures
    /// Attempt to re-annotate a type that was already annotated, indicating a bug.
    TypeAlreadyAnnotatedFailure,
    /// Unexpected failure in the type-checker implementation, indicating a bug.
    CheckerImplementationFailure,

    // Assets
    /// Expected a token name as an argument but found an invalid token.
    BadTokenName,
    /// Invalid or malformed signature in a `(define-non-fungible-token ...)` expression.
    DefineNFTBadSignature,
    /// Referenced non-fungible token (NFT) does not exist.
    /// The `String` wraps the non-existent token name.
    NoSuchNFT(String),
    /// Referenced fungible token (FT) does not exist.
    /// The `String` wraps the non-existent token name.
    NoSuchFT(String),

    // Tuples
    /// Tuple field name is invalid or violates naming rules.
    BadTupleFieldName,
    /// Expected a tuple type but found a different type.
    /// The `Box<TypeSignature>` wraps the actual type provided.
    ExpectedTuple(Box<TypeSignature>),
    /// Referenced tuple field does not exist in the tuple type.
    /// The `String` wraps the requested field name, and the `TupleTypeSignature` wraps the tuple’s type.
    NoSuchTupleField(String, TupleTypeSignature),
    /// Empty tuple is not allowed in Clarity.
    EmptyTuplesNotAllowed,
    /// Invalid tuple construction due to malformed syntax or type mismatch.
    /// The `String` wraps the specific error description.
    BadTupleConstruction(BoundedErrorString),

    // Variables
    /// Referenced data variable does not exist in scope.
    /// The `String` wraps the non-existent variable name.
    NoSuchDataVariable(String),

    // Data map
    /// Map name is invalid or violates naming rules.
    BadMapName,
    /// Referenced data map does not exist in scope.
    /// The `String` wraps the non-existent map name.
    NoSuchMap(String),

    // Defines
    /// Invalid or malformed signature in a function definition.
    DefineFunctionBadSignature,
    /// Function name is invalid or violates naming rules.
    BadFunctionName,
    /// Invalid or malformed map type definition in a `(define-map ...)` expression.
    BadMapTypeDefinition,
    /// Public function must return a response type, but found a different type.
    /// The `Box<TypeSignature>` wraps the actual return type.
    PublicFunctionMustReturnResponse(Box<TypeSignature>),
    /// Invalid or malformed variable definition in a `(define-data-var ...)` expression.
    DefineVariableBadSignature,
    /// Return types of function branches do not match the expected type.
    /// The first `Box<TypeSignature>` wraps the expected type, and the second wraps the actual type.
    ReturnTypesMustMatch(Box<TypeSignature>, Box<TypeSignature>),

    // Contract-call errors
    /// Referenced contract does not exist.
    /// The `String` wraps the non-existent contract name.
    NoSuchContract(String),
    /// Referenced public function does not exist in the specified contract.
    /// The first `String` wraps the contract name, and the second wraps the function name.
    NoSuchPublicFunction(String, String),
    /// Attempt to define a contract with a name that already exists.
    /// The `String` wraps the conflicting contract name.
    ContractAlreadyExists(String),
    /// Expected a contract name in a `contract-call?` expression but found an invalid token.
    ContractCallExpectName,
    /// Expected a callable type (e.g., function or trait) but found a different type.
    /// The `Box<TypeSignature>` wraps the actual type provided.
    ExpectedCallableType(Box<TypeSignature>),

    // get-block-info? errors
    /// Referenced block info property does not exist.
    /// The `String` wraps the non-existent property name.
    NoSuchBlockInfoProperty(String),
    /// Referenced Stacks block info property does not exist.
    /// The `String` wraps the non-existent property name.
    NoSuchStacksBlockInfoProperty(String),
    /// Referenced tenure info property does not exist.
    /// The `String` wraps the non-existent property name.
    NoSuchTenureInfoProperty(String),
    /// Expected a block info property name but found an invalid token.
    GetBlockInfoExpectPropertyName,
    /// Expected a burn block info property name but found an invalid token.
    GetBurnBlockInfoExpectPropertyName,
    /// Expected a Stacks block info property name but found an invalid token.
    GetStacksBlockInfoExpectPropertyName,
    /// Expected a tenure info property name but found an invalid token.
    GetTenureInfoExpectPropertyName,

    /// Name (e.g., variable, function) is already in use within the same scope.
    /// The `String` wraps the conflicting name.
    NameAlreadyUsed(String),
    /// Name is a reserved word in Clarity and cannot be used.
    /// The `String` wraps the reserved name.
    ReservedWord(String),

    // Expect a function, or applying a function to a list
    /// Attempt to apply a non-function value as a function.
    NonFunctionApplication,
    /// Expected a list application but found a different expression.
    ExpectedListApplication,
    /// Expected a sequence type (e.g., list, buffer) but found a different type.
    /// The `Box<TypeSignature>` wraps the actual type provided.
    ExpectedSequence(Box<TypeSignature>),
    /// Sequence length exceeds the maximum allowed limit.
    MaxLengthOverflow,

    // Let syntax
    /// Invalid syntax in a `let` expression, violating binding or structure rules.
    BadLetSyntax,

    // Generic binding syntax
    /// Invalid binding syntax in a generic construct (e.g., `let`, `match`).
    /// The `SyntaxBindingError` wraps the specific binding error.
    BadSyntaxBinding(SyntaxBindingError),

    /// Maximum context depth for type-checking has been reached.
    MaxContextDepthReached,
    /// Referenced variable is not defined in the current scope.
    /// The `String` wraps the non-existent variable name.
    UndefinedVariable(String),

    // Argument counts
    /// Function requires at least the specified number of arguments, but fewer were provided.
    /// The first `usize` represents the minimum required, and the second represents the actual count.
    RequiresAtLeastArguments(usize, usize),
    /// Function requires at most the specified number of arguments, but more were provided.
    /// The first `usize` represents the maximum allowed, and the second represents the actual count.
    RequiresAtMostArguments(usize, usize),
    /// Incorrect number of arguments provided to a function.
    /// The first `usize` represents the expected count, and the second represents the actual count.
    IncorrectArgumentCount(usize, usize),
    /// `if` expression arms have mismatched return types.
    /// The first `Box<TypeSignature>` wraps the type of one arm, and the second wraps the other.
    IfArmsMustMatch(Box<TypeSignature>, Box<TypeSignature>),
    /// `match` expression arms have mismatched return types.
    /// The first `Box<TypeSignature>` wraps the type of one arm, and the second wraps the other.
    MatchArmsMustMatch(Box<TypeSignature>, Box<TypeSignature>),
    /// `default-to` expression types are mismatched.
    /// The first `Box<TypeSignature>` wraps the expected type, and the second wraps the actual type.
    DefaultTypesMustMatch(Box<TypeSignature>, Box<TypeSignature>),
    /// Application of an illegal or unknown function.
    /// The `String` wraps the function name.
    IllegalOrUnknownFunctionApplication(String),
    /// Referenced function is unknown or not defined.
    /// The `String` wraps the non-existent function name.
    UnknownFunction(String),
    /// Too many function parameters specified.
    /// The first `usize` represents the number of parameters found, the second represents the maximum allowed.
    TooManyFunctionParameters(usize, usize),

    // Traits
    /// Referenced trait does not exist in the specified contract.
    /// The first `String` wraps the contract name, and the second wraps the trait name.
    NoSuchTrait(String, String),
    /// Referenced trait is not defined or cannot be found.
    /// The `String` wraps the non-existent trait name.
    TraitReferenceUnknown(String),
    /// Referenced method does not exist in the specified trait.
    /// The first `String` wraps the trait name, and the second wraps the method name.
    TraitMethodUnknown(String, String),
    /// Expected a trait identifier (e.g., `.trait-name`) but found an invalid token.
    ExpectedTraitIdentifier,
    /// Invalid implementation of a trait method.
    /// The first `String` wraps the trait name, and the second wraps the method name.
    BadTraitImplementation(String, String),
    /// Invalid or malformed signature in a `(define-trait ...)` expression.
    DefineTraitBadSignature,
    /// Trait definition contains duplicate method names.
    /// The `String` wraps the duplicate method name.
    DefineTraitDuplicateMethod(String),
    /// Unexpected use of a trait or field reference in a non-trait context.
    UnexpectedTraitOrFieldReference,
    /// `contract-of` expects a trait type but found a different type.
    ContractOfExpectsTrait,
    /// Trait implementation is incompatible with the expected trait definition.
    /// The first `Box<TraitIdentifier>` wraps the expected trait, and the second wraps the actual trait.
    IncompatibleTrait(Box<TraitIdentifier>, Box<TraitIdentifier>),
    /// Too many trait methods specified.
    /// The first `usize` represents the number of methods found, the second the maximum allowed.
    TraitTooManyMethods(usize, usize),

    /// Attempt to write to contract state in a read-only function.
    WriteAttemptedInReadOnly,
    /// `at-block` closure must be read-only but contains write operations.
    AtBlockClosureMustBeReadOnly,
    /// `at-block` is not available in this epoch.
    AtBlockUnavailable,

    // contract post-conditions
    /// Post-condition expects a list of asset allowances but received invalid input.
    /// The first `String` wraps the function name, and the second `i32` wraps the argument number.
    ExpectedListOfAllowances(String, i32),
    /// Allowance expressions are only allowed in specific contexts (`restrict-assets?` or `as-contract?`).
    AllowanceExprNotAllowed,
    /// Expected an allowance expression but found invalid input.
    /// The `String` wraps the unexpected input.
    ExpectedAllowanceExpr(String),
    /// `with-all-assets-unsafe` is not allowed in this context.
    WithAllAllowanceNotAllowed,
    /// `with-all-assets-unsafe` cannot be used alongside other allowances.
    WithAllAllowanceNotAlone,
    /// `with-nft` allowance requires a list of asset identifiers.
    WithNftExpectedListOfIdentifiers,
    /// `with-nft` allowance identifiers list exceeds the maximum allowed length.
    /// The first `u32` represents the maximum length, and the second represents the actual length.
    MaxIdentifierLengthExceeded(u32, u32),
    /// Too many allowances specified in post-condition.
    /// The first `usize` represents the maximum allowed, and the second represents the actual count.
    TooManyAllowances(usize, usize),
}

/// An error that occurs during the runtime analysis of a smart contract at runtime. Could be returnd by:
/// - a contract initialization execution
/// - a contract call execution
///
/// These errors are found when a contract is executed. They represent dynamic conditions
/// that cannot be determined by static analysis, such as:
/// - Failures based on runtime arguments or state changes.
/// - Value-level type mismatches.
#[derive(Debug, PartialEq)]
pub enum RuntimeCheckErrorKind {
    // Cost checker errors
    /// Arithmetic overflow in cost computation during type-checking, exceeding the maximum threshold.
    CostOverflow,
    /// Cumulative type-checking cost exceeds the allocated budget, indicating budget depletion.
    /// The first `ExecutionCost` represents the total consumed cost, and the second represents the budget limit.
    CostBalanceExceeded(ExecutionCost, ExecutionCost),
    /// Memory usage during type-checking exceeds the allocated budget.
    /// The first `u64` represents the total consumed memory, and the second represents the memory limit.
    MemoryBalanceExceeded(u64, u64),
    /// Temporary guard for oversized `restrict-assets?` allowance payloads.
    /// The first `u64` represents the tracked execution-memory total and the second the guard limit.
    /// TODO(epoch-3.5): remove this special case and make `MemoryBalanceExceeded` rejectable instead.
    RestrictAssetsMemoryExceeded(u64, u64),
    /// Failure in cost-tracking due to an unexpected condition or invalid state.
    /// The `String` wraps the specific reason for the failure.
    CostComputationFailed(String),
    /// Runtime (eval) execution time or memory use exceeds the allowed budget, halting execution to ensure responsiveness.
    ExecutionResourceBudgetExceeded(String),

    /// Value exceeds the maximum allowed size for type-checking or serialization.
    ValueTooLarge,
    /// Value is outside the acceptable range for its type (e.g., integer bounds).
    ValueOutOfBounds,
    /// Type signature nesting depth exceeds the allowed limit during analysis.
    TypeSignatureTooDeep,

    /// Unexpected condition or failure in the type-checker, indicating a catastrophic bug or invalid state.
    Unreachable(BoundedErrorString),

    /// Block rejection: a `pox-4` call would overwrite
    /// an existing asset-map stacking entry for its sender.
    PoxStxAssetMapOverwrite,

    // List typing errors
    /// List elements have mismatched types, violating type consistency.
    ListTypesMustMatch,

    // Type mismatch errors
    /// Expected type does not match the actual type during analysis.
    /// The first `Box<TypeSignature>` wraps the expected type, and the second wraps the actual type.
    TypeError(Box<TypeSignature>, Box<TypeSignature>),
    /// Value does not match the expected type during type-checking.
    /// The `Box<TypeSignature>` wraps the expected type, and the
    /// `BoundedValueString` is a truncated display representation of the
    /// invalid value.
    TypeValueError(Box<TypeSignature>, BoundedValueString),

    // Union type mismatch
    /// Value does not belong to the expected union of types during type-checking.
    /// The `Vec<TypeSignature>` represents the expected types, and the
    /// `BoundedValueString` is a truncated display representation of the
    /// invalid value.
    UnionTypeValueError(Vec<TypeSignature>, BoundedValueString),

    /// Expected a contract principal value but found a different value.
    /// The `String` is a truncated display representation of the actual value provided.
    ExpectedContractPrincipalValue(BoundedValueString),

    // Match type errors
    /// Could not determine the type of an expression during analysis.
    CouldNotDetermineType,

    // Defines
    /// Return types of function branches do not match the expected type.
    /// The first `Box<TypeSignature>` wraps the expected type, and the second wraps the actual type.
    ReturnTypesMustMatch(Box<TypeSignature>, Box<TypeSignature>),

    /// Circular reference detected in interdependent function definitions.
    /// The `Vec<String>` represents the list of referenced names forming the cycle.
    CircularReference(Vec<String>),

    // Contract-call errors
    /// Referenced contract does not exist.
    /// The `String` wraps the non-existent contract name.
    NoSuchContract(String),
    /// Referenced public function does not exist in the specified contract.
    /// The first `String` wraps the contract name, and the second wraps the function name.
    NoSuchPublicFunction(String, String),
    /// Expected a contract name in a `contract-call?` expression but found an invalid token.
    ContractCallExpectName,

    /// Name (e.g., variable, function) is already in use within the same scope.
    /// The `String` wraps the conflicting name.
    NameAlreadyUsed(String),

    /// Referenced function is not defined in the current scope.
    /// The `String` wraps the non-existent function name.
    UndefinedFunction(String),
    /// `at-block` is not available in this epoch.
    AtBlockUnavailable,

    // Argument counts
    /// Incorrect number of arguments provided to a function.
    /// The first `usize` represents the expected count, and the second represents the actual count.
    IncorrectArgumentCount(usize, usize),

    // Traits
    /// Referenced trait is not defined or cannot be found.
    /// The `String` wraps the non-existent trait name.
    /// This is only reachable at runtime via contracts deployed with Clarity 1 as its
    /// static analysis is not as strict as later clarity versions.
    TraitReferenceUnknown(String),
    /// Referenced method does not exist in the specified trait.
    /// The first `String` wraps the trait name, and the second wraps the method name.
    /// This is only reachable at runtime via contracts deployed with Clarity 1 as its
    /// static analysis is not as strict as later clarity versions.
    TraitMethodUnknown(String, String),
    /// Invalid implementation of a trait method.
    /// The first `String` wraps the trait name, and the second wraps the method name.
    BadTraitImplementation(String, String),

    // Strings
    /// String contains invalid or disallowed characters (e.g., non-ASCII in ASCII strings).
    InvalidCharactersDetected,
    /// String contains invalid UTF-8 encoding.
    InvalidUTF8Encoding,
}

#[derive(Debug, PartialEq)]
/// A complete static analysis error, combining the error with diagnostic information.
///
/// This struct wraps a [`StaticCheckErrorKind`] variant with its source location
/// (like line and column numbers) and the code expression that caused the error.
/// It provides the full context needed to report a clear, actionable error to a
/// developer during contract deployment.
pub struct StaticCheckError {
    /// The specific type-checking or semantic error that occurred.
    pub err: Box<StaticCheckErrorKind>,
    /// Optional vector of expressions related to the error, if available.
    pub expressions: Option<Vec<SymbolicExpression>>,
    /// Diagnostic details (e.g., line/column numbers, error message, suggestions) around the error.
    pub diagnostic: Diagnostic,
}

impl RuntimeCheckErrorKind {
    /// This check indicates that the transaction should be rejected.
    pub fn rejectable(&self) -> bool {
        matches!(
            self,
            RuntimeCheckErrorKind::Unreachable(_)
                | RuntimeCheckErrorKind::RestrictAssetsMemoryExceeded(_, _)
                | RuntimeCheckErrorKind::PoxStxAssetMapOverwrite
        )
    }

    /// Returns true if this error is an unreachable error, indicating a potential bug.
    /// Used only for monitoring (logging + prometheus counter), not for business logic.
    pub fn is_unreachable(&self) -> bool {
        matches!(self, RuntimeCheckErrorKind::Unreachable(_))
    }
}

impl StaticCheckErrorKind {
    /// This check indicates that the transaction should be rejected in the given epoch.
    pub fn rejectable_in_epoch(&self, epoch: StacksEpochId) -> bool {
        match self {
            StaticCheckErrorKind::SupertypeTooLarge => epoch.rejects_supertype_too_large(),
            StaticCheckErrorKind::TraitReferenceChainTooDeep => true,
            StaticCheckErrorKind::Unreachable(_) => true,
            StaticCheckErrorKind::ReadOnlyCheckerRecursionLimitExceeded => true,
            _ => false,
        }
    }

    /// Returns true if this error is an unreachable error, indicating a potential bug.
    /// Used only for monitoring (logging + prometheus counter), not for business logic.
    pub fn is_unreachable(&self) -> bool {
        matches!(self, StaticCheckErrorKind::Unreachable(_))
    }
}

impl StaticCheckError {
    pub fn new(err: StaticCheckErrorKind) -> StaticCheckError {
        let diagnostic = Diagnostic::err(&err);
        StaticCheckError {
            err: Box::new(err),
            expressions: None,
            diagnostic,
        }
    }

    pub fn has_expression(&self) -> bool {
        self.expressions.is_some()
    }

    pub fn set_expression(&mut self, expr: &SymbolicExpression) {
        self.diagnostic.spans = vec![expr.span().clone()];
        self.expressions.replace(vec![expr.clone()]);
    }

    pub fn set_expressions(&mut self, exprs: &[SymbolicExpression]) {
        self.diagnostic.spans = exprs.iter().map(|e| e.span().clone()).collect();
        self.expressions.replace(exprs.to_vec());
    }

    pub fn with_expression(err: StaticCheckErrorKind, expr: &SymbolicExpression) -> Self {
        let mut r = Self::new(err);
        r.set_expression(expr);
        r
    }
}

impl From<ClarityTypeError> for StaticCheckErrorKind {
    fn from(err: ClarityTypeError) -> Self {
        match err {
            ClarityTypeError::ValueTooLarge => Self::ValueTooLarge,
            ClarityTypeError::TypeSignatureTooDeep => Self::TypeSignatureTooDeep,
            ClarityTypeError::ValueOutOfBounds => Self::ValueOutOfBounds,
            ClarityTypeError::DuplicateTupleField(name) => Self::NameAlreadyUsed(name),
            ClarityTypeError::NoSuchTupleField(field, tuple_sig) => {
                Self::NoSuchTupleField(field, tuple_sig)
            }
            ClarityTypeError::TypeMismatch(expected, found) => Self::TypeError(expected, found),
            ClarityTypeError::EmptyTuplesNotAllowed => Self::EmptyTuplesNotAllowed,
            ClarityTypeError::SupertypeTooLarge => Self::SupertypeTooLarge,
            ClarityTypeError::InvalidTypeDescription => Self::InvalidTypeDescription,
            ClarityTypeError::InvalidUrlString(_)
            | ClarityTypeError::InvalidClarityName(_)
            | ClarityTypeError::InvalidContractName(_)
            | ClarityTypeError::QualifiedContractEmptyIssuer
            | ClarityTypeError::QualifiedContractMissingDot
            | ClarityTypeError::InvalidPrincipalEncoding(_)
            | ClarityTypeError::InvalidPrincipalLength(_)
            | ClarityTypeError::ListTypeMismatch
            | ClarityTypeError::SequenceElementArityMismatch { .. }
            | ClarityTypeError::ExpectedSequenceValue
            | ClarityTypeError::TypeMismatchValue(_, _)
            | ClarityTypeError::ResponseTypeMismatch { .. }
            | ClarityTypeError::InvalidAsciiCharacter(_)
            | ClarityTypeError::InvalidUtf8Encoding
            | ClarityTypeError::InvariantViolation(_)
            | ClarityTypeError::InvalidPrincipalVersion(_) => Self::Unreachable(bounded_format!(
                "Unexpected error type during static analysis: {err}"
            )),
            ClarityTypeError::CouldNotDetermineSerializationType => {
                Self::CouldNotDetermineSerializationType
            }
            ClarityTypeError::CouldNotDetermineType => Self::CouldNotDetermineType,
            ClarityTypeError::UnsupportedTypeInEpoch(ty, epoch) => {
                Self::Unreachable(bounded_format!("{ty} should not be used in {epoch}"))
            }
            ClarityTypeError::UnsupportedEpoch(epoch) => {
                Self::Unreachable(bounded_format!("{epoch} is not supported"))
            }
        }
    }
}

impl From<ClarityTypeError> for StaticCheckError {
    fn from(err: ClarityTypeError) -> Self {
        StaticCheckErrorKind::from(err).into()
    }
}

impl From<(CommonCheckErrorKind, &SymbolicExpression)> for StaticCheckError {
    fn from(e: (CommonCheckErrorKind, &SymbolicExpression)) -> Self {
        Self::with_expression(e.0.into(), e.1)
    }
}

impl From<(SyntaxBindingError, &SymbolicExpression)> for StaticCheckError {
    fn from(e: (SyntaxBindingError, &SymbolicExpression)) -> Self {
        Self::with_expression(StaticCheckErrorKind::BadSyntaxBinding(e.0), e.1)
    }
}

impl From<(CommonCheckErrorKind, &SymbolicExpression)> for CommonCheckErrorKind {
    fn from(e: (CommonCheckErrorKind, &SymbolicExpression)) -> Self {
        e.0
    }
}

impl From<(CommonCheckErrorKind, &SymbolicExpression)> for RuntimeCheckErrorKind {
    fn from(e: (CommonCheckErrorKind, &SymbolicExpression)) -> Self {
        e.0.into()
    }
}

impl From<ClarityTypeError> for RuntimeCheckErrorKind {
    fn from(err: ClarityTypeError) -> Self {
        match err {
            ClarityTypeError::ValueTooLarge => Self::ValueTooLarge,
            ClarityTypeError::TypeSignatureTooDeep => Self::TypeSignatureTooDeep,
            ClarityTypeError::ValueOutOfBounds => Self::ValueOutOfBounds,
            ClarityTypeError::DuplicateTupleField(name) => Self::NameAlreadyUsed(name),
            ClarityTypeError::TypeMismatchValue(ty, value) => {
                Self::TypeValueError(ty, value.to_error_string())
            }
            ClarityTypeError::TypeMismatch(expected, found) => Self::TypeError(expected, found),
            ClarityTypeError::ListTypeMismatch => Self::ListTypesMustMatch,
            ClarityTypeError::InvalidAsciiCharacter(_) => Self::InvalidCharactersDetected,
            ClarityTypeError::InvalidUtf8Encoding => Self::InvalidUTF8Encoding,
            ClarityTypeError::ExpectedSequenceValue
            | ClarityTypeError::SequenceElementArityMismatch { .. }
            | ClarityTypeError::CouldNotDetermineSerializationType
            | ClarityTypeError::InvalidUrlString(_)
            | ClarityTypeError::InvalidClarityName(_)
            | ClarityTypeError::InvalidContractName(_)
            | ClarityTypeError::QualifiedContractEmptyIssuer
            | ClarityTypeError::QualifiedContractMissingDot
            | ClarityTypeError::InvalidPrincipalEncoding(_)
            | ClarityTypeError::InvalidPrincipalLength(_)
            | ClarityTypeError::InvalidTypeDescription
            | ClarityTypeError::NoSuchTupleField(_, _)
            | ClarityTypeError::EmptyTuplesNotAllowed
            | ClarityTypeError::ResponseTypeMismatch { .. } => Self::Unreachable(bounded_format!(
                "Unexpected error type during runtime analysis: {err}"
            )),
            ClarityTypeError::InvariantViolation(_)
            | ClarityTypeError::InvalidPrincipalVersion(_)
            | ClarityTypeError::SupertypeTooLarge => Self::Unreachable(bounded_format!(
                "Unexpected error type during runtime analysis: {err}"
            )),
            ClarityTypeError::CouldNotDetermineType => Self::CouldNotDetermineType,
            ClarityTypeError::UnsupportedTypeInEpoch(ty, epoch) => {
                Self::Unreachable(bounded_format!("{ty} should not be used in {epoch}"))
            }
            ClarityTypeError::UnsupportedEpoch(epoch) => {
                Self::Unreachable(bounded_format!("{epoch} is not supported"))
            }
        }
    }
}

impl From<ClarityTypeError> for CommonCheckErrorKind {
    fn from(err: ClarityTypeError) -> Self {
        CommonCheckErrorKind::ClarityType(err)
    }
}

impl fmt::Display for CommonCheckErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl fmt::Display for RuntimeCheckErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl fmt::Display for StaticCheckErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl fmt::Display for StaticCheckError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.err)?;

        if let Some(ref e) = self.expressions {
            write!(f, "\nNear:\n{e:?}")?;
        }

        Ok(())
    }
}

impl From<CostErrors> for StaticCheckError {
    fn from(err: CostErrors) -> Self {
        StaticCheckError::from(StaticCheckErrorKind::from(err))
    }
}

impl From<CostErrors> for StaticCheckErrorKind {
    fn from(err: CostErrors) -> Self {
        match err {
            CostErrors::CostOverflow => StaticCheckErrorKind::CostOverflow,
            CostErrors::CostBalanceExceeded(a, b) => {
                StaticCheckErrorKind::CostBalanceExceeded(a, b)
            }
            CostErrors::MemoryBalanceExceeded(a, b) => {
                StaticCheckErrorKind::MemoryBalanceExceeded(a, b)
            }
            CostErrors::CostComputationFailed(s) => StaticCheckErrorKind::CostComputationFailed(s),
            CostErrors::CostContractLoadFailure => {
                StaticCheckErrorKind::CostComputationFailed("Failed to load cost contract".into())
            }
            CostErrors::InterpreterFailure => StaticCheckErrorKind::Unreachable(
                "Unexpected interpreter failure in cost computation".into(),
            ),
            CostErrors::Expect(s) => {
                StaticCheckErrorKind::Unreachable(BoundedErrorString::from_display(&s))
            }
        }
    }
}

impl From<CostErrors> for RuntimeCheckErrorKind {
    fn from(err: CostErrors) -> Self {
        match err {
            CostErrors::CostOverflow => RuntimeCheckErrorKind::CostOverflow,
            CostErrors::CostBalanceExceeded(a, b) => {
                RuntimeCheckErrorKind::CostBalanceExceeded(a, b)
            }
            CostErrors::MemoryBalanceExceeded(a, b) => {
                RuntimeCheckErrorKind::MemoryBalanceExceeded(a, b)
            }
            CostErrors::CostComputationFailed(s) => RuntimeCheckErrorKind::CostComputationFailed(s),
            CostErrors::CostContractLoadFailure => {
                RuntimeCheckErrorKind::CostComputationFailed("Failed to load cost contract".into())
            }
            CostErrors::InterpreterFailure => RuntimeCheckErrorKind::Unreachable(
                "Unexpected interpreter failure in cost computation".into(),
            ),
            CostErrors::Expect(s) => {
                RuntimeCheckErrorKind::Unreachable(BoundedErrorString::from_display(&s))
            }
        }
    }
}

impl From<CostErrors> for CommonCheckErrorKind {
    fn from(err: CostErrors) -> Self {
        CommonCheckErrorKind::Cost(err)
    }
}

impl error::Error for CommonCheckErrorKind {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl error::Error for StaticCheckError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl error::Error for RuntimeCheckErrorKind {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl From<StaticCheckErrorKind> for StaticCheckError {
    fn from(err: StaticCheckErrorKind) -> Self {
        StaticCheckError::new(err)
    }
}

impl From<CommonCheckErrorKind> for StaticCheckError {
    fn from(err: CommonCheckErrorKind) -> Self {
        StaticCheckError::new(StaticCheckErrorKind::from(err))
    }
}

impl From<CommonCheckErrorKind> for RuntimeCheckErrorKind {
    fn from(err: CommonCheckErrorKind) -> Self {
        match err {
            CommonCheckErrorKind::Cost(e) => e.into(),
            CommonCheckErrorKind::ClarityType(e) => e.into(),
            CommonCheckErrorKind::IncorrectArgumentCount(expected, args) => {
                RuntimeCheckErrorKind::IncorrectArgumentCount(expected, args)
            }
            CommonCheckErrorKind::RequiresAtLeastArguments(expected, args) => {
                RuntimeCheckErrorKind::Unreachable(bounded_format!(
                    "Requires at least args: {expected} got {args}"
                ))
            }
            CommonCheckErrorKind::RequiresAtMostArguments(expected, args) => {
                RuntimeCheckErrorKind::Unreachable(bounded_format!(
                    "Requires at most args: {expected} got {args}"
                ))
            }
            CommonCheckErrorKind::TooManyFunctionParameters(found, allowed) => {
                RuntimeCheckErrorKind::Unreachable(bounded_format!(
                    "Too many function params: found {found}, allowed {allowed}"
                ))
            }
            CommonCheckErrorKind::ExpectedName => {
                RuntimeCheckErrorKind::Unreachable("Expected name".into())
            }
            CommonCheckErrorKind::DefineFunctionBadSignature => {
                RuntimeCheckErrorKind::Unreachable("Define function bad signature".into())
            }
            CommonCheckErrorKind::ExpectedTraitIdentifier => {
                RuntimeCheckErrorKind::Unreachable("Expected trait identifier".into())
            }
            CommonCheckErrorKind::DefineTraitDuplicateMethod(s) => {
                RuntimeCheckErrorKind::Unreachable(bounded_format!(
                    "Define trait duplicate method: {s}"
                ))
            }
            CommonCheckErrorKind::TraitTooManyMethods(found, allowed) => {
                RuntimeCheckErrorKind::Unreachable(bounded_format!(
                    "Trait too many methods: found {found}, allowed {allowed}"
                ))
            }
            CommonCheckErrorKind::DefineTraitBadSignature => {
                RuntimeCheckErrorKind::Unreachable("Define trait bad signature".into())
            }
            CommonCheckErrorKind::BadSyntaxBinding(e) => {
                RuntimeCheckErrorKind::Unreachable(bounded_format!("Bad syntax binding: {e}"))
            }
            CommonCheckErrorKind::UnknownTypeName(name) => {
                RuntimeCheckErrorKind::Unreachable(bounded_format!("Unknown type name: {name}"))
            }
        }
    }
}

impl From<CommonCheckErrorKind> for StaticCheckErrorKind {
    fn from(err: CommonCheckErrorKind) -> Self {
        match err {
            CommonCheckErrorKind::Cost(e) => e.into(),
            CommonCheckErrorKind::ClarityType(e) => e.into(),
            CommonCheckErrorKind::IncorrectArgumentCount(expected, args) => {
                StaticCheckErrorKind::IncorrectArgumentCount(expected, args)
            }
            CommonCheckErrorKind::RequiresAtLeastArguments(expected, args) => {
                StaticCheckErrorKind::RequiresAtLeastArguments(expected, args)
            }
            CommonCheckErrorKind::RequiresAtMostArguments(expected, args) => {
                StaticCheckErrorKind::RequiresAtMostArguments(expected, args)
            }
            CommonCheckErrorKind::TooManyFunctionParameters(found, allowed) => {
                StaticCheckErrorKind::TooManyFunctionParameters(found, allowed)
            }
            CommonCheckErrorKind::ExpectedName => StaticCheckErrorKind::ExpectedName,
            CommonCheckErrorKind::DefineFunctionBadSignature => {
                StaticCheckErrorKind::DefineFunctionBadSignature
            }
            CommonCheckErrorKind::ExpectedTraitIdentifier => {
                StaticCheckErrorKind::ExpectedTraitIdentifier
            }
            CommonCheckErrorKind::DefineTraitDuplicateMethod(s) => {
                StaticCheckErrorKind::DefineTraitDuplicateMethod(s)
            }
            CommonCheckErrorKind::DefineTraitBadSignature => {
                StaticCheckErrorKind::DefineTraitBadSignature
            }
            CommonCheckErrorKind::TraitTooManyMethods(found, allowed) => {
                StaticCheckErrorKind::TraitTooManyMethods(found, allowed)
            }
            CommonCheckErrorKind::BadSyntaxBinding(e) => StaticCheckErrorKind::BadSyntaxBinding(e),
            CommonCheckErrorKind::UnknownTypeName(name) => {
                StaticCheckErrorKind::UnknownTypeName(name)
            }
        }
    }
}

/// This conversion is provided to support tests in
/// `clarity/src/vm/analysis/type_checker/v2_1/tests/contracts.rs`.
#[cfg(any(test, feature = "testing"))]
impl From<StaticCheckErrorKind> for String {
    fn from(o: StaticCheckErrorKind) -> Self {
        o.to_string()
    }
}

pub fn check_argument_count<T>(expected: usize, args: &[T]) -> Result<(), CommonCheckErrorKind> {
    if args.len() != expected {
        Err(CommonCheckErrorKind::IncorrectArgumentCount(
            expected,
            args.len(),
        ))
    } else {
        Ok(())
    }
}

pub fn check_arguments_at_least<T>(
    expected: usize,
    args: &[T],
) -> Result<(), CommonCheckErrorKind> {
    if args.len() < expected {
        Err(CommonCheckErrorKind::RequiresAtLeastArguments(
            expected,
            args.len(),
        ))
    } else {
        Ok(())
    }
}

pub fn check_arguments_at_most<T>(expected: usize, args: &[T]) -> Result<(), CommonCheckErrorKind> {
    if args.len() > expected {
        Err(CommonCheckErrorKind::RequiresAtMostArguments(
            expected,
            args.len(),
        ))
    } else {
        Ok(())
    }
}

/// Check if the supplied arguments are exactly N in length, and if so, return
///  a fixed array with pointers to the arguments. Otherwise, return an IncorrectArgumentCount
pub fn get_arguments_exact<T, const N: usize>(args: &[T]) -> Result<&[T; N], CommonCheckErrorKind> {
    args.try_into()
        .map_err(|_| CommonCheckErrorKind::IncorrectArgumentCount(N, args.len()))
}

/// Check if the supplied arguments are at least N in length, and if so, return
///  a fixed array of size N with pointers to the arguments and a slice with the excess.
/// Otherwise, return an IncorrectArgumentCount
pub fn get_arguments_at_least<T, const N: usize>(
    args: &[T],
) -> Result<(&[T; N], &[T]), CommonCheckErrorKind> {
    args.split_first_chunk::<N>()
        .ok_or_else(|| CommonCheckErrorKind::RequiresAtLeastArguments(N, args.len()))
}

/// Renders a type union as `'a', 'b' or 'c'`. A `Display` adapter rather than
/// a `String`-returning function, so the types stream into the enclosing
/// diagnostic's byte-budgeted sink instead of being materialized in full.
struct FormattedExpectedTypes<'a>(&'a [TypeSignature]);

impl fmt::Display for FormattedExpectedTypes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "'{}'", self.0[0])?;
        if self.0.len() > 2 {
            for expected_type in self.0[1..self.0.len() - 1].iter() {
                write!(f, ", '{expected_type}'")?;
            }
        }
        write!(f, " or '{}'", self.0[self.0.len() - 1])
    }
}

impl DiagnosableError for StaticCheckErrorKind {
    fn write_message(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            StaticCheckErrorKind::SupertypeTooLarge => f.write_str("supertype of two types is too large"),
            StaticCheckErrorKind::Unreachable(s) => write!(f, "unexpected and unacceptable interpreter behavior: {s}"),
            StaticCheckErrorKind::BadMatchOptionSyntax(source) => {
                f.write_str("match on a optional type uses the following syntax: (match input some-name if-some-expression if-none-expression). Caused by: ")?;
                source.write_message(f)
            }
            StaticCheckErrorKind::BadMatchResponseSyntax(source) => {
                f.write_str("match on a result type uses the following syntax: (match input ok-name if-ok-expression err-name if-err-expression). Caused by: ")?;
                source.write_message(f)
            }
            StaticCheckErrorKind::BadMatchInput(t) =>
                write!(f, "match requires an input of either a response or optional, found input: '{}'", t),
            StaticCheckErrorKind::CostOverflow => f.write_str("contract execution cost overflowed cost counter"),
            StaticCheckErrorKind::CostBalanceExceeded(a, b) => write!(f, "contract execution cost exceeded budget: {a:?} > {b:?}"),
            StaticCheckErrorKind::MemoryBalanceExceeded(a, b) => write!(f, "contract execution cost exceeded memory budget: {a:?} > {b:?}"),
            StaticCheckErrorKind::CostComputationFailed(s) => write!(f, "contract cost computation failed: {s}"),
            StaticCheckErrorKind::AnalysisResourceBudgetExceeded(s) => write!(f, "analysis resource budget exceeded: {s}"),
            StaticCheckErrorKind::ReadOnlyCheckerRecursionLimitExceeded => f.write_str("read-only checker exceeded maximum allowed recursion depth"),
            StaticCheckErrorKind::InvalidTypeDescription => f.write_str("supplied type description is invalid"),
            StaticCheckErrorKind::EmptyTuplesNotAllowed => f.write_str("tuple types may not be empty"),
            StaticCheckErrorKind::UnknownTypeName(name) => write!(f, "failed to parse type: '{name}'"),
            StaticCheckErrorKind::ValueTooLarge => f.write_str("created a type which was greater than maximum allowed value size"),
            StaticCheckErrorKind::ValueOutOfBounds => f.write_str("created a type which value size was out of defined bounds"),
            StaticCheckErrorKind::TypeSignatureTooDeep => f.write_str("created a type which was deeper than maximum allowed type depth"),
            StaticCheckErrorKind::TraitReferenceChainTooDeep => f.write_str("trait-reference chain exceeds the maximum allowed type-checker recursion depth"),
            StaticCheckErrorKind::ExpectedName => f.write_str("expected a name argument to this function"),
            StaticCheckErrorKind::ConstructedListTooLarge => f.write_str("reached limit of elements in a sequence"),
            StaticCheckErrorKind::TypeError(expected_type, found_type) => write!(f, "expecting expression of type '{}', found '{}'", expected_type, found_type),
            StaticCheckErrorKind::UnionTypeError(expected_types, found_type) => write!(f, "expecting expression of type {}, found '{}'", FormattedExpectedTypes(expected_types), found_type),
            StaticCheckErrorKind::ExpectedOptionalType(found_type) => write!(f, "expecting expression of type 'optional', found '{}'", found_type),
            StaticCheckErrorKind::ExpectedOptionalOrResponseType(found_type) => write!(f, "expecting expression of type 'optional' or 'response', found '{}'", found_type),
            StaticCheckErrorKind::ExpectedResponseType(found_type) => write!(f, "expecting expression of type 'response', found '{}'", found_type),
            StaticCheckErrorKind::CouldNotDetermineResponseOkType => f.write_str("attempted to obtain 'ok' value from response, but 'ok' type is indeterminate"),
            StaticCheckErrorKind::CouldNotDetermineResponseErrType => f.write_str("attempted to obtain 'err' value from response, but 'err' type is indeterminate"),
            StaticCheckErrorKind::CouldNotDetermineMatchTypes => f.write_str("attempted to match on an (optional) or (response) type where either the some, ok, or err type is indeterminate. you may wish to use unwrap-panic or unwrap-err-panic instead."),
            StaticCheckErrorKind::CouldNotDetermineType => f.write_str("type of expression cannot be determined"),
            StaticCheckErrorKind::BadTupleFieldName => f.write_str("invalid tuple field name"),
            StaticCheckErrorKind::ExpectedTuple(type_signature) => write!(f, "expecting tuple, found '{}'", type_signature),
            StaticCheckErrorKind::NoSuchTupleField(field_name, tuple_signature) => write!(f, "cannot find field '{field_name}' in tuple '{}'", tuple_signature),
            StaticCheckErrorKind::BadTupleConstruction(message) => write!(f, "invalid tuple syntax: {message}"),
            StaticCheckErrorKind::NoSuchDataVariable(var_name) => write!(f, "use of unresolved persisted variable '{var_name}'"),
            StaticCheckErrorKind::BadMapName => f.write_str("invalid map name"),
            StaticCheckErrorKind::NoSuchMap(map_name) => write!(f, "use of unresolved map '{map_name}'"),
            StaticCheckErrorKind::DefineFunctionBadSignature => f.write_str("invalid function definition"),
            StaticCheckErrorKind::BadFunctionName => f.write_str("invalid function name"),
            StaticCheckErrorKind::BadMapTypeDefinition => f.write_str("invalid map definition"),
            StaticCheckErrorKind::PublicFunctionMustReturnResponse(found_type) => write!(f, "public functions must return an expression of type 'response', found '{}'", found_type),
            StaticCheckErrorKind::DefineVariableBadSignature => f.write_str("invalid variable definition"),
            StaticCheckErrorKind::ReturnTypesMustMatch(type_1, type_2) => write!(f, "detected two execution paths, returning two different expression types (got '{}' and '{}')", type_1, type_2),
            StaticCheckErrorKind::NoSuchContract(contract_identifier) => write!(f, "use of unresolved contract '{contract_identifier}'"),
            StaticCheckErrorKind::NoSuchPublicFunction(contract_identifier, function_name) => write!(f, "contract '{contract_identifier}' has no public function '{function_name}'"),
            StaticCheckErrorKind::ContractAlreadyExists(contract_identifier) => write!(f, "contract name '{contract_identifier}' conflicts with existing contract"),
            StaticCheckErrorKind::ContractCallExpectName => f.write_str("missing contract name for call"),
            StaticCheckErrorKind::ExpectedCallableType(found_type) => write!(f, "expected a callable contract, found {}", found_type),
            StaticCheckErrorKind::NoSuchBlockInfoProperty(property_name) => write!(f, "use of block unknown property '{property_name}'"),
            StaticCheckErrorKind::NoSuchStacksBlockInfoProperty(property_name) => write!(f, "use of unknown stacks block property '{property_name}'"),
            StaticCheckErrorKind::NoSuchTenureInfoProperty(property_name) => write!(f, "use of unknown tenure property '{property_name}'"),
            StaticCheckErrorKind::GetBlockInfoExpectPropertyName => f.write_str("missing property name for block info introspection"),
            StaticCheckErrorKind::GetBurnBlockInfoExpectPropertyName => f.write_str("missing property name for burn block info introspection"),
            StaticCheckErrorKind::GetStacksBlockInfoExpectPropertyName => f.write_str("missing property name for stacks block info introspection"),
            StaticCheckErrorKind::GetTenureInfoExpectPropertyName => f.write_str("missing property name for tenure info introspection"),
            StaticCheckErrorKind::NameAlreadyUsed(name) => write!(f, "defining '{name}' conflicts with previous value"),
            StaticCheckErrorKind::ReservedWord(name) => write!(f, "{name} is a reserved word"),
            StaticCheckErrorKind::NonFunctionApplication => f.write_str("expecting expression of type function"),
            StaticCheckErrorKind::ExpectedListApplication => f.write_str("expecting expression of type list"),
            StaticCheckErrorKind::ExpectedSequence(found_type) => write!(f, "expecting expression of type 'list', 'buff', 'string-ascii' or 'string-utf8' - found '{}'", found_type),
            StaticCheckErrorKind::MaxLengthOverflow => write!(f, "expecting a value <= {}", u32::MAX),
            StaticCheckErrorKind::BadLetSyntax => f.write_str("invalid syntax of 'let'"),
            StaticCheckErrorKind::BadSyntaxBinding(binding_error) => {
                f.write_str("invalid syntax binding: ")?;
                binding_error.write_message(f)
            }
            StaticCheckErrorKind::MaxContextDepthReached => f.write_str("reached depth limit"),
            StaticCheckErrorKind::UndefinedVariable(var_name) => write!(f, "use of unresolved variable '{var_name}'"),
            StaticCheckErrorKind::RequiresAtLeastArguments(expected, found) => write!(f, "expecting >= {expected} arguments, got {found}"),
            StaticCheckErrorKind::RequiresAtMostArguments(expected, found) => write!(f, "expecting < {expected} arguments, got {found}"),
            StaticCheckErrorKind::IncorrectArgumentCount(expected_count, found_count) => write!(f, "expecting {expected_count} arguments, got {found_count}"),
            StaticCheckErrorKind::IfArmsMustMatch(type_1, type_2) => write!(f, "expression types returned by the arms of 'if' must match (got '{}' and '{}')", type_1, type_2),
            StaticCheckErrorKind::MatchArmsMustMatch(type_1, type_2) => write!(f, "expression types returned by the arms of 'match' must match (got '{}' and '{}')", type_1, type_2),
            StaticCheckErrorKind::DefaultTypesMustMatch(type_1, type_2) => write!(f, "expression types passed in 'default-to' must match (got '{}' and '{}')", type_1, type_2),
            StaticCheckErrorKind::IllegalOrUnknownFunctionApplication(function_name) => write!(f, "use of illegal / unresolved function '{function_name}"),
            StaticCheckErrorKind::UnknownFunction(function_name) => write!(f, "use of unresolved function '{function_name}'"),
            StaticCheckErrorKind::TooManyFunctionParameters(found, allowed) => write!(f, "too many function parameters specified: found {found}, the maximum is {allowed}"),
            StaticCheckErrorKind::WriteAttemptedInReadOnly => f.write_str("expecting read-only statements, detected a writing operation"),
            StaticCheckErrorKind::AtBlockClosureMustBeReadOnly => f.write_str("(at-block ...) closures expect read-only statements, but detected a writing operation"),
            StaticCheckErrorKind::AtBlockUnavailable => f.write_str("(at-block ...) is not available in this epoch"),
            StaticCheckErrorKind::BadTokenName => f.write_str("expecting an token name as an argument"),
            StaticCheckErrorKind::DefineNFTBadSignature => f.write_str("(define-asset ...) expects an asset name and an asset identifier type signature as arguments"),
            StaticCheckErrorKind::NoSuchNFT(asset_name) => write!(f, "tried to use asset function with a undefined asset ('{asset_name}')"),
            StaticCheckErrorKind::NoSuchFT(asset_name) => write!(f, "tried to use token function with a undefined token ('{asset_name}')"),
            StaticCheckErrorKind::NoSuchTrait(contract_name, trait_name) => write!(f, "use of unresolved trait {contract_name}.{trait_name}"),
            StaticCheckErrorKind::TraitReferenceUnknown(trait_name) => write!(f, "use of undeclared trait <{trait_name}>"),
            StaticCheckErrorKind::TraitMethodUnknown(trait_name, func_name) => write!(f, "method '{func_name}' unspecified in trait <{trait_name}>"),
            StaticCheckErrorKind::BadTraitImplementation(trait_name, func_name) => write!(f, "invalid signature for method '{func_name}' regarding trait's specification <{trait_name}>"),
            StaticCheckErrorKind::ExpectedTraitIdentifier => f.write_str("expecting expression of type trait identifier"),
            StaticCheckErrorKind::UnexpectedTraitOrFieldReference => f.write_str("unexpected use of trait reference or field"),
            StaticCheckErrorKind::DefineTraitBadSignature => f.write_str("invalid trait definition"),
            StaticCheckErrorKind::DefineTraitDuplicateMethod(method_name) => write!(f, "duplicate method name '{method_name}' in trait definition"),
            StaticCheckErrorKind::ContractOfExpectsTrait => f.write_str("trait reference expected"),
            StaticCheckErrorKind::IncompatibleTrait(expected_trait, actual_trait) => write!(f, "trait '{actual_trait}' is not a compatible with expected trait, '{expected_trait}'"),
            StaticCheckErrorKind::TraitTooManyMethods(found, allowed) => write!(f, "too many trait methods specified: found {found}, the maximum is {allowed}"),
            StaticCheckErrorKind::TypeAlreadyAnnotatedFailure | StaticCheckErrorKind::CheckerImplementationFailure => {
                f.write_str("internal error - please file an issue on https://github.com/stacks-network/stacks-blockchain")
            },
            StaticCheckErrorKind::UncheckedIntermediaryResponses => f.write_str("intermediary responses in consecutive statements must be checked"),
            StaticCheckErrorKind::CouldNotDetermineSerializationType => f.write_str("could not determine the input type for the serialization function"),
            StaticCheckErrorKind::ExpectedListOfAllowances(fn_name, arg_num) => write!(f, "{fn_name} expects a list of asset allowances as argument {arg_num}"),
            StaticCheckErrorKind::AllowanceExprNotAllowed => f.write_str("allowance expressions are only allowed in the context of a `restrict-assets?` or `as-contract?`"),
            StaticCheckErrorKind::ExpectedAllowanceExpr(got_name) => write!(f, "expected an allowance expression, got: {got_name}"),
            StaticCheckErrorKind::WithAllAllowanceNotAllowed => f.write_str("with-all-assets-unsafe is not allowed here, only in the allowance list for `as-contract?`"),
            StaticCheckErrorKind::WithAllAllowanceNotAlone => f.write_str("with-all-assets-unsafe must not be used along with other allowances"),
            StaticCheckErrorKind::WithNftExpectedListOfIdentifiers => f.write_str("with-nft allowance must include a list of asset identifiers"),
            StaticCheckErrorKind::MaxIdentifierLengthExceeded(max_len, len) => write!(f, "with-nft allowance identifiers list must not exceed {max_len} elements, got {len}"),
            StaticCheckErrorKind::TooManyAllowances(max_allowed, found) => write!(f, "too many allowances specified, the maximum is {max_allowed}, found {found}"),
        }
    }

    fn suggestion(&self) -> Option<String> {
        match &self {
            StaticCheckErrorKind::BadLetSyntax => Some(
                "'let' syntax example: (let ((supply 1000) (ttl 60)) <next-expression>)".into(),
            ),
            StaticCheckErrorKind::TraitReferenceUnknown(_) => Some(
                "traits should be either defined, with define-trait, or imported, with use-trait."
                    .into(),
            ),
            StaticCheckErrorKind::NoSuchBlockInfoProperty(_) => Some(
                "properties available: time, header-hash, burnchain-header-hash, vrf-seed".into(),
            ),
            _ => None,
        }
    }
}
