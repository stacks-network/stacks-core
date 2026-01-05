// Copyright (C) 2025 Stacks Open Internet Foundation
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

use crate::diagnostic::{DiagnosableError, Diagnostic};
use crate::errors::CostErrors;
use crate::execution_cost::ExecutionCost;
use crate::representations::SymbolicExpression;
use crate::types::{ClarityTypeError, TraitIdentifier, TupleTypeSignature, TypeSignature, Value};

/// What kind of syntax binding was found to be in error?
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum SyntaxBindingErrorType {
    Let,
    Eval,
    TupleCons,
}

impl fmt::Display for SyntaxBindingErrorType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self.message())
    }
}

impl DiagnosableError for SyntaxBindingErrorType {
    fn message(&self) -> String {
        match &self {
            Self::Let => "Let-binding".to_string(),
            Self::Eval => "Function argument definition".to_string(),
            Self::TupleCons => "Tuple constructor".to_string(),
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
    fn message(&self) -> String {
        match &self {
            Self::NotList(err_type, item_index) => {
                let item_no = item_index + 1;
                format!("{err_type} item #{item_no} is not a list",)
            }
            Self::InvalidLength(err_type, item_index) => {
                let item_no = item_index + 1;
                format!("{err_type} item #{item_no} is not a two-element list",)
            }
            Self::NotAtom(err_type, item_index) => {
                let item_no = item_index + 1;
                format!("{err_type} item #{item_no}'s name is not an atom",)
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
    // Time checker errors
    /// Type-checking time exceeds the allowed budget, halting analysis to ensure responsiveness.
    ExecutionTimeExpired,

    /// Value exceeds the maximum allowed size for type-checking or serialization.
    ValueTooLarge,
    /// Value is outside the acceptable range for its type (e.g., integer bounds).
    ValueOutOfBounds,
    /// Type signature nesting depth exceeds the allowed limit during analysis.
    TypeSignatureTooDeep,
    /// Expected a name (e.g., variable, function) but found an invalid or missing token.
    ExpectedName,
    /// Supertype (e.g., trait or union) exceeds the maximum allowed size or complexity.
    SupertypeTooLarge,

    // Unexpected interpreter behavior
    /// Unexpected condition or failure in the type-checker, indicating a bug or invalid state.
    ExpectsRejectable(String),
    // Unexpected interpreter behavior
    /// Unexpected condition or failure in the type-checker, indicating a bug or invalid state.
    /// This error does NOT indicate a transaction would invalidate a block if included.
    ExpectsAcceptable(String),

    // Type mismatch errors
    /// Expected type does not match the actual type during analysis.
    /// The first `Box<TypeSignature>` wraps the expected type, and the second wraps the actual type.
    TypeError(Box<TypeSignature>, Box<TypeSignature>),

    /// Type description is invalid or malformed, preventing proper type-checking.
    InvalidTypeDescription,
    /// Referenced type name does not exist or is undefined.
    /// The `String` wraps the non-existent type name.
    UnknownTypeName(String),

    /// Could not determine the type of an expression during analysis.
    CouldNotDetermineType,

    /// Empty tuple is not allowed in Clarity.
    EmptyTuplesNotAllowed,

    /// Invalid or malformed signature in a function definition.
    DefineFunctionBadSignature,

    /// Name (e.g., variable, function) is already in use within the same scope.
    /// The `String` wraps the conflicting name.
    NameAlreadyUsed(String),

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
    // Time checker errors
    /// Type-checking time exceeds the allowed budget, halting analysis to ensure responsiveness.
    ExecutionTimeExpired,

    /// Value exceeds the maximum allowed size for type-checking or serialization.
    ValueTooLarge,
    /// Value is outside the acceptable range for its type (e.g., integer bounds).
    ValueOutOfBounds,
    /// Type signature nesting depth exceeds the allowed limit during analysis.
    TypeSignatureTooDeep,
    /// Expected a name (e.g., variable, function) but found an invalid or missing token.
    ExpectedName,
    /// Supertype (e.g., trait or union) exceeds the maximum allowed size or complexity.
    SupertypeTooLarge,

    // Unexpected interpreter behavior
    /// Unexpected condition or failure in the type-checker, indicating a bug or invalid state.
    ExpectsRejectable(String),
    // Unexpected interpreter behavior
    /// Unexpected condition or failure in the type-checker, indicating a bug or invalid state.
    /// This error does NOT indicate a transaction would invalidate a block if included.
    ExpectsAcceptable(String),

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
    BadTupleConstruction(String),

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
pub enum CheckErrorKind {
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
    // Time checker errors
    /// Type-checking time exceeds the allowed budget, halting analysis to ensure responsiveness.
    ExecutionTimeExpired,

    /// Value exceeds the maximum allowed size for type-checking or serialization.
    ValueTooLarge,
    /// Value is outside the acceptable range for its type (e.g., integer bounds).
    ValueOutOfBounds,
    /// Type signature nesting depth exceeds the allowed limit during analysis.
    TypeSignatureTooDeep,
    /// Expected a name (e.g., variable, function) but found an invalid or missing token.
    ExpectedName,
    /// Supertype (e.g., trait or union) exceeds the maximum allowed size or complexity.
    SupertypeTooLarge,

    // Unexpected interpreter behavior
    /// Unexpected condition or failure in the type-checker, indicating a catastrophic bug or invalid state.
    ExpectsRejectable(String),
    /// Unexpected condition or failure in the type-checker, indicating a noncatastrophic bug or invalid state.
    ExpectsAcceptable(String),

    // Match expression errors
    /// Invalid syntax in an `option` match expression.
    /// The `Box<CheckErrorKind>` wraps the underlying error causing the syntax issue.
    BadMatchOptionSyntax(Box<CheckErrorKind>),
    /// Invalid syntax in a `response` match expression.
    /// The `Box<CheckErrorKind>` wraps the underlying error causing the syntax issue.
    BadMatchResponseSyntax(Box<CheckErrorKind>),
    /// Input to a `match` expression does not conform to the expected type (e.g., `Option` or `Response`).
    /// The `Box<TypeSignature>` wraps the actual type of the provided input.
    BadMatchInput(Box<TypeSignature>),

    // List typing errors
    /// List elements have mismatched types, violating type consistency.
    ListTypesMustMatch,

    // Type mismatch errors
    /// Expected type does not match the actual type during analysis.
    /// The first `Box<TypeSignature>` wraps the expected type, and the second wraps the actual type.
    TypeError(Box<TypeSignature>, Box<TypeSignature>),
    /// Value does not match the expected type during type-checking.
    /// The `Box<TypeSignature>` wraps the expected type, and the `Box<Value>` wraps the invalid value.
    TypeValueError(Box<TypeSignature>, Box<Value>),

    /// Type description is invalid or malformed, preventing proper type-checking.
    InvalidTypeDescription,
    /// Referenced type name does not exist or is undefined.
    /// The `String` wraps the non-existent type name.
    UnknownTypeName(String),

    // Union type mismatch
    /// Type does not belong to the expected union of types during analysis.
    /// The `Vec<TypeSignature>` represents the expected types, and the `Box<TypeSignature>` wraps the actual type.
    UnionTypeError(Vec<TypeSignature>, Box<TypeSignature>),
    /// Value does not belong to the expected union of types during type-checking.
    /// The `Vec<TypeSignature>` represents the expected types, and the `Box<Value>` wraps the invalid value.
    UnionTypeValueError(Vec<TypeSignature>, Box<Value>),

    /// Expected an optional value but found a different value.
    /// The `Box<Value>` wraps the actual value provided.
    ExpectedOptionalValue(Box<Value>),
    /// Expected a response value but found a different value.
    /// The `Box<Value>` wraps the actual value provided.
    ExpectedResponseValue(Box<Value>),
    /// Expected an optional or response value but found a different value.
    /// The `Box<Value>` wraps the actual value provided.
    ExpectedOptionalOrResponseValue(Box<Value>),
    /// Expected a contract principal value but found a different value.
    /// The `Box<Value>` wraps the actual value provided.
    ExpectedContractPrincipalValue(Box<Value>),

    // Match type errors
    /// Could not determine the type of an expression during analysis.
    CouldNotDetermineType,

    // Assets
    /// Expected a token name as an argument but found an invalid token.
    BadTokenName,
    /// Referenced non-fungible token (NFT) does not exist.
    /// The `String` wraps the non-existent token name.
    NoSuchNFT(String),
    /// Referenced fungible token (FT) does not exist.
    /// The `String` wraps the non-existent token name.
    NoSuchFT(String),

    // Transfer and asset operation errors
    /// Invalid arguments provided to a `stx-transfer?` function.
    BadTransferSTXArguments,
    /// Invalid arguments provided to a fungible token transfer function.
    BadTransferFTArguments,
    /// Invalid arguments provided to a non-fungible token transfer function.
    BadTransferNFTArguments,
    /// Invalid arguments provided to a fungible token mint function.
    BadMintFTArguments,
    /// Invalid arguments provided to a fungible token burn function.
    BadBurnFTArguments,

    // Tuples
    /// Expected a tuple type but found a different type.
    /// The `Box<TypeSignature>` wraps the actual type provided.
    ExpectedTuple(Box<TypeSignature>),
    /// Referenced tuple field does not exist in the tuple type.
    /// The `String` wraps the requested field name, and the `TupleTypeSignature` wraps the tuple’s type.
    NoSuchTupleField(String, TupleTypeSignature),
    /// Empty tuple is not allowed in Clarity.
    EmptyTuplesNotAllowed,

    // Variables
    /// Referenced data variable does not exist in scope.
    /// The `String` wraps the non-existent variable name.
    NoSuchDataVariable(String),

    // Data map
    /// Referenced data map does not exist in scope.
    /// The `String` wraps the non-existent map name.
    NoSuchMap(String),

    // Defines
    /// Invalid or malformed signature in a function definition.
    DefineFunctionBadSignature,
    /// Function name is invalid or violates naming rules.
    BadFunctionName,
    /// Public function must return a response type, but found a different type.
    /// The `Box<TypeSignature>` wraps the actual return type.
    PublicFunctionMustReturnResponse(Box<TypeSignature>),
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
    /// Public function is not read-only when expected to be.
    /// The first `String` wraps the contract name, and the second wraps the function name.
    PublicFunctionNotReadOnly(String, String),
    /// Attempt to define a contract with a name that already exists.
    /// The `String` wraps the conflicting contract name.
    ContractAlreadyExists(String),
    /// Expected a contract name in a `contract-call?` expression but found an invalid token.
    ContractCallExpectName,

    // get-block-info? errors
    /// Referenced burn block info property does not exist.
    /// The `String` wraps the non-existent property name.
    NoSuchBurnBlockInfoProperty(String),
    /// Referenced Stacks block info property does not exist.
    /// The `String` wraps the non-existent property name.
    NoSuchStacksBlockInfoProperty(String),
    /// Expected a block info property name but found an invalid token.
    GetBlockInfoExpectPropertyName,
    /// Expected a Stacks block info property name but found an invalid token.
    GetStacksBlockInfoExpectPropertyName,
    /// Expected a tenure info property name but found an invalid token.
    GetTenureInfoExpectPropertyName,

    /// Name (e.g., variable, function) is already in use within the same scope.
    /// The `String` wraps the conflicting name.
    NameAlreadyUsed(String),

    // Expect a function, or applying a function to a list
    /// Attempt to apply a non-function value as a function.
    NonFunctionApplication,
    /// Expected a list application but found a different expression.
    ExpectedListApplication,
    /// Expected a sequence type (e.g., list, buffer) but encountered a non-sequence value.
    ///
    /// The boxed [`TypeSignature`] represents the **actual type provided**, if known.
    /// If the type could not be determined, this will be [`TypeSignature::NoType`].
    ExpectedSequence(Box<TypeSignature>),

    // Let syntax
    /// Invalid syntax in a `let` expression, violating binding or structure rules.
    BadLetSyntax,

    // Generic binding syntax
    /// Invalid binding syntax in a generic construct (e.g., `let`, `match`).
    /// The `SyntaxBindingError` wraps the specific binding error.
    BadSyntaxBinding(SyntaxBindingError),

    /// Referenced function is not defined in the current scope.
    /// The `String` wraps the non-existent function name.
    UndefinedFunction(String),
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
    /// Too many function parameters specified.
    /// The first `usize` represents the number of parameters found, the second represents the maximum allowed.
    TooManyFunctionParameters(usize, usize),

    // Traits
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

    /// Trait-based contract call used in a read-only context, which is prohibited.
    TraitBasedContractCallInReadOnly,
    /// `contract-of` expects a trait type but found a different type.
    ContractOfExpectsTrait,
    /// Too many trait methods specified.
    /// The first `usize` represents the number of methods found, the second the maximum allowed.
    TraitTooManyMethods(usize, usize),

    // Strings
    /// String contains invalid or disallowed characters (e.g., non-ASCII in ASCII strings).
    InvalidCharactersDetected,
    /// String contains invalid UTF-8 encoding.
    InvalidUTF8Encoding,

    /// Attempt to write to contract state in a read-only function.
    WriteAttemptedInReadOnly,

    // contract post-conditions
    /// Post-condition expects a list of asset allowances but received invalid input.
    /// The first `String` wraps the function name, and the second `i32` wraps the argument number.
    ExpectedListOfAllowances(String, i32),
    /// Allowance expressions are only allowed in specific contexts (`restrict-assets?` or `as-contract?`).
    AllowanceExprNotAllowed,
    /// Expected an allowance expression but found invalid input.
    /// The `String` wraps the unexpected input.
    ExpectedAllowanceExpr(String),
    /// Too many allowances specified in post-condition.
    /// The first `usize` represents the maximum allowed, and the second represents the actual count.
    TooManyAllowances(usize, usize),
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

impl CheckErrorKind {
    /// This check indicates that the transaction should be rejected.
    pub fn rejectable(&self) -> bool {
        matches!(
            self,
            CheckErrorKind::SupertypeTooLarge | CheckErrorKind::ExpectsRejectable(_)
        )
    }
}

impl StaticCheckErrorKind {
    /// This check indicates that the transaction should be rejected.
    pub fn rejectable(&self) -> bool {
        matches!(
            self,
            StaticCheckErrorKind::SupertypeTooLarge | StaticCheckErrorKind::ExpectsRejectable(_)
        )
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
            | ClarityTypeError::InvalidUtf8Encoding => Self::ExpectsAcceptable(format!(
                "Unexpected error type during static analysis: {err}"
            )),
            ClarityTypeError::InvariantViolation(_)
            | ClarityTypeError::InvalidPrincipalVersion(_) => Self::ExpectsRejectable(format!(
                "Unexpected error type during static analysis: {err}"
            )),
            ClarityTypeError::CouldNotDetermineSerializationType => {
                Self::CouldNotDetermineSerializationType
            }
            ClarityTypeError::CouldNotDetermineType => Self::CouldNotDetermineType,
            ClarityTypeError::UnsupportedTypeInEpoch(ty, epoch) => {
                Self::ExpectsRejectable(format!("{ty} should not be used in {epoch}"))
            }
            ClarityTypeError::UnsupportedEpoch(epoch) => {
                Self::ExpectsRejectable(format!("{epoch} is not supported"))
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

impl From<(CommonCheckErrorKind, &SymbolicExpression)> for CheckErrorKind {
    fn from(e: (CommonCheckErrorKind, &SymbolicExpression)) -> Self {
        e.0.into()
    }
}

impl From<ClarityTypeError> for CheckErrorKind {
    fn from(err: ClarityTypeError) -> Self {
        match err {
            ClarityTypeError::ValueTooLarge => Self::ValueTooLarge,
            ClarityTypeError::TypeSignatureTooDeep => Self::TypeSignatureTooDeep,
            ClarityTypeError::ValueOutOfBounds => Self::ValueOutOfBounds,
            ClarityTypeError::DuplicateTupleField(name) => Self::NameAlreadyUsed(name),
            ClarityTypeError::NoSuchTupleField(field, tuple_sig) => {
                Self::NoSuchTupleField(field, tuple_sig)
            }
            ClarityTypeError::TypeMismatchValue(ty, value) => Self::TypeValueError(ty, value),
            ClarityTypeError::TypeMismatch(expected, found) => Self::TypeError(expected, found),
            ClarityTypeError::EmptyTuplesNotAllowed => Self::EmptyTuplesNotAllowed,
            ClarityTypeError::SupertypeTooLarge => Self::SupertypeTooLarge,
            ClarityTypeError::InvalidTypeDescription => Self::InvalidTypeDescription,
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
            | ClarityTypeError::ResponseTypeMismatch { .. } => Self::ExpectsAcceptable(format!(
                "Unexpected error type during runtime analysis: {err}"
            )),
            ClarityTypeError::InvariantViolation(_)
            | ClarityTypeError::InvalidPrincipalVersion(_) => Self::ExpectsRejectable(format!(
                "Unexpected error type during runtime analysis: {err}"
            )),
            ClarityTypeError::CouldNotDetermineType => Self::CouldNotDetermineType,
            ClarityTypeError::UnsupportedTypeInEpoch(ty, epoch) => {
                Self::ExpectsRejectable(format!("{ty} should not be used in {epoch}"))
            }
            ClarityTypeError::UnsupportedEpoch(epoch) => {
                Self::ExpectsRejectable(format!("{epoch} is not supported"))
            }
        }
    }
}

impl From<ClarityTypeError> for CommonCheckErrorKind {
    fn from(err: ClarityTypeError) -> Self {
        match err {
            ClarityTypeError::ValueTooLarge => Self::ValueTooLarge,
            ClarityTypeError::TypeSignatureTooDeep => Self::TypeSignatureTooDeep,
            ClarityTypeError::ValueOutOfBounds => Self::ValueOutOfBounds,
            ClarityTypeError::DuplicateTupleField(name) => Self::NameAlreadyUsed(name),
            ClarityTypeError::TypeMismatch(expected, found) => Self::TypeError(expected, found),
            ClarityTypeError::EmptyTuplesNotAllowed => Self::EmptyTuplesNotAllowed,
            ClarityTypeError::SupertypeTooLarge => Self::SupertypeTooLarge,
            ClarityTypeError::InvalidTypeDescription => Self::InvalidTypeDescription,
            ClarityTypeError::CouldNotDetermineType => Self::CouldNotDetermineType,
            ClarityTypeError::ListTypeMismatch
            | ClarityTypeError::SequenceElementArityMismatch { .. }
            | ClarityTypeError::ExpectedSequenceValue
            | ClarityTypeError::InvalidAsciiCharacter(_)
            | ClarityTypeError::InvalidUtf8Encoding
            | ClarityTypeError::NoSuchTupleField(_, _)
            | ClarityTypeError::TypeMismatchValue(_, _)
            | ClarityTypeError::CouldNotDetermineSerializationType
            | ClarityTypeError::InvalidUrlString(_)
            | ClarityTypeError::InvalidClarityName(_)
            | ClarityTypeError::InvalidContractName(_)
            | ClarityTypeError::QualifiedContractEmptyIssuer
            | ClarityTypeError::QualifiedContractMissingDot
            | ClarityTypeError::InvalidPrincipalEncoding(_)
            | ClarityTypeError::InvalidPrincipalLength(_)
            | ClarityTypeError::ResponseTypeMismatch { .. } => Self::ExpectsAcceptable(format!(
                "Unexpected but acceptable error type during analysis: {err}"
            )),
            ClarityTypeError::InvariantViolation(_)
            | ClarityTypeError::InvalidPrincipalVersion(_) => Self::ExpectsRejectable(format!(
                "Unexpected and unacceptable error type during analysis: {err}"
            )),
            ClarityTypeError::UnsupportedTypeInEpoch(ty, epoch) => {
                Self::ExpectsRejectable(format!("{ty} should not be used in {epoch}"))
            }
            ClarityTypeError::UnsupportedEpoch(epoch) => {
                Self::ExpectsRejectable(format!("{epoch} is not supported"))
            }
        }
    }
}

impl fmt::Display for CommonCheckErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl fmt::Display for CheckErrorKind {
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
            CostErrors::InterpreterFailure => StaticCheckErrorKind::ExpectsRejectable(
                "Unexpected interpreter failure in cost computation".into(),
            ),
            CostErrors::Expect(s) => StaticCheckErrorKind::ExpectsRejectable(s),
            CostErrors::ExecutionTimeExpired => StaticCheckErrorKind::ExecutionTimeExpired,
        }
    }
}

impl From<CostErrors> for CheckErrorKind {
    fn from(err: CostErrors) -> Self {
        match err {
            CostErrors::CostOverflow => CheckErrorKind::CostOverflow,
            CostErrors::CostBalanceExceeded(a, b) => CheckErrorKind::CostBalanceExceeded(a, b),
            CostErrors::MemoryBalanceExceeded(a, b) => CheckErrorKind::MemoryBalanceExceeded(a, b),
            CostErrors::CostComputationFailed(s) => CheckErrorKind::CostComputationFailed(s),
            CostErrors::CostContractLoadFailure => {
                CheckErrorKind::CostComputationFailed("Failed to load cost contract".into())
            }
            CostErrors::InterpreterFailure => CheckErrorKind::ExpectsRejectable(
                "Unexpected interpreter failure in cost computation".into(),
            ),
            CostErrors::Expect(s) => CheckErrorKind::ExpectsRejectable(s),
            CostErrors::ExecutionTimeExpired => CheckErrorKind::ExecutionTimeExpired,
        }
    }
}

impl From<CostErrors> for CommonCheckErrorKind {
    fn from(err: CostErrors) -> Self {
        match err {
            CostErrors::CostOverflow => CommonCheckErrorKind::CostOverflow,
            CostErrors::CostBalanceExceeded(a, b) => {
                CommonCheckErrorKind::CostBalanceExceeded(a, b)
            }
            CostErrors::MemoryBalanceExceeded(a, b) => {
                CommonCheckErrorKind::MemoryBalanceExceeded(a, b)
            }
            CostErrors::CostComputationFailed(s) => CommonCheckErrorKind::CostComputationFailed(s),
            CostErrors::CostContractLoadFailure => {
                CommonCheckErrorKind::CostComputationFailed("Failed to load cost contract".into())
            }
            CostErrors::InterpreterFailure => CommonCheckErrorKind::ExpectsRejectable(
                "Unexpected interpreter failure in cost computation".into(),
            ),
            CostErrors::Expect(s) => CommonCheckErrorKind::ExpectsRejectable(s),
            CostErrors::ExecutionTimeExpired => CommonCheckErrorKind::ExecutionTimeExpired,
        }
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

impl error::Error for CheckErrorKind {
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

impl From<CommonCheckErrorKind> for CheckErrorKind {
    fn from(err: CommonCheckErrorKind) -> Self {
        match err {
            CommonCheckErrorKind::CostOverflow => CheckErrorKind::CostOverflow,
            CommonCheckErrorKind::CostBalanceExceeded(a, b) => {
                CheckErrorKind::CostBalanceExceeded(a, b)
            }
            CommonCheckErrorKind::MemoryBalanceExceeded(a, b) => {
                CheckErrorKind::MemoryBalanceExceeded(a, b)
            }
            CommonCheckErrorKind::CostComputationFailed(s) => {
                CheckErrorKind::CostComputationFailed(s)
            }
            CommonCheckErrorKind::ExecutionTimeExpired => CheckErrorKind::ExecutionTimeExpired,
            CommonCheckErrorKind::IncorrectArgumentCount(expected, args) => {
                CheckErrorKind::IncorrectArgumentCount(expected, args)
            }
            CommonCheckErrorKind::RequiresAtLeastArguments(expected, args) => {
                CheckErrorKind::RequiresAtLeastArguments(expected, args)
            }
            CommonCheckErrorKind::RequiresAtMostArguments(expected, args) => {
                CheckErrorKind::RequiresAtMostArguments(expected, args)
            }
            CommonCheckErrorKind::TooManyFunctionParameters(found, allowed) => {
                CheckErrorKind::TooManyFunctionParameters(found, allowed)
            }
            CommonCheckErrorKind::ExpectedName => CheckErrorKind::ExpectedName,
            CommonCheckErrorKind::DefineFunctionBadSignature => {
                CheckErrorKind::DefineFunctionBadSignature
            }
            CommonCheckErrorKind::ExpectedTraitIdentifier => {
                CheckErrorKind::ExpectedTraitIdentifier
            }
            CommonCheckErrorKind::ExpectsRejectable(s) => CheckErrorKind::ExpectsRejectable(s),
            CommonCheckErrorKind::ExpectsAcceptable(s) => CheckErrorKind::ExpectsAcceptable(s),
            CommonCheckErrorKind::CouldNotDetermineType => CheckErrorKind::CouldNotDetermineType,
            CommonCheckErrorKind::ValueTooLarge => CheckErrorKind::ValueTooLarge,
            CommonCheckErrorKind::TypeSignatureTooDeep => CheckErrorKind::TypeSignatureTooDeep,
            CommonCheckErrorKind::DefineTraitDuplicateMethod(s) => {
                CheckErrorKind::DefineTraitDuplicateMethod(s)
            }
            CommonCheckErrorKind::TraitTooManyMethods(found, allowed) => {
                CheckErrorKind::TraitTooManyMethods(found, allowed)
            }
            CommonCheckErrorKind::DefineTraitBadSignature => {
                CheckErrorKind::DefineTraitBadSignature
            }
            CommonCheckErrorKind::InvalidTypeDescription => CheckErrorKind::InvalidTypeDescription,
            CommonCheckErrorKind::SupertypeTooLarge => CheckErrorKind::SupertypeTooLarge,
            CommonCheckErrorKind::TypeError(a, b) => CheckErrorKind::TypeError(a, b),
            CommonCheckErrorKind::BadSyntaxBinding(e) => CheckErrorKind::BadSyntaxBinding(e),
            CommonCheckErrorKind::ValueOutOfBounds => CheckErrorKind::ValueOutOfBounds,
            CommonCheckErrorKind::EmptyTuplesNotAllowed => CheckErrorKind::EmptyTuplesNotAllowed,
            CommonCheckErrorKind::NameAlreadyUsed(name) => CheckErrorKind::NameAlreadyUsed(name),
            CommonCheckErrorKind::UnknownTypeName(name) => CheckErrorKind::UnknownTypeName(name),
        }
    }
}

impl From<CommonCheckErrorKind> for StaticCheckErrorKind {
    fn from(err: CommonCheckErrorKind) -> Self {
        match err {
            CommonCheckErrorKind::CostOverflow => StaticCheckErrorKind::CostOverflow,
            CommonCheckErrorKind::CostBalanceExceeded(a, b) => {
                StaticCheckErrorKind::CostBalanceExceeded(a, b)
            }
            CommonCheckErrorKind::MemoryBalanceExceeded(a, b) => {
                StaticCheckErrorKind::MemoryBalanceExceeded(a, b)
            }
            CommonCheckErrorKind::CostComputationFailed(s) => {
                StaticCheckErrorKind::CostComputationFailed(s)
            }
            CommonCheckErrorKind::ExecutionTimeExpired => {
                StaticCheckErrorKind::ExecutionTimeExpired
            }
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
            CommonCheckErrorKind::ExpectsRejectable(s) => {
                StaticCheckErrorKind::ExpectsRejectable(s)
            }
            CommonCheckErrorKind::ExpectsAcceptable(s) => {
                StaticCheckErrorKind::ExpectsAcceptable(s)
            }
            CommonCheckErrorKind::CouldNotDetermineType => {
                StaticCheckErrorKind::CouldNotDetermineType
            }
            CommonCheckErrorKind::ValueTooLarge => StaticCheckErrorKind::ValueTooLarge,
            CommonCheckErrorKind::TypeSignatureTooDeep => {
                StaticCheckErrorKind::TypeSignatureTooDeep
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
            CommonCheckErrorKind::InvalidTypeDescription => {
                StaticCheckErrorKind::InvalidTypeDescription
            }
            CommonCheckErrorKind::SupertypeTooLarge => StaticCheckErrorKind::SupertypeTooLarge,
            CommonCheckErrorKind::TypeError(a, b) => StaticCheckErrorKind::TypeError(a, b),
            CommonCheckErrorKind::BadSyntaxBinding(e) => StaticCheckErrorKind::BadSyntaxBinding(e),
            CommonCheckErrorKind::ValueOutOfBounds => StaticCheckErrorKind::ValueOutOfBounds,
            CommonCheckErrorKind::EmptyTuplesNotAllowed => {
                StaticCheckErrorKind::EmptyTuplesNotAllowed
            }
            CommonCheckErrorKind::NameAlreadyUsed(name) => {
                StaticCheckErrorKind::NameAlreadyUsed(name)
            }
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

fn formatted_expected_types(expected_types: &[TypeSignature]) -> String {
    let mut expected_types_joined = format!("'{}'", expected_types[0]);

    if expected_types.len() > 2 {
        for expected_type in expected_types[1..expected_types.len() - 1].iter() {
            expected_types_joined.push_str(&format!(", '{expected_type}'"));
        }
    }
    expected_types_joined.push_str(&format!(
        " or '{}'",
        expected_types[expected_types.len() - 1]
    ));
    expected_types_joined
}

impl DiagnosableError for StaticCheckErrorKind {
    fn message(&self) -> String {
        match &self {
            StaticCheckErrorKind::SupertypeTooLarge => "supertype of two types is too large".into(),
            StaticCheckErrorKind::ExpectsRejectable(s) => format!("unexpected and unacceptable interpreter behavior: {s}"),
            StaticCheckErrorKind::ExpectsAcceptable(s) => format!("unexpected but acceptable interpreter behaviour: {s}"),
            StaticCheckErrorKind::BadMatchOptionSyntax(source) =>
                format!("match on a optional type uses the following syntax: (match input some-name if-some-expression if-none-expression). Caused by: {}",
                        source.message()),
            StaticCheckErrorKind::BadMatchResponseSyntax(source) =>
                format!("match on a result type uses the following syntax: (match input ok-name if-ok-expression err-name if-err-expression). Caused by: {}",
                        source.message()),
            StaticCheckErrorKind::BadMatchInput(t) =>
                format!("match requires an input of either a response or optional, found input: '{t}'"),
            StaticCheckErrorKind::CostOverflow => "contract execution cost overflowed cost counter".into(),
            StaticCheckErrorKind::CostBalanceExceeded(a, b) => format!("contract execution cost exceeded budget: {a:?} > {b:?}"),
            StaticCheckErrorKind::MemoryBalanceExceeded(a, b) => format!("contract execution cost exceeded memory budget: {a:?} > {b:?}"),
            StaticCheckErrorKind::CostComputationFailed(s) => format!("contract cost computation failed: {s}"),
            StaticCheckErrorKind::ExecutionTimeExpired => "execution time expired".into(),
            StaticCheckErrorKind::InvalidTypeDescription => "supplied type description is invalid".into(),
            StaticCheckErrorKind::EmptyTuplesNotAllowed => "tuple types may not be empty".into(),
            StaticCheckErrorKind::UnknownTypeName(name) => format!("failed to parse type: '{name}'"),
            StaticCheckErrorKind::ValueTooLarge => "created a type which was greater than maximum allowed value size".into(),
            StaticCheckErrorKind::ValueOutOfBounds => "created a type which value size was out of defined bounds".into(),
            StaticCheckErrorKind::TypeSignatureTooDeep => "created a type which was deeper than maximum allowed type depth".into(),
            StaticCheckErrorKind::ExpectedName => "expected a name argument to this function".into(),
            StaticCheckErrorKind::ConstructedListTooLarge => "reached limit of elements in a sequence".into(),
            StaticCheckErrorKind::TypeError(expected_type, found_type) => format!("expecting expression of type '{expected_type}', found '{found_type}'"),
            StaticCheckErrorKind::UnionTypeError(expected_types, found_type) => format!("expecting expression of type {}, found '{}'", formatted_expected_types(expected_types), found_type),
            StaticCheckErrorKind::ExpectedOptionalType(found_type) => format!("expecting expression of type 'optional', found '{found_type}'"),
            StaticCheckErrorKind::ExpectedOptionalOrResponseType(found_type) => format!("expecting expression of type 'optional' or 'response', found '{found_type}'"),
            StaticCheckErrorKind::ExpectedResponseType(found_type) => format!("expecting expression of type 'response', found '{found_type}'"),
            StaticCheckErrorKind::CouldNotDetermineResponseOkType => "attempted to obtain 'ok' value from response, but 'ok' type is indeterminate".into(),
            StaticCheckErrorKind::CouldNotDetermineResponseErrType => "attempted to obtain 'err' value from response, but 'err' type is indeterminate".into(),
            StaticCheckErrorKind::CouldNotDetermineMatchTypes => "attempted to match on an (optional) or (response) type where either the some, ok, or err type is indeterminate. you may wish to use unwrap-panic or unwrap-err-panic instead.".into(),
            StaticCheckErrorKind::CouldNotDetermineType => "type of expression cannot be determined".into(),
            StaticCheckErrorKind::BadTupleFieldName => "invalid tuple field name".into(),
            StaticCheckErrorKind::ExpectedTuple(type_signature) => format!("expecting tuple, found '{type_signature}'"),
            StaticCheckErrorKind::NoSuchTupleField(field_name, tuple_signature) => format!("cannot find field '{field_name}' in tuple '{tuple_signature}'"),
            StaticCheckErrorKind::BadTupleConstruction(message) => format!("invalid tuple syntax: {message}"),
            StaticCheckErrorKind::NoSuchDataVariable(var_name) => format!("use of unresolved persisted variable '{var_name}'"),
            StaticCheckErrorKind::BadMapName => "invalid map name".into(),
            StaticCheckErrorKind::NoSuchMap(map_name) => format!("use of unresolved map '{map_name}'"),
            StaticCheckErrorKind::DefineFunctionBadSignature => "invalid function definition".into(),
            StaticCheckErrorKind::BadFunctionName => "invalid function name".into(),
            StaticCheckErrorKind::BadMapTypeDefinition => "invalid map definition".into(),
            StaticCheckErrorKind::PublicFunctionMustReturnResponse(found_type) => format!("public functions must return an expression of type 'response', found '{found_type}'"),
            StaticCheckErrorKind::DefineVariableBadSignature => "invalid variable definition".into(),
            StaticCheckErrorKind::ReturnTypesMustMatch(type_1, type_2) => format!("detected two execution paths, returning two different expression types (got '{type_1}' and '{type_2}')"),
            StaticCheckErrorKind::NoSuchContract(contract_identifier) => format!("use of unresolved contract '{contract_identifier}'"),
            StaticCheckErrorKind::NoSuchPublicFunction(contract_identifier, function_name) => format!("contract '{contract_identifier}' has no public function '{function_name}'"),
            StaticCheckErrorKind::ContractAlreadyExists(contract_identifier) => format!("contract name '{contract_identifier}' conflicts with existing contract"),
            StaticCheckErrorKind::ContractCallExpectName => "missing contract name for call".into(),
            StaticCheckErrorKind::ExpectedCallableType(found_type) => format!("expected a callable contract, found {found_type}"),
            StaticCheckErrorKind::NoSuchBlockInfoProperty(property_name) => format!("use of block unknown property '{property_name}'"),
            StaticCheckErrorKind::NoSuchStacksBlockInfoProperty(property_name) => format!("use of unknown stacks block property '{property_name}'"),
            StaticCheckErrorKind::NoSuchTenureInfoProperty(property_name) => format!("use of unknown tenure property '{property_name}'"),
            StaticCheckErrorKind::GetBlockInfoExpectPropertyName => "missing property name for block info introspection".into(),
            StaticCheckErrorKind::GetBurnBlockInfoExpectPropertyName => "missing property name for burn block info introspection".into(),
            StaticCheckErrorKind::GetStacksBlockInfoExpectPropertyName => "missing property name for stacks block info introspection".into(),
            StaticCheckErrorKind::GetTenureInfoExpectPropertyName => "missing property name for tenure info introspection".into(),
            StaticCheckErrorKind::NameAlreadyUsed(name) => format!("defining '{name}' conflicts with previous value"),
            StaticCheckErrorKind::ReservedWord(name) => format!("{name} is a reserved word"),
            StaticCheckErrorKind::NonFunctionApplication => "expecting expression of type function".into(),
            StaticCheckErrorKind::ExpectedListApplication => "expecting expression of type list".into(),
            StaticCheckErrorKind::ExpectedSequence(found_type) => format!("expecting expression of type 'list', 'buff', 'string-ascii' or 'string-utf8' - found '{found_type}'"),
            StaticCheckErrorKind::MaxLengthOverflow => format!("expecting a value <= {}", u32::MAX),
            StaticCheckErrorKind::BadLetSyntax => "invalid syntax of 'let'".into(),
            StaticCheckErrorKind::BadSyntaxBinding(binding_error) => format!("invalid syntax binding: {}", &binding_error.message()),
            StaticCheckErrorKind::MaxContextDepthReached => "reached depth limit".into(),
            StaticCheckErrorKind::UndefinedVariable(var_name) => format!("use of unresolved variable '{var_name}'"),
            StaticCheckErrorKind::RequiresAtLeastArguments(expected, found) => format!("expecting >= {expected} arguments, got {found}"),
            StaticCheckErrorKind::RequiresAtMostArguments(expected, found) => format!("expecting < {expected} arguments, got {found}"),
            StaticCheckErrorKind::IncorrectArgumentCount(expected_count, found_count) => format!("expecting {expected_count} arguments, got {found_count}"),
            StaticCheckErrorKind::IfArmsMustMatch(type_1, type_2) => format!("expression types returned by the arms of 'if' must match (got '{type_1}' and '{type_2}')"),
            StaticCheckErrorKind::MatchArmsMustMatch(type_1, type_2) => format!("expression types returned by the arms of 'match' must match (got '{type_1}' and '{type_2}')"),
            StaticCheckErrorKind::DefaultTypesMustMatch(type_1, type_2) => format!("expression types passed in 'default-to' must match (got '{type_1}' and '{type_2}')"),
            StaticCheckErrorKind::IllegalOrUnknownFunctionApplication(function_name) => format!("use of illegal / unresolved function '{function_name}"),
            StaticCheckErrorKind::UnknownFunction(function_name) => format!("use of unresolved function '{function_name}'"),
            StaticCheckErrorKind::TooManyFunctionParameters(found, allowed) => format!("too many function parameters specified: found {found}, the maximum is {allowed}"),
            StaticCheckErrorKind::WriteAttemptedInReadOnly => "expecting read-only statements, detected a writing operation".into(),
            StaticCheckErrorKind::AtBlockClosureMustBeReadOnly => "(at-block ...) closures expect read-only statements, but detected a writing operation".into(),
            StaticCheckErrorKind::BadTokenName => "expecting an token name as an argument".into(),
            StaticCheckErrorKind::DefineNFTBadSignature => "(define-asset ...) expects an asset name and an asset identifier type signature as arguments".into(),
            StaticCheckErrorKind::NoSuchNFT(asset_name) => format!("tried to use asset function with a undefined asset ('{asset_name}')"),
            StaticCheckErrorKind::NoSuchFT(asset_name) => format!("tried to use token function with a undefined token ('{asset_name}')"),
            StaticCheckErrorKind::NoSuchTrait(contract_name, trait_name) => format!("use of unresolved trait {contract_name}.{trait_name}"),
            StaticCheckErrorKind::TraitReferenceUnknown(trait_name) => format!("use of undeclared trait <{trait_name}>"),
            StaticCheckErrorKind::TraitMethodUnknown(trait_name, func_name) => format!("method '{func_name}' unspecified in trait <{trait_name}>"),
            StaticCheckErrorKind::BadTraitImplementation(trait_name, func_name) => format!("invalid signature for method '{func_name}' regarding trait's specification <{trait_name}>"),
            StaticCheckErrorKind::ExpectedTraitIdentifier => "expecting expression of type trait identifier".into(),
            StaticCheckErrorKind::UnexpectedTraitOrFieldReference => "unexpected use of trait reference or field".into(),
            StaticCheckErrorKind::DefineTraitBadSignature => "invalid trait definition".into(),
            StaticCheckErrorKind::DefineTraitDuplicateMethod(method_name) => format!("duplicate method name '{method_name}' in trait definition"),
            StaticCheckErrorKind::ContractOfExpectsTrait => "trait reference expected".into(),
            StaticCheckErrorKind::IncompatibleTrait(expected_trait, actual_trait) => format!("trait '{actual_trait}' is not a compatible with expected trait, '{expected_trait}'"),
            StaticCheckErrorKind::TraitTooManyMethods(found, allowed) => format!("too many trait methods specified: found {found}, the maximum is {allowed}"),
            StaticCheckErrorKind::TypeAlreadyAnnotatedFailure | StaticCheckErrorKind::CheckerImplementationFailure => {
                "internal error - please file an issue on https://github.com/stacks-network/stacks-blockchain".into()
            },
            StaticCheckErrorKind::UncheckedIntermediaryResponses => "intermediary responses in consecutive statements must be checked".into(),
            StaticCheckErrorKind::CouldNotDetermineSerializationType => "could not determine the input type for the serialization function".into(),
            StaticCheckErrorKind::ExpectedListOfAllowances(fn_name, arg_num) => format!("{fn_name} expects a list of asset allowances as argument {arg_num}"),
            StaticCheckErrorKind::AllowanceExprNotAllowed => "allowance expressions are only allowed in the context of a `restrict-assets?` or `as-contract?`".into(),
            StaticCheckErrorKind::ExpectedAllowanceExpr(got_name) => format!("expected an allowance expression, got: {got_name}"),
            StaticCheckErrorKind::WithAllAllowanceNotAllowed => "with-all-assets-unsafe is not allowed here, only in the allowance list for `as-contract?`".into(),
            StaticCheckErrorKind::WithAllAllowanceNotAlone => "with-all-assets-unsafe must not be used along with other allowances".into(),
            StaticCheckErrorKind::WithNftExpectedListOfIdentifiers => "with-nft allowance must include a list of asset identifiers".into(),
            StaticCheckErrorKind::MaxIdentifierLengthExceeded(max_len, len) => format!("with-nft allowance identifiers list must not exceed {max_len} elements, got {len}"),
            StaticCheckErrorKind::TooManyAllowances(max_allowed, found) => format!("too many allowances specified, the maximum is {max_allowed}, found {found}"),
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
