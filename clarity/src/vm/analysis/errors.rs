// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use crate::vm::costs::{CostErrors, ExecutionCost};
use crate::vm::diagnostic::{DiagnosableError, Diagnostic};
use crate::vm::representations::SymbolicExpression;
use crate::vm::types::{TraitIdentifier, TupleTypeSignature, TypeSignature, Value};

pub type CheckResult<T> = Result<T, CheckError>;

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

impl From<SyntaxBindingError> for CheckErrorKind {
    fn from(e: SyntaxBindingError) -> Self {
        Self::BadSyntaxBinding(e)
    }
}

/// Enumerates the specific kinds of semantic or structural rule violations in Clarity code.
///
/// This type represents failures related to the program's meaning and structure, such as
/// type mismatches, undefined variables, or incorrect function arity.
///
/// This enum serves two purposes in the VM:
///
/// 1.  **During Static Analysis:** It is wrapped in a [`CheckError`] struct to be paired
///     with a full, human-readable [`Diagnostic`] report.
/// 2.  **During Runtime Execution:** It is used directly within the
///     [`crate::vm::errors::VmExecutionError::IntegrityCheck`] variant
///     for dynamic checks that could not be performed statically.
#[derive(Debug, PartialEq)]
pub enum CheckErrorKind {
    // cost checker errors
    CostOverflow,
    CostBalanceExceeded(ExecutionCost, ExecutionCost),
    MemoryBalanceExceeded(u64, u64),
    CostComputationFailed(String),

    ValueTooLarge,
    ValueOutOfBounds,
    TypeSignatureTooDeep,
    ExpectedName,
    SupertypeTooLarge,

    // unexpected interpreter behavior
    Expects(String),

    // match errors
    BadMatchOptionSyntax(Box<CheckErrorKind>),
    BadMatchResponseSyntax(Box<CheckErrorKind>),
    BadMatchInput(TypeSignature),

    // list typing errors
    UnknownListConstructionFailure,
    ListTypesMustMatch,
    ConstructedListTooLarge,

    // simple type expectation mismatch
    TypeError(TypeSignature, TypeSignature),
    TypeLiteralError(TypeSignature, TypeSignature),
    TypeValueError(TypeSignature, Value),

    NoSuperType(TypeSignature, TypeSignature),
    InvalidTypeDescription,
    UnknownTypeName(String),

    // union type mismatch
    UnionTypeError(Vec<TypeSignature>, TypeSignature),
    UnionTypeValueError(Vec<TypeSignature>, Value),

    ExpectedLiteral,
    ExpectedOptionalType(TypeSignature),
    ExpectedResponseType(TypeSignature),
    ExpectedOptionalOrResponseType(TypeSignature),
    ExpectedOptionalValue(Value),
    ExpectedResponseValue(Value),
    ExpectedOptionalOrResponseValue(Value),
    CouldNotDetermineResponseOkType,
    CouldNotDetermineResponseErrType,
    CouldNotDetermineSerializationType,
    UncheckedIntermediaryResponses,

    CouldNotDetermineMatchTypes,
    CouldNotDetermineType,

    // Checker runtime failures
    TypeAlreadyAnnotatedFailure,
    TypeAnnotationExpectedFailure,
    CheckerImplementationFailure,

    // Assets
    BadTokenName,
    DefineFTBadSignature,
    DefineNFTBadSignature,
    NoSuchNFT(String),
    NoSuchFT(String),

    BadTransferSTXArguments,
    BadTransferFTArguments,
    BadTransferNFTArguments,
    BadMintFTArguments,
    BadBurnFTArguments,

    // tuples
    BadTupleFieldName,
    ExpectedTuple(TypeSignature),
    NoSuchTupleField(String, TupleTypeSignature),
    EmptyTuplesNotAllowed,
    BadTupleConstruction(String),

    // variables
    NoSuchDataVariable(String),

    // data map
    BadMapName,
    NoSuchMap(String),

    // defines
    DefineFunctionBadSignature,
    BadFunctionName,
    BadMapTypeDefinition,
    PublicFunctionMustReturnResponse(TypeSignature),
    DefineVariableBadSignature,
    ReturnTypesMustMatch(TypeSignature, TypeSignature),

    CircularReference(Vec<String>),

    // contract-call errors
    NoSuchContract(String),
    NoSuchPublicFunction(String, String),
    PublicFunctionNotReadOnly(String, String),
    ContractAlreadyExists(String),
    ContractCallExpectName,
    ExpectedCallableType(TypeSignature),

    // get-block-info? errors
    NoSuchBlockInfoProperty(String),
    NoSuchBurnBlockInfoProperty(String),
    NoSuchStacksBlockInfoProperty(String),
    NoSuchTenureInfoProperty(String),
    GetBlockInfoExpectPropertyName,
    GetBurnBlockInfoExpectPropertyName,
    GetStacksBlockInfoExpectPropertyName,
    GetTenureInfoExpectPropertyName,

    NameAlreadyUsed(String),
    ReservedWord(String),

    // expect a function, or applying a function to a list
    NonFunctionApplication,
    ExpectedListApplication,
    ExpectedSequence(TypeSignature),
    MaxLengthOverflow,

    // let syntax
    BadLetSyntax,

    // generic binding syntax
    BadSyntaxBinding(SyntaxBindingError),

    MaxContextDepthReached,
    UndefinedFunction(String),
    UndefinedVariable(String),

    // argument counts
    RequiresAtLeastArguments(usize, usize),
    RequiresAtMostArguments(usize, usize),
    IncorrectArgumentCount(usize, usize),
    IfArmsMustMatch(TypeSignature, TypeSignature),
    MatchArmsMustMatch(TypeSignature, TypeSignature),
    DefaultTypesMustMatch(TypeSignature, TypeSignature),
    TooManyExpressions,
    IllegalOrUnknownFunctionApplication(String),
    UnknownFunction(String),

    // traits
    NoSuchTrait(String, String),
    TraitReferenceUnknown(String),
    TraitMethodUnknown(String, String),
    ExpectedTraitIdentifier,
    ImportTraitBadSignature,
    TraitReferenceNotAllowed,
    BadTraitImplementation(String, String),
    DefineTraitBadSignature,
    DefineTraitDuplicateMethod(String),
    UnexpectedTraitOrFieldReference,
    TraitBasedContractCallInReadOnly,
    ContractOfExpectsTrait,
    IncompatibleTrait(TraitIdentifier, TraitIdentifier),

    // strings
    InvalidCharactersDetected,
    InvalidUTF8Encoding,

    // secp256k1 signature
    InvalidSecp65k1Signature,

    WriteAttemptedInReadOnly,
    AtBlockClosureMustBeReadOnly,

    // time checker errors
    ExecutionTimeExpired,
}

/// A complete diagnostic report for a check failure discovered during static analysis.
///
/// This struct represents a complete, user-facing error generated by the static checker.
/// It bundles the machine-readable error category ([`CheckErrorKind`]) with contextual
/// information, including the specific code expressions involved and a fully formed
/// [`Diagnostic`] message intended for display.
///
/// This is the canonical error type for failures discovered *before* execution and is
/// used within the [`crate::vm::clarity::ClarityError::StaticCheck`] variant.
#[derive(Debug, PartialEq)]
pub struct CheckError {
    pub err: CheckErrorKind,
    pub expressions: Option<Vec<SymbolicExpression>>,
    pub diagnostic: Diagnostic,
}

impl CheckErrorKind {
    /// Does this check error indicate that the transaction should be
    /// rejected?
    pub fn rejectable(&self) -> bool {
        matches!(
            self,
            CheckErrorKind::SupertypeTooLarge | CheckErrorKind::Expects(_)
        )
    }
}

impl CheckError {
    pub fn new(err: CheckErrorKind) -> CheckError {
        let diagnostic = Diagnostic::err(&err);
        CheckError {
            err,
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

    pub fn with_expression(err: CheckErrorKind, expr: &SymbolicExpression) -> Self {
        let mut r = Self::new(err);
        r.set_expression(expr);
        r
    }
}

impl From<(SyntaxBindingError, &SymbolicExpression)> for CheckError {
    fn from(e: (SyntaxBindingError, &SymbolicExpression)) -> Self {
        Self::with_expression(CheckErrorKind::BadSyntaxBinding(e.0), e.1)
    }
}

impl From<(CheckErrorKind, &SymbolicExpression)> for CheckError {
    fn from(e: (CheckErrorKind, &SymbolicExpression)) -> Self {
        let mut ce = Self::new(e.0);
        ce.set_expression(e.1);
        ce
    }
}

impl From<(CheckErrorKind, &SymbolicExpression)> for CheckErrorKind {
    fn from(e: (CheckErrorKind, &SymbolicExpression)) -> Self {
        e.0
    }
}

impl fmt::Display for CheckErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.err)?;

        if let Some(ref e) = self.expressions {
            write!(f, "\nNear:\n{e:?}")?;
        }

        Ok(())
    }
}

impl From<CostErrors> for CheckError {
    fn from(err: CostErrors) -> Self {
        CheckError::from(CheckErrorKind::from(err))
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
            CostErrors::InterpreterFailure => {
                CheckErrorKind::Expects("Unexpected interpreter failure in cost computation".into())
            }
            CostErrors::Expect(s) => CheckErrorKind::Expects(s),
            CostErrors::ExecutionTimeExpired => CheckErrorKind::ExecutionTimeExpired,
        }
    }
}

impl error::Error for CheckError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl error::Error for CheckErrorKind {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl From<CheckErrorKind> for CheckError {
    fn from(err: CheckErrorKind) -> Self {
        CheckError::new(err)
    }
}

pub fn check_argument_count<T>(expected: usize, args: &[T]) -> Result<(), CheckErrorKind> {
    if args.len() != expected {
        Err(CheckErrorKind::IncorrectArgumentCount(expected, args.len()))
    } else {
        Ok(())
    }
}

pub fn check_arguments_at_least<T>(expected: usize, args: &[T]) -> Result<(), CheckErrorKind> {
    if args.len() < expected {
        Err(CheckErrorKind::RequiresAtLeastArguments(
            expected,
            args.len(),
        ))
    } else {
        Ok(())
    }
}

pub fn check_arguments_at_most<T>(expected: usize, args: &[T]) -> Result<(), CheckErrorKind> {
    if args.len() > expected {
        Err(CheckErrorKind::RequiresAtMostArguments(
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

impl DiagnosableError for CheckErrorKind {
    fn message(&self) -> String {
        match &self {
            CheckErrorKind::ExpectedLiteral => "expected a literal argument".into(),
            CheckErrorKind::SupertypeTooLarge => "supertype of two types is too large".into(),
            CheckErrorKind::Expects(s) => format!("unexpected interpreter behavior: {s}"),
            CheckErrorKind::BadMatchOptionSyntax(source) =>
                format!("match on a optional type uses the following syntax: (match input some-name if-some-expression if-none-expression). Caused by: {}",
                        source.message()),
            CheckErrorKind::BadMatchResponseSyntax(source) =>
                format!("match on a result type uses the following syntax: (match input ok-name if-ok-expression err-name if-err-expression). Caused by: {}",
                        source.message()),
            CheckErrorKind::BadMatchInput(t) =>
                format!("match requires an input of either a response or optional, found input: '{t}'"),
            CheckErrorKind::TypeAnnotationExpectedFailure => "analysis expected type to already be annotated for expression".into(),
            CheckErrorKind::CostOverflow => "contract execution cost overflowed cost counter".into(),
            CheckErrorKind::CostBalanceExceeded(a, b) => format!("contract execution cost exceeded budget: {a:?} > {b:?}"),
            CheckErrorKind::MemoryBalanceExceeded(a, b) => format!("contract execution cost exceeded memory budget: {a:?} > {b:?}"),
            CheckErrorKind::InvalidTypeDescription => "supplied type description is invalid".into(),
            CheckErrorKind::EmptyTuplesNotAllowed => "tuple types may not be empty".into(),
            CheckErrorKind::UnknownTypeName(name) => format!("failed to parse type: '{name}'"),
            CheckErrorKind::ValueTooLarge => "created a type which was greater than maximum allowed value size".into(),
            CheckErrorKind::ValueOutOfBounds => "created a type which value size was out of defined bounds".into(),
            CheckErrorKind::TypeSignatureTooDeep => "created a type which was deeper than maximum allowed type depth".into(),
            CheckErrorKind::ExpectedName => "expected a name argument to this function".into(),
            CheckErrorKind::NoSuperType(a, b) => format!("unable to create a supertype for the two types: '{a}' and '{b}'"),
            CheckErrorKind::UnknownListConstructionFailure => "invalid syntax for list definition".into(),
            CheckErrorKind::ListTypesMustMatch => "expecting elements of same type in a list".into(),
            CheckErrorKind::ConstructedListTooLarge => "reached limit of elements in a sequence".into(),
            CheckErrorKind::TypeError(expected_type, found_type) => format!("expecting expression of type '{expected_type}', found '{found_type}'"),
            CheckErrorKind::TypeLiteralError(expected_type, found_type) => format!("expecting a literal of type '{expected_type}', found '{found_type}'"),
            CheckErrorKind::TypeValueError(expected_type, found_value) => format!("expecting expression of type '{expected_type}', found '{found_value}'"),
            CheckErrorKind::UnionTypeError(expected_types, found_type) => format!("expecting expression of type {}, found '{}'", formatted_expected_types(expected_types), found_type),
            CheckErrorKind::UnionTypeValueError(expected_types, found_type) => format!("expecting expression of type {}, found '{}'", formatted_expected_types(expected_types), found_type),
            CheckErrorKind::ExpectedOptionalType(found_type) => format!("expecting expression of type 'optional', found '{found_type}'"),
            CheckErrorKind::ExpectedOptionalOrResponseType(found_type) => format!("expecting expression of type 'optional' or 'response', found '{found_type}'"),
            CheckErrorKind::ExpectedOptionalOrResponseValue(found_type) =>  format!("expecting expression of type 'optional' or 'response', found '{found_type}'"),
            CheckErrorKind::ExpectedResponseType(found_type) => format!("expecting expression of type 'response', found '{found_type}'"),
            CheckErrorKind::ExpectedOptionalValue(found_type) => format!("expecting expression of type 'optional', found '{found_type}'"),
            CheckErrorKind::ExpectedResponseValue(found_type) => format!("expecting expression of type 'response', found '{found_type}'"),
            CheckErrorKind::CouldNotDetermineResponseOkType => "attempted to obtain 'ok' value from response, but 'ok' type is indeterminate".into(),
            CheckErrorKind::CouldNotDetermineResponseErrType => "attempted to obtain 'err' value from response, but 'err' type is indeterminate".into(),
            CheckErrorKind::CouldNotDetermineMatchTypes => "attempted to match on an (optional) or (response) type where either the some, ok, or err type is indeterminate. you may wish to use unwrap-panic or unwrap-err-panic instead.".into(),
            CheckErrorKind::CouldNotDetermineType => "type of expression cannot be determined".into(),
            CheckErrorKind::BadTupleFieldName => "invalid tuple field name".into(),
            CheckErrorKind::ExpectedTuple(type_signature) => format!("expecting tuple, found '{type_signature}'"),
            CheckErrorKind::NoSuchTupleField(field_name, tuple_signature) => format!("cannot find field '{field_name}' in tuple '{tuple_signature}'"),
            CheckErrorKind::BadTupleConstruction(message) => format!("invalid tuple syntax: {message}"),
            CheckErrorKind::NoSuchDataVariable(var_name) => format!("use of unresolved persisted variable '{var_name}'"),
            CheckErrorKind::BadTransferSTXArguments => "STX transfer expects an int amount, from principal, to principal".into(),
            CheckErrorKind::BadTransferFTArguments => "transfer expects an int amount, from principal, to principal".into(),
            CheckErrorKind::BadTransferNFTArguments => "transfer expects an asset, from principal, to principal".into(),
            CheckErrorKind::BadMintFTArguments => "mint expects a uint amount and from principal".into(),
            CheckErrorKind::BadBurnFTArguments => "burn expects a uint amount and from principal".into(),
            CheckErrorKind::BadMapName => "invalid map name".into(),
            CheckErrorKind::NoSuchMap(map_name) => format!("use of unresolved map '{map_name}'"),
            CheckErrorKind::DefineFunctionBadSignature => "invalid function definition".into(),
            CheckErrorKind::BadFunctionName => "invalid function name".into(),
            CheckErrorKind::BadMapTypeDefinition => "invalid map definition".into(),
            CheckErrorKind::PublicFunctionMustReturnResponse(found_type) => format!("public functions must return an expression of type 'response', found '{found_type}'"),
            CheckErrorKind::DefineVariableBadSignature => "invalid variable definition".into(),
            CheckErrorKind::ReturnTypesMustMatch(type_1, type_2) => format!("detected two execution paths, returning two different expression types (got '{type_1}' and '{type_2}')"),
            CheckErrorKind::NoSuchContract(contract_identifier) => format!("use of unresolved contract '{contract_identifier}'"),
            CheckErrorKind::NoSuchPublicFunction(contract_identifier, function_name) => format!("contract '{contract_identifier}' has no public function '{function_name}'"),
            CheckErrorKind::PublicFunctionNotReadOnly(contract_identifier, function_name) => format!("function '{contract_identifier}' in '{function_name}' is not read-only"),
            CheckErrorKind::ContractAlreadyExists(contract_identifier) => format!("contract name '{contract_identifier}' conflicts with existing contract"),
            CheckErrorKind::ContractCallExpectName => "missing contract name for call".into(),
            CheckErrorKind::ExpectedCallableType(found_type) => format!("expected a callable contract, found {found_type}"),
            CheckErrorKind::NoSuchBlockInfoProperty(property_name) => format!("use of block unknown property '{property_name}'"),
            CheckErrorKind::NoSuchBurnBlockInfoProperty(property_name) => format!("use of burn block unknown property '{property_name}'"),
            CheckErrorKind::NoSuchStacksBlockInfoProperty(property_name) => format!("use of unknown stacks block property '{property_name}'"),
            CheckErrorKind::NoSuchTenureInfoProperty(property_name) => format!("use of unknown tenure property '{property_name}'"),
            CheckErrorKind::GetBlockInfoExpectPropertyName => "missing property name for block info introspection".into(),
            CheckErrorKind::GetBurnBlockInfoExpectPropertyName => "missing property name for burn block info introspection".into(),
            CheckErrorKind::GetStacksBlockInfoExpectPropertyName => "missing property name for stacks block info introspection".into(),
            CheckErrorKind::GetTenureInfoExpectPropertyName => "missing property name for tenure info introspection".into(),
            CheckErrorKind::NameAlreadyUsed(name) => format!("defining '{name}' conflicts with previous value"),
            CheckErrorKind::ReservedWord(name) => format!("{name} is a reserved word"),
            CheckErrorKind::NonFunctionApplication => "expecting expression of type function".into(),
            CheckErrorKind::ExpectedListApplication => "expecting expression of type list".into(),
            CheckErrorKind::ExpectedSequence(found_type) => format!("expecting expression of type 'list', 'buff', 'string-ascii' or 'string-utf8' - found '{found_type}'"),
            CheckErrorKind::MaxLengthOverflow => format!("expecting a value <= {}", u32::MAX),
            CheckErrorKind::BadLetSyntax => "invalid syntax of 'let'".into(),
            CheckErrorKind::CircularReference(references) => format!("detected circular reference: ({})", references.join(", ")),
            CheckErrorKind::BadSyntaxBinding(binding_error) => format!("invalid syntax binding: {}", &binding_error.message()),
            CheckErrorKind::MaxContextDepthReached => "reached depth limit".into(),
            CheckErrorKind::UndefinedVariable(var_name) => format!("use of unresolved variable '{var_name}'"),
            CheckErrorKind::UndefinedFunction(var_name) => format!("use of unresolved function '{var_name}'"),
            CheckErrorKind::RequiresAtLeastArguments(expected, found) => format!("expecting >= {expected} arguments, got {found}"),
            CheckErrorKind::RequiresAtMostArguments(expected, found) => format!("expecting < {expected} arguments, got {found}"),
            CheckErrorKind::IncorrectArgumentCount(expected_count, found_count) => format!("expecting {expected_count} arguments, got {found_count}"),
            CheckErrorKind::IfArmsMustMatch(type_1, type_2) => format!("expression types returned by the arms of 'if' must match (got '{type_1}' and '{type_2}')"),
            CheckErrorKind::MatchArmsMustMatch(type_1, type_2) => format!("expression types returned by the arms of 'match' must match (got '{type_1}' and '{type_2}')"),
            CheckErrorKind::DefaultTypesMustMatch(type_1, type_2) => format!("expression types passed in 'default-to' must match (got '{type_1}' and '{type_2}')"),
            CheckErrorKind::TooManyExpressions => "reached limit of expressions".into(),
            CheckErrorKind::IllegalOrUnknownFunctionApplication(function_name) => format!("use of illegal / unresolved function '{function_name}"),
            CheckErrorKind::UnknownFunction(function_name) => format!("use of unresolved function '{function_name}'"),
            CheckErrorKind::TraitBasedContractCallInReadOnly => "use of trait based contract calls are not allowed in read-only context".into(),
            CheckErrorKind::WriteAttemptedInReadOnly => "expecting read-only statements, detected a writing operation".into(),
            CheckErrorKind::AtBlockClosureMustBeReadOnly => "(at-block ...) closures expect read-only statements, but detected a writing operation".into(),
            CheckErrorKind::BadTokenName => "expecting an token name as an argument".into(),
            CheckErrorKind::DefineFTBadSignature => "(define-token ...) expects a token name as an argument".into(),
            CheckErrorKind::DefineNFTBadSignature => "(define-asset ...) expects an asset name and an asset identifier type signature as arguments".into(),
            CheckErrorKind::NoSuchNFT(asset_name) => format!("tried to use asset function with a undefined asset ('{asset_name}')"),
            CheckErrorKind::NoSuchFT(asset_name) => format!("tried to use token function with a undefined token ('{asset_name}')"),
            CheckErrorKind::NoSuchTrait(contract_name, trait_name) => format!("use of unresolved trait {contract_name}.{trait_name}"),
            CheckErrorKind::TraitReferenceUnknown(trait_name) => format!("use of undeclared trait <{trait_name}>"),
            CheckErrorKind::TraitMethodUnknown(trait_name, func_name) => format!("method '{func_name}' unspecified in trait <{trait_name}>"),
            CheckErrorKind::ImportTraitBadSignature => "(use-trait ...) expects a trait name and a trait identifier".into(),
            CheckErrorKind::BadTraitImplementation(trait_name, func_name) => format!("invalid signature for method '{func_name}' regarding trait's specification <{trait_name}>"),
            CheckErrorKind::ExpectedTraitIdentifier => "expecting expression of type trait identifier".into(),
            CheckErrorKind::UnexpectedTraitOrFieldReference => "unexpected use of trait reference or field".into(),
            CheckErrorKind::DefineTraitBadSignature => "invalid trait definition".into(),
            CheckErrorKind::DefineTraitDuplicateMethod(method_name) => format!("duplicate method name '{method_name}' in trait definition"),
            CheckErrorKind::TraitReferenceNotAllowed => "trait references can not be stored".into(),
            CheckErrorKind::ContractOfExpectsTrait => "trait reference expected".into(),
            CheckErrorKind::IncompatibleTrait(expected_trait, actual_trait) => format!("trait '{actual_trait}' is not a compatible with expected trait, '{expected_trait}'"),
            CheckErrorKind::InvalidCharactersDetected => "invalid characters detected".into(),
            CheckErrorKind::InvalidUTF8Encoding => "invalid UTF8 encoding".into(),
            CheckErrorKind::InvalidSecp65k1Signature => "invalid seckp256k1 signature".into(),
            CheckErrorKind::TypeAlreadyAnnotatedFailure | CheckErrorKind::CheckerImplementationFailure => {
                "internal error - please file an issue on https://github.com/stacks-network/stacks-blockchain".into()
            },
            CheckErrorKind::UncheckedIntermediaryResponses => "intermediary responses in consecutive statements must be checked".into(),
            CheckErrorKind::CostComputationFailed(s) => format!("contract cost computation failed: {s}"),
            CheckErrorKind::CouldNotDetermineSerializationType => "could not determine the input type for the serialization function".into(),
            CheckErrorKind::ExecutionTimeExpired => "execution time expired".into(),
        }
    }

    fn suggestion(&self) -> Option<String> {
        match &self {
            CheckErrorKind::BadLetSyntax => Some(
                "'let' syntax example: (let ((supply 1000) (ttl 60)) <next-expression>)".into(),
            ),
            CheckErrorKind::TraitReferenceUnknown(_) => Some(
                "traits should be either defined, with define-trait, or imported, with use-trait."
                    .into(),
            ),
            CheckErrorKind::NoSuchBlockInfoProperty(_) => Some(
                "properties available: time, header-hash, burnchain-header-hash, vrf-seed".into(),
            ),
            _ => None,
        }
    }
}
