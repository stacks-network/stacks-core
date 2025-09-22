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
use crate::types::{TraitIdentifier, TupleTypeSignature, TypeSignature, Value};

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

impl From<SyntaxBindingError> for CheckErrors {
    fn from(e: SyntaxBindingError) -> Self {
        Self::BadSyntaxBinding(e)
    }
}

#[derive(Debug, PartialEq)]
pub enum CheckErrors {
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
    BadMatchOptionSyntax(Box<CheckErrors>),
    BadMatchResponseSyntax(Box<CheckErrors>),
    BadMatchInput(Box<TypeSignature>),

    // list typing errors
    ListTypesMustMatch,
    ConstructedListTooLarge,

    // simple type expectation mismatch
    TypeError(Box<TypeSignature>, Box<TypeSignature>),
    TypeValueError(Box<TypeSignature>, Box<Value>),

    InvalidTypeDescription,
    UnknownTypeName(String),

    // union type mismatch
    UnionTypeError(Vec<TypeSignature>, Box<TypeSignature>),
    UnionTypeValueError(Vec<TypeSignature>, Box<Value>),

    ExpectedOptionalType(Box<TypeSignature>),
    ExpectedResponseType(Box<TypeSignature>),
    ExpectedOptionalOrResponseType(Box<TypeSignature>),
    ExpectedOptionalValue(Box<Value>),
    ExpectedResponseValue(Box<Value>),
    ExpectedOptionalOrResponseValue(Box<Value>),
    CouldNotDetermineResponseOkType,
    CouldNotDetermineResponseErrType,
    CouldNotDetermineSerializationType,
    UncheckedIntermediaryResponses,
    ExpectedContractPrincipalValue(Box<Value>),

    CouldNotDetermineMatchTypes,
    CouldNotDetermineType,

    // Checker runtime failures
    TypeAlreadyAnnotatedFailure,
    CheckerImplementationFailure,

    // Assets
    BadTokenName,
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
    ExpectedTuple(Box<TypeSignature>),
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
    PublicFunctionMustReturnResponse(Box<TypeSignature>),
    DefineVariableBadSignature,
    ReturnTypesMustMatch(Box<TypeSignature>, Box<TypeSignature>),

    CircularReference(Vec<String>),

    // contract-call errors
    NoSuchContract(String),
    NoSuchPublicFunction(String, String),
    PublicFunctionNotReadOnly(String, String),
    ContractAlreadyExists(String),
    ContractCallExpectName,
    ExpectedCallableType(Box<TypeSignature>),

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
    ExpectedSequence(Box<TypeSignature>),
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
    IfArmsMustMatch(Box<TypeSignature>, Box<TypeSignature>),
    MatchArmsMustMatch(Box<TypeSignature>, Box<TypeSignature>),
    DefaultTypesMustMatch(Box<TypeSignature>, Box<TypeSignature>),
    IllegalOrUnknownFunctionApplication(String),
    UnknownFunction(String),

    // traits
    NoSuchTrait(String, String),
    TraitReferenceUnknown(String),
    TraitMethodUnknown(String, String),
    ExpectedTraitIdentifier,
    TraitReferenceNotAllowed,
    BadTraitImplementation(String, String),
    DefineTraitBadSignature,
    DefineTraitDuplicateMethod(String),
    UnexpectedTraitOrFieldReference,
    TraitBasedContractCallInReadOnly,
    ContractOfExpectsTrait,
    IncompatibleTrait(Box<TraitIdentifier>, Box<TraitIdentifier>),

    // strings
    InvalidCharactersDetected,
    InvalidUTF8Encoding,

    // secp256k1 signature
    InvalidSecp65k1Signature,

    WriteAttemptedInReadOnly,
    AtBlockClosureMustBeReadOnly,

    // time checker errors
    ExecutionTimeExpired,

    // contract post-conditions
    ExpectedListOfAllowances(String, i32),
    AllowanceExprNotAllowed,
    ExpectedAllowanceExpr(String),
    WithAllAllowanceNotAllowed,
    WithAllAllowanceNotAlone,
    WithNftExpectedListOfIdentifiers,
    MaxIdentifierLengthExceeded(u32),
}

#[derive(Debug, PartialEq)]
pub struct CheckError {
    pub err: Box<CheckErrors>,
    pub expressions: Option<Vec<SymbolicExpression>>,
    pub diagnostic: Diagnostic,
}

impl CheckErrors {
    /// Does this check error indicate that the transaction should be
    /// rejected?
    pub fn rejectable(&self) -> bool {
        matches!(
            self,
            CheckErrors::SupertypeTooLarge | CheckErrors::Expects(_)
        )
    }
}

impl CheckError {
    pub fn new(err: CheckErrors) -> CheckError {
        let diagnostic = Diagnostic::err(&err);
        CheckError {
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

    pub fn with_expression(err: CheckErrors, expr: &SymbolicExpression) -> Self {
        let mut r = Self::new(err);
        r.set_expression(expr);
        r
    }
}

impl From<(SyntaxBindingError, &SymbolicExpression)> for CheckError {
    fn from(e: (SyntaxBindingError, &SymbolicExpression)) -> Self {
        Self::with_expression(CheckErrors::BadSyntaxBinding(e.0), e.1)
    }
}

impl From<(CheckErrors, &SymbolicExpression)> for CheckError {
    fn from(e: (CheckErrors, &SymbolicExpression)) -> Self {
        let mut ce = Self::new(e.0);
        ce.set_expression(e.1);
        ce
    }
}

impl From<(CheckErrors, &SymbolicExpression)> for CheckErrors {
    fn from(e: (CheckErrors, &SymbolicExpression)) -> Self {
        e.0
    }
}

impl fmt::Display for CheckErrors {
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
        CheckError::from(CheckErrors::from(err))
    }
}

impl From<CostErrors> for CheckErrors {
    fn from(err: CostErrors) -> Self {
        match err {
            CostErrors::CostOverflow => CheckErrors::CostOverflow,
            CostErrors::CostBalanceExceeded(a, b) => CheckErrors::CostBalanceExceeded(a, b),
            CostErrors::MemoryBalanceExceeded(a, b) => CheckErrors::MemoryBalanceExceeded(a, b),
            CostErrors::CostComputationFailed(s) => CheckErrors::CostComputationFailed(s),
            CostErrors::CostContractLoadFailure => {
                CheckErrors::CostComputationFailed("Failed to load cost contract".into())
            }
            CostErrors::InterpreterFailure => {
                CheckErrors::Expects("Unexpected interpreter failure in cost computation".into())
            }
            CostErrors::Expect(s) => CheckErrors::Expects(s),
            CostErrors::ExecutionTimeExpired => CheckErrors::ExecutionTimeExpired,
        }
    }
}

impl error::Error for CheckError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl error::Error for CheckErrors {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl From<CheckErrors> for CheckError {
    fn from(err: CheckErrors) -> Self {
        CheckError::new(err)
    }
}

#[cfg(any(test, feature = "testing"))]
impl From<CheckErrors> for String {
    fn from(o: CheckErrors) -> Self {
        o.to_string()
    }
}

pub fn check_argument_count<T>(expected: usize, args: &[T]) -> Result<(), CheckErrors> {
    if args.len() != expected {
        Err(CheckErrors::IncorrectArgumentCount(expected, args.len()))
    } else {
        Ok(())
    }
}

pub fn check_arguments_at_least<T>(expected: usize, args: &[T]) -> Result<(), CheckErrors> {
    if args.len() < expected {
        Err(CheckErrors::RequiresAtLeastArguments(expected, args.len()))
    } else {
        Ok(())
    }
}

pub fn check_arguments_at_most<T>(expected: usize, args: &[T]) -> Result<(), CheckErrors> {
    if args.len() > expected {
        Err(CheckErrors::RequiresAtMostArguments(expected, args.len()))
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

impl DiagnosableError for CheckErrors {
    fn message(&self) -> String {
        match &self {
            CheckErrors::SupertypeTooLarge => "supertype of two types is too large".into(),
            CheckErrors::Expects(s) => format!("unexpected interpreter behavior: {s}"),
            CheckErrors::BadMatchOptionSyntax(source) =>
                format!("match on a optional type uses the following syntax: (match input some-name if-some-expression if-none-expression). Caused by: {}",
                        source.message()),
            CheckErrors::BadMatchResponseSyntax(source) =>
                format!("match on a result type uses the following syntax: (match input ok-name if-ok-expression err-name if-err-expression). Caused by: {}",
                        source.message()),
            CheckErrors::BadMatchInput(t) =>
                format!("match requires an input of either a response or optional, found input: '{t}'"),
            CheckErrors::CostOverflow => "contract execution cost overflowed cost counter".into(),
            CheckErrors::CostBalanceExceeded(a, b) => format!("contract execution cost exceeded budget: {a:?} > {b:?}"),
            CheckErrors::MemoryBalanceExceeded(a, b) => format!("contract execution cost exceeded memory budget: {a:?} > {b:?}"),
            CheckErrors::InvalidTypeDescription => "supplied type description is invalid".into(),
            CheckErrors::EmptyTuplesNotAllowed => "tuple types may not be empty".into(),
            CheckErrors::UnknownTypeName(name) => format!("failed to parse type: '{name}'"),
            CheckErrors::ValueTooLarge => "created a type which was greater than maximum allowed value size".into(),
            CheckErrors::ValueOutOfBounds => "created a type which value size was out of defined bounds".into(),
            CheckErrors::TypeSignatureTooDeep => "created a type which was deeper than maximum allowed type depth".into(),
            CheckErrors::ExpectedName => "expected a name argument to this function".into(),
            CheckErrors::ListTypesMustMatch => "expecting elements of same type in a list".into(),
            CheckErrors::ConstructedListTooLarge => "reached limit of elements in a sequence".into(),
            CheckErrors::TypeError(expected_type, found_type) => format!("expecting expression of type '{expected_type}', found '{found_type}'"),
            CheckErrors::TypeValueError(expected_type, found_value) => format!("expecting expression of type '{expected_type}', found '{found_value}'"),
            CheckErrors::UnionTypeError(expected_types, found_type) => format!("expecting expression of type {}, found '{}'", formatted_expected_types(expected_types), found_type),
            CheckErrors::UnionTypeValueError(expected_types, found_type) => format!("expecting expression of type {}, found '{}'", formatted_expected_types(expected_types), found_type),
            CheckErrors::ExpectedOptionalType(found_type) => format!("expecting expression of type 'optional', found '{found_type}'"),
            CheckErrors::ExpectedOptionalOrResponseType(found_type) => format!("expecting expression of type 'optional' or 'response', found '{found_type}'"),
            CheckErrors::ExpectedOptionalOrResponseValue(found_value) =>  format!("expecting expression of type 'optional' or 'response', found '{found_value}'"),
            CheckErrors::ExpectedResponseType(found_type) => format!("expecting expression of type 'response', found '{found_type}'"),
            CheckErrors::ExpectedOptionalValue(found_value) => format!("expecting expression of type 'optional', found '{found_value}'"),
            CheckErrors::ExpectedResponseValue(found_value) => format!("expecting expression of type 'response', found '{found_value}'"),
            CheckErrors::ExpectedContractPrincipalValue(found_value) => format!("expecting contract principal value, found '{found_value}'"),
            CheckErrors::CouldNotDetermineResponseOkType => "attempted to obtain 'ok' value from response, but 'ok' type is indeterminate".into(),
            CheckErrors::CouldNotDetermineResponseErrType => "attempted to obtain 'err' value from response, but 'err' type is indeterminate".into(),
            CheckErrors::CouldNotDetermineMatchTypes => "attempted to match on an (optional) or (response) type where either the some, ok, or err type is indeterminate. you may wish to use unwrap-panic or unwrap-err-panic instead.".into(),
            CheckErrors::CouldNotDetermineType => "type of expression cannot be determined".into(),
            CheckErrors::BadTupleFieldName => "invalid tuple field name".into(),
            CheckErrors::ExpectedTuple(type_signature) => format!("expecting tuple, found '{type_signature}'"),
            CheckErrors::NoSuchTupleField(field_name, tuple_signature) => format!("cannot find field '{field_name}' in tuple '{tuple_signature}'"),
            CheckErrors::BadTupleConstruction(message) => format!("invalid tuple syntax: {message}"),
            CheckErrors::NoSuchDataVariable(var_name) => format!("use of unresolved persisted variable '{var_name}'"),
            CheckErrors::BadTransferSTXArguments => "STX transfer expects an int amount, from principal, to principal".into(),
            CheckErrors::BadTransferFTArguments => "transfer expects an int amount, from principal, to principal".into(),
            CheckErrors::BadTransferNFTArguments => "transfer expects an asset, from principal, to principal".into(),
            CheckErrors::BadMintFTArguments => "mint expects a uint amount and from principal".into(),
            CheckErrors::BadBurnFTArguments => "burn expects a uint amount and from principal".into(),
            CheckErrors::BadMapName => "invalid map name".into(),
            CheckErrors::NoSuchMap(map_name) => format!("use of unresolved map '{map_name}'"),
            CheckErrors::DefineFunctionBadSignature => "invalid function definition".into(),
            CheckErrors::BadFunctionName => "invalid function name".into(),
            CheckErrors::BadMapTypeDefinition => "invalid map definition".into(),
            CheckErrors::PublicFunctionMustReturnResponse(found_type) => format!("public functions must return an expression of type 'response', found '{found_type}'"),
            CheckErrors::DefineVariableBadSignature => "invalid variable definition".into(),
            CheckErrors::ReturnTypesMustMatch(type_1, type_2) => format!("detected two execution paths, returning two different expression types (got '{type_1}' and '{type_2}')"),
            CheckErrors::NoSuchContract(contract_identifier) => format!("use of unresolved contract '{contract_identifier}'"),
            CheckErrors::NoSuchPublicFunction(contract_identifier, function_name) => format!("contract '{contract_identifier}' has no public function '{function_name}'"),
            CheckErrors::PublicFunctionNotReadOnly(contract_identifier, function_name) => format!("function '{contract_identifier}' in '{function_name}' is not read-only"),
            CheckErrors::ContractAlreadyExists(contract_identifier) => format!("contract name '{contract_identifier}' conflicts with existing contract"),
            CheckErrors::ContractCallExpectName => "missing contract name for call".into(),
            CheckErrors::ExpectedCallableType(found_type) => format!("expected a callable contract, found {found_type}"),
            CheckErrors::NoSuchBlockInfoProperty(property_name) => format!("use of block unknown property '{property_name}'"),
            CheckErrors::NoSuchBurnBlockInfoProperty(property_name) => format!("use of burn block unknown property '{property_name}'"),
            CheckErrors::NoSuchStacksBlockInfoProperty(property_name) => format!("use of unknown stacks block property '{property_name}'"),
            CheckErrors::NoSuchTenureInfoProperty(property_name) => format!("use of unknown tenure property '{property_name}'"),
            CheckErrors::GetBlockInfoExpectPropertyName => "missing property name for block info introspection".into(),
            CheckErrors::GetBurnBlockInfoExpectPropertyName => "missing property name for burn block info introspection".into(),
            CheckErrors::GetStacksBlockInfoExpectPropertyName => "missing property name for stacks block info introspection".into(),
            CheckErrors::GetTenureInfoExpectPropertyName => "missing property name for tenure info introspection".into(),
            CheckErrors::NameAlreadyUsed(name) => format!("defining '{name}' conflicts with previous value"),
            CheckErrors::ReservedWord(name) => format!("{name} is a reserved word"),
            CheckErrors::NonFunctionApplication => "expecting expression of type function".into(),
            CheckErrors::ExpectedListApplication => "expecting expression of type list".into(),
            CheckErrors::ExpectedSequence(found_type) => format!("expecting expression of type 'list', 'buff', 'string-ascii' or 'string-utf8' - found '{found_type}'"),
            CheckErrors::MaxLengthOverflow => format!("expecting a value <= {}", u32::MAX),
            CheckErrors::BadLetSyntax => "invalid syntax of 'let'".into(),
            CheckErrors::CircularReference(references) => format!("detected circular reference: ({})", references.join(", ")),
            CheckErrors::BadSyntaxBinding(binding_error) => format!("invalid syntax binding: {}", &binding_error.message()),
            CheckErrors::MaxContextDepthReached => "reached depth limit".into(),
            CheckErrors::UndefinedVariable(var_name) => format!("use of unresolved variable '{var_name}'"),
            CheckErrors::UndefinedFunction(var_name) => format!("use of unresolved function '{var_name}'"),
            CheckErrors::RequiresAtLeastArguments(expected, found) => format!("expecting >= {expected} arguments, got {found}"),
            CheckErrors::RequiresAtMostArguments(expected, found) => format!("expecting < {expected} arguments, got {found}"),
            CheckErrors::IncorrectArgumentCount(expected_count, found_count) => format!("expecting {expected_count} arguments, got {found_count}"),
            CheckErrors::IfArmsMustMatch(type_1, type_2) => format!("expression types returned by the arms of 'if' must match (got '{type_1}' and '{type_2}')"),
            CheckErrors::MatchArmsMustMatch(type_1, type_2) => format!("expression types returned by the arms of 'match' must match (got '{type_1}' and '{type_2}')"),
            CheckErrors::DefaultTypesMustMatch(type_1, type_2) => format!("expression types passed in 'default-to' must match (got '{type_1}' and '{type_2}')"),
            CheckErrors::IllegalOrUnknownFunctionApplication(function_name) => format!("use of illegal / unresolved function '{function_name}"),
            CheckErrors::UnknownFunction(function_name) => format!("use of unresolved function '{function_name}'"),
            CheckErrors::TraitBasedContractCallInReadOnly => "use of trait based contract calls are not allowed in read-only context".into(),
            CheckErrors::WriteAttemptedInReadOnly => "expecting read-only statements, detected a writing operation".into(),
            CheckErrors::AtBlockClosureMustBeReadOnly => "(at-block ...) closures expect read-only statements, but detected a writing operation".into(),
            CheckErrors::BadTokenName => "expecting an token name as an argument".into(),
            CheckErrors::DefineNFTBadSignature => "(define-asset ...) expects an asset name and an asset identifier type signature as arguments".into(),
            CheckErrors::NoSuchNFT(asset_name) => format!("tried to use asset function with a undefined asset ('{asset_name}')"),
            CheckErrors::NoSuchFT(asset_name) => format!("tried to use token function with a undefined token ('{asset_name}')"),
            CheckErrors::NoSuchTrait(contract_name, trait_name) => format!("use of unresolved trait {contract_name}.{trait_name}"),
            CheckErrors::TraitReferenceUnknown(trait_name) => format!("use of undeclared trait <{trait_name}>"),
            CheckErrors::TraitMethodUnknown(trait_name, func_name) => format!("method '{func_name}' unspecified in trait <{trait_name}>"),
            CheckErrors::BadTraitImplementation(trait_name, func_name) => format!("invalid signature for method '{func_name}' regarding trait's specification <{trait_name}>"),
            CheckErrors::ExpectedTraitIdentifier => "expecting expression of type trait identifier".into(),
            CheckErrors::UnexpectedTraitOrFieldReference => "unexpected use of trait reference or field".into(),
            CheckErrors::DefineTraitBadSignature => "invalid trait definition".into(),
            CheckErrors::DefineTraitDuplicateMethod(method_name) => format!("duplicate method name '{method_name}' in trait definition"),
            CheckErrors::TraitReferenceNotAllowed => "trait references can not be stored".into(),
            CheckErrors::ContractOfExpectsTrait => "trait reference expected".into(),
            CheckErrors::IncompatibleTrait(expected_trait, actual_trait) => format!("trait '{actual_trait}' is not a compatible with expected trait, '{expected_trait}'"),
            CheckErrors::InvalidCharactersDetected => "invalid characters detected".into(),
            CheckErrors::InvalidUTF8Encoding => "invalid UTF8 encoding".into(),
            CheckErrors::InvalidSecp65k1Signature => "invalid seckp256k1 signature".into(),
            CheckErrors::TypeAlreadyAnnotatedFailure | CheckErrors::CheckerImplementationFailure => {
                "internal error - please file an issue on https://github.com/stacks-network/stacks-blockchain".into()
            },
            CheckErrors::UncheckedIntermediaryResponses => "intermediary responses in consecutive statements must be checked".into(),
            CheckErrors::CostComputationFailed(s) => format!("contract cost computation failed: {s}"),
            CheckErrors::CouldNotDetermineSerializationType => "could not determine the input type for the serialization function".into(),
            CheckErrors::ExecutionTimeExpired => "execution time expired".into(),
            CheckErrors::ExpectedListOfAllowances(fn_name, arg_num) => format!("{fn_name} expects a list of asset allowances as argument {arg_num}"),
            CheckErrors::AllowanceExprNotAllowed => "allowance expressions are only allowed in the context of a `restrict-assets?` or `as-contract?`".into(),
            CheckErrors::ExpectedAllowanceExpr(got_name) => format!("expected an allowance expression, got: {got_name}"),
            CheckErrors::WithAllAllowanceNotAllowed => "with-all-assets-unsafe is not allowed here, only in the allowance list for `as-contract?`".into(),
            CheckErrors::WithAllAllowanceNotAlone => "with-all-assets-unsafe must not be used along with other allowances".into(),
            CheckErrors::WithNftExpectedListOfIdentifiers => "with-nft allowance must include a list of asset identifiers".into(),
            CheckErrors::MaxIdentifierLengthExceeded(max_len) => format!("with-nft allowance identifiers list must not exceed 128 elements, got {max_len}"),
        }
    }

    fn suggestion(&self) -> Option<String> {
        match &self {
            CheckErrors::BadLetSyntax => Some(
                "'let' syntax example: (let ((supply 1000) (ttl 60)) <next-expression>)".into(),
            ),
            CheckErrors::TraitReferenceUnknown(_) => Some(
                "traits should be either defined, with define-trait, or imported, with use-trait."
                    .into(),
            ),
            CheckErrors::NoSuchBlockInfoProperty(_) => Some(
                "properties available: time, header-hash, burnchain-header-hash, vrf-seed".into(),
            ),
            _ => None,
        }
    }
}
