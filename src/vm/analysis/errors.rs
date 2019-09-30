use vm::representations::SymbolicExpression;
use vm::diagnostic::{Diagnostic, DiagnosableError};
use vm::types::{TypeSignature, TupleTypeSignature, Value};
use std::error;
use std::fmt;

pub type CheckResult <T> = Result<T, CheckError>;

#[derive(Debug, PartialEq)]
pub enum CheckErrors {
    ValueTooLarge,
    ExpectedName,

    // list typing errors
    UnknownListConstructionFailure,
    ListTypesMustMatch,
    ConstructedListTooLarge,

    // simple type expectation mismatch
    TypeError(TypeSignature, TypeSignature),
    TypeValueError(TypeSignature, Value),

    NoSuperType(TypeSignature, TypeSignature),
    InvalidTypeDescription,
    UnknownTypeName(String),

    // union type mismatch
    UnionTypeError(Vec<TypeSignature>, TypeSignature),
    UnionTypeValueError(Vec<TypeSignature>, Value),

    ExpectedOptionalType(TypeSignature),
    ExpectedResponseType(TypeSignature),
    ExpectedOptionalValue(Value),
    ExpectedResponseValue(Value),
    CouldNotDetermineResponseOkType,
    CouldNotDetermineResponseErrType,

    // Checker runtime failures
    TypeAlreadyAnnotatedFailure,
    CheckerImplementationFailure,

    // Assets
    BadTokenName,
    DefineFTBadSignature,
    DefineNFTBadSignature,
    NoSuchNFT(String),
    NoSuchFT(String),

    BadTransferFTArguments,
    BadTransferNFTArguments,
    BadMintFTArguments,

    // tuples
    BadTupleFieldName,
    ExpectedTuple(TypeSignature),
    NoSuchTupleField(String, TupleTypeSignature),
    EmptyTuplesNotAllowed,
    BadTupleConstruction,
    TupleExpectsPairs,

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
    ContractAlreadyExists(String),
    ContractCallExpectName,

    // get-block-info errors
    NoSuchBlockInfoProperty(String),
    GetBlockInfoExpectPropertyName,

    NameAlreadyUsed(String),

    // expect a function, or applying a function to a list
    NonFunctionApplication,
    ExpectedListApplication,

    // let syntax
    BadLetSyntax,

    // generic binding syntax
    BadSyntaxBinding,
    BadSyntaxExpectedListOfPairs,

    MaxContextDepthReached,
    UndefinedFunction(String),
    UndefinedVariable(String),
    
    // argument counts
    RequiresAtLeastArguments(usize, usize),
    IncorrectArgumentCount(usize, usize),
    IfArmsMustMatch(TypeSignature, TypeSignature),
    DefaultTypesMustMatch(TypeSignature, TypeSignature),
    TooManyExpressions,
    IllegalOrUnknownFunctionApplication(String),
    UnknownFunction(String),

    WriteAttemptedInReadOnly,
    AtBlockClosureMustBeReadOnly
}

#[derive(Debug, PartialEq)]
pub struct CheckError {
    pub err: CheckErrors,
    pub expressions: Option<Vec<SymbolicExpression>>,
    pub diagnostic: Diagnostic,
}

impl CheckError {
    pub fn new(err: CheckErrors) -> CheckError {
        let diagnostic = Diagnostic::err(&err);
        CheckError {
            err,
            expressions: None,
            diagnostic
        }
    }

    pub fn has_expression(&self) -> bool {
        self.expressions.is_some()
    }

    pub fn set_expression(&mut self, expr: &SymbolicExpression) {
        self.diagnostic.spans = vec![expr.span.clone()];
        self.expressions.replace(vec![expr.clone()]);
    }

    pub fn set_expressions(&mut self, exprs: Vec<SymbolicExpression>) {
        self.diagnostic.spans = exprs.iter().map(|e| e.span.clone()).collect();
        self.expressions.replace(exprs.clone().to_vec());
    }
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.err {
            _ =>  write!(f, "{:?}", self.err)
        }?;

        if let Some(ref e) = self.expressions {
            write!(f, "\nNear:\n{:?}", e)?;
        }

        Ok(())
    }
}

impl error::Error for CheckError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self.err {
            _ => None
        }
    }
}

impl From<CheckErrors> for CheckError {
    fn from(err: CheckErrors) -> Self {
        CheckError::new(err)
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

fn formatted_expected_types(expected_types: & Vec<TypeSignature>) -> String {
    let mut expected_types_joined = String::new();
    expected_types_joined = format!("'{}'", expected_types[0]);

    if expected_types.len() > 2 {
        for expected_type in expected_types[1..expected_types.len()-1].into_iter() {
            expected_types_joined.push_str(&format!(", '{}'", expected_type));
        }
    }
    expected_types_joined.push_str(&format!(" or '{}'", expected_types[expected_types.len()-1]));
    expected_types_joined
}

impl DiagnosableError for CheckErrors {

    fn message(&self) -> String {
        match &self {
            CheckErrors::InvalidTypeDescription => "supplied type description is invalid".into(),
            CheckErrors::EmptyTuplesNotAllowed => "tuple types may not be empty".into(),
            CheckErrors::BadSyntaxExpectedListOfPairs => "bad syntax: function expects a list of pairs to bind names, e.g., ((name-0 a) (name-1 b) ...)".into(),
            CheckErrors::UnknownTypeName(name) => format!("failed to parse type: '{}'", name),
            CheckErrors::ValueTooLarge => format!("created a type which was great than maximum allowed value size"),
            CheckErrors::ExpectedName => format!("expected a name argument to this function"),
            CheckErrors::NoSuperType(a, b) => format!("unable to create a supertype for the two types: '{}' and '{}'", a, b),
            CheckErrors::UnknownListConstructionFailure => format!("invalid syntax for list definition"),
            CheckErrors::ListTypesMustMatch => format!("expecting elements of same type in a list"),
            CheckErrors::ConstructedListTooLarge => format!("reached limit of elements in a list"),
            CheckErrors::TypeError(expected_type, found_type) => format!("expecting expression of type '{}', found '{}'", expected_type, found_type),
            CheckErrors::TypeValueError(expected_type, found_value) => format!("expecting expression of type '{}', found '{}'", expected_type, found_value),
            CheckErrors::UnionTypeError(expected_types, found_type) => format!("expecting expression of type {}, found '{}'", formatted_expected_types(expected_types), found_type),
            CheckErrors::UnionTypeValueError(expected_types, found_type) => format!("expecting expression of type {}, found '{}'", formatted_expected_types(expected_types), found_type),
            CheckErrors::ExpectedOptionalType(found_type) => format!("expecting expression of type 'optional', found '{}'", found_type),
            CheckErrors::ExpectedResponseType(found_type) => format!("expecting expression of type 'response', found '{}'", found_type),
            CheckErrors::ExpectedOptionalValue(found_type) => format!("expecting expression of type 'optional', found '{}'", found_type),
            CheckErrors::ExpectedResponseValue(found_type) => format!("expecting expression of type 'response', found '{}'", found_type),
            CheckErrors::CouldNotDetermineResponseOkType => format!("attempted to obtain 'ok' value from response, but 'ok' type is indeterminate"),
            CheckErrors::CouldNotDetermineResponseErrType => format!("attempted to obtain 'err' value from response, but 'err' type is indeterminate"),
            CheckErrors::BadTupleFieldName => format!("invalid tuple field name"),
            CheckErrors::ExpectedTuple(type_signature) => format!("expecting tuple, found '{}'", type_signature),
            CheckErrors::NoSuchTupleField(field_name, tuple_signature) => format!("cannot find field '{}' in tuple '{}'", field_name, tuple_signature),
            CheckErrors::BadTupleConstruction => format!("invalid tuple syntax, expecting list of pair"),
            CheckErrors::TupleExpectsPairs => format!("invalid tuple syntax, expecting pair"),
            CheckErrors::NoSuchDataVariable(var_name) => format!("use of unresolved persisted variable '{}'", var_name),
            CheckErrors::BadTransferFTArguments => format!("transfer expects an int amount, from principal, to principal"),
            CheckErrors::BadTransferNFTArguments => format!("transfer expects an asset, from principal, to principal"),
            CheckErrors::BadMintFTArguments => format!("mint expects an int amount and from principal"),
            CheckErrors::BadMapName => format!("invalid map name"),
            CheckErrors::NoSuchMap(map_name) => format!("use of unresolved map '{}'", map_name),
            CheckErrors::DefineFunctionBadSignature => format!("invalid function definition"),
            CheckErrors::BadFunctionName => format!("invalid function name"),
            CheckErrors::BadMapTypeDefinition => format!("invalid map definition"), 
            CheckErrors::PublicFunctionMustReturnResponse(found_type) => format!("public functions must return an expression of type 'response', found '{}'", found_type),
            CheckErrors::DefineVariableBadSignature => format!("invalid variable definition"),
            CheckErrors::ReturnTypesMustMatch(type_1, type_2) => format!("detected two execution paths, returning two different expression types (got '{}' and '{}')", type_1, type_2),
            CheckErrors::NoSuchContract(contract_identifier) => format!("use of unresolved contract '{}'", contract_identifier),
            CheckErrors::NoSuchPublicFunction(contract_identifier, function_name) => format!("contract '{}' has no public function '{}'", contract_identifier, function_name),
            CheckErrors::ContractAlreadyExists(contract_identifier) => format!("contract name '{}' conflicts with existing contract", contract_identifier),
            CheckErrors::ContractCallExpectName => format!("missing contract name for call"),
            CheckErrors::NoSuchBlockInfoProperty(property_name) => format!("use of block unknown property '{}'", property_name),
            CheckErrors::GetBlockInfoExpectPropertyName => format!("missing property name for block info introspection"),
            CheckErrors::NameAlreadyUsed(name) => format!("defining '{}' conflicts with previous value", name),
            CheckErrors::NonFunctionApplication => format!("expecting expression of type function"),
            CheckErrors::ExpectedListApplication => format!("expecting expression of type list"),
            CheckErrors::BadLetSyntax => format!("invalid syntax of 'let'"),
            CheckErrors::CircularReference(function_names) => format!("detected interdependent functions ({})", function_names.join(", ")),
            CheckErrors::BadSyntaxBinding => format!("invalid syntax binding"),
            CheckErrors::MaxContextDepthReached => format!("reached depth limit"),
            CheckErrors::UndefinedVariable(var_name) => format!("use of unresolved variable '{}'", var_name),
            CheckErrors::UndefinedFunction(var_name) => format!("use of unresolved function '{}'", var_name),
            CheckErrors::RequiresAtLeastArguments(expected, found) => format!("expecting >= {} argument, got {}", expected, found),
            CheckErrors::IncorrectArgumentCount(expected_count, found_count) => format!("expecting {} arguments, got {}", expected_count, found_count),
            CheckErrors::IfArmsMustMatch(type_1, type_2) => format!("expression types returned by the arms of 'if' must match (got '{}' and '{}')", type_1, type_2),
            CheckErrors::DefaultTypesMustMatch(type_1, type_2) => format!("expression types passed in 'default-to' must match (got '{}' and '{}')", type_1, type_2),
            CheckErrors::TooManyExpressions => format!("reached limit of expressions"),
            CheckErrors::IllegalOrUnknownFunctionApplication(function_name) => format!("use of illegal / unresolved function '{}", function_name),
            CheckErrors::UnknownFunction(function_name) => format!("use of unresolved function '{}'", function_name),
            CheckErrors::WriteAttemptedInReadOnly => format!("expecting read-only statements, detected a writing operation"),
            CheckErrors::AtBlockClosureMustBeReadOnly => format!("(at-block ...) closures expect read-only statements, but detected a writing operation"),
            CheckErrors::BadTokenName => format!("expecting an token name as an argument"),
            CheckErrors::DefineFTBadSignature => format!("(define-token ...) expects a token name as an argument"),
            CheckErrors::DefineNFTBadSignature => format!("(define-asset ...) expects an asset name and an asset identifier type signature as arguments"),
            CheckErrors::NoSuchNFT(asset_name) => format!("tried to use asset function with a undefined asset ('{}')", asset_name),
            CheckErrors::NoSuchFT(asset_name) => format!("tried to use token function with a undefined token ('{}')", asset_name),
            CheckErrors::TypeAlreadyAnnotatedFailure | CheckErrors::CheckerImplementationFailure => {
                format!("internal error - please file an issue on github.com/blockstack/blockstack-core")
            },
        }
    }

    fn suggestion(&self) -> Option<String> {
        match &self {
            CheckErrors::BadSyntaxBinding => Some(format!("binding syntax example: ((supply int) (ttl int))")),
            CheckErrors::BadLetSyntax => Some(format!("'let' syntax example: (let ((supply 1000) (ttl 60)) <next-expression>)")),
            CheckErrors::NoSuchBlockInfoProperty(_) => Some(format!("properties available: time, header-hash, burnchain-header-hash, vrf-seed")),
            _ => None
        }
    }
}
