use vm::representations::SymbolicExpression;
use vm::checker::diagnostic::{Diagnostic, DiagnosableError};
use vm::types::{TypeSignature, TupleTypeSignature};
use std::error;
use std::fmt;

pub type CheckResult <T> = Result<T, CheckError>;

#[derive(Debug, PartialEq)]
pub enum CheckErrors {
    // list typing errors
    UnknownListConstructionFailure,
    ListTypesMustMatch,
    ConstructedListTooLarge,

    // simple type expectation mismatch
    TypeError(TypeSignature, TypeSignature),
    // union type mismatch
    UnionTypeError(Vec<TypeSignature>, TypeSignature),
    ExpectedOptionalType,
    ExpectedResponseType,
    CouldNotDetermineResponseOkType,
    CouldNotDetermineResponseErrType,

    // Checker runtime failures
    TypeAlreadyAnnotatedFailure,
    CheckerImplementationFailure,
    TypeNotAnnotatedFailure,

    // tuples
    BadTupleFieldName,
    ExpectedTuple(TypeSignature),
    NoSuchTupleField(String),
    BadTupleConstruction,
    TupleExpectsPairs,

    // variables
    NoSuchVariable(String),

    // data map
    BadMapName,
    NoSuchMap(String),

    // defines
    DefineFunctionBadSignature,
    BadFunctionName,
    BadMapTypeDefinition,
    PublicFunctionMustReturnBool,
    DefineVariableBadSignature,
    ReturnTypesMustMatch,

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
    BadSyntaxBinding,
    MaxContextDepthReached,
    UnboundVariable(String),
    VariadicNeedsOneArgument,
    IncorrectArgumentCount(usize, usize),
    IfArmsMustMatch(TypeSignature, TypeSignature),
    DefaultTypesMustMatch(TypeSignature, TypeSignature),
    TooManyExpressions,
    IllegalOrUnknownFunctionApplication(String),
    UnknownFunction(String),

    NotImplemented,
    WriteAttemptedInReadOnly,
}

#[derive(Debug, PartialEq)]
pub struct CheckError {
    pub err: CheckErrors,
    pub expression: Option<SymbolicExpression>,
    pub diagnostic: Diagnostic,
}

impl CheckError {
    pub fn new(err: CheckErrors) -> CheckError {
        let diagnostic = Diagnostic::err(&err, None);
        CheckError {
            err: err,
            expression: None,
            diagnostic: diagnostic
        }
    }

    pub fn has_expression(&self) -> bool {
        self.expression.is_some()
    }

    pub fn set_expression(&mut self, expr: &SymbolicExpression) {
        self.diagnostic.span = Some(expr.span.clone());
        self.expression.replace(expr.clone());
    }
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.err {
            _ =>  write!(f, "{:?}", self.err)
        }?;

        if let Some(ref e) = self.expression {
            write!(f, "\nNear:\n{}", e)?;
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

impl DiagnosableError for CheckErrors {

    fn message(&self) -> String {
        let message = match &self {
            CheckErrors::UnknownListConstructionFailure => format!("invalid syntax for list definition"),
            CheckErrors::ListTypesMustMatch => format!("expecting elements of same type in a list"),
            CheckErrors::ConstructedListTooLarge => format!("reached limit of elements in a list"),
            CheckErrors::TypeError(type1, type2) => format!("{:?}", self),
            CheckErrors::UnionTypeError(type_signatures, type_signature) => format!("{:?}", self),
            CheckErrors::ExpectedOptionalType => format!("cannot convert return expression of type '' to return type 'optional'"), // todo(@ludo) add current type
            CheckErrors::ExpectedResponseType => format!("cannot convert return expression of type '' to return type 'response'"), // todo(@ludo) add current type
            CheckErrors::CouldNotDetermineResponseOkType => format!("expecting a response of type 'ok'"),
            CheckErrors::CouldNotDetermineResponseErrType => format!("expecting a response of type 'err'"),
            CheckErrors::TypeAlreadyAnnotatedFailure => format!("{:?}", self),
            CheckErrors::CheckerImplementationFailure => format!("{:?}", self),
            CheckErrors::TypeNotAnnotatedFailure => format!("{:?}", self),
            CheckErrors::BadTupleFieldName => format!("cannot get tuple field '' from tuple ''"), // todo(@ludo) add field name + tuple struct
            CheckErrors::ExpectedTuple(type_signature) => format!("expecting tuple, got {}", type_signature),
            CheckErrors::NoSuchTupleField(field_name) => format!("cannot fint field '{}' from tuple", field_name),
            CheckErrors::BadTupleConstruction => format!("invalid tuple syntax, expecting list of pair"),
            CheckErrors::TupleExpectsPairs => format!("invalid tuple syntax, expecting pair"),
            CheckErrors::NoSuchVariable(var_name) => format!("variable '{}' unknown", var_name),
            CheckErrors::BadMapName => format!("invalid map name"), // todo(@ludo) add map_name
            CheckErrors::NoSuchMap(map_name) => format!("use of unresolved map '{}'", map_name),
            CheckErrors::DefineFunctionBadSignature => format!("invalid function definition"), // add function name?
            CheckErrors::BadFunctionName => format!("invalid function name"), // todo(@ludo) add function name?
            CheckErrors::BadMapTypeDefinition => format!("invalid map definition"), 
            CheckErrors::PublicFunctionMustReturnBool => format!("cannot convert return expression of type '' to return type 'bool'"), // todo(@ludo) is that still true? + add current type
            CheckErrors::DefineVariableBadSignature => format!("invalid variable definition"),
            CheckErrors::ReturnTypesMustMatch => format!("cannot convert return expression of type '' to return type ''"), // todo(@ludo) add current + expected
            CheckErrors::NoSuchContract(contract_name) => format!("use of unresolved contract '{}'", contract_name),
            CheckErrors::NoSuchPublicFunction(contract_name, function_name) => format!("contract '{}' has no public function '{}'", contract_name, function_name),
            CheckErrors::ContractAlreadyExists(contract_name) => format!("contract name '{}' conflicts with existing contract", contract_name),
            CheckErrors::ContractCallExpectName => format!("missing contract name for call"),
            CheckErrors::NoSuchBlockInfoProperty(property_name) => format!("use of block unknown property '{}'", property_name),
            CheckErrors::GetBlockInfoExpectPropertyName => format!("missing property name for block info introspection"),
            CheckErrors::NameAlreadyUsed(name) => format!("defining '{}' conflicts with previous value", name),
            CheckErrors::NonFunctionApplication => format!("{:?}", self),
            CheckErrors::ExpectedListApplication => format!("{:?}", self), // todo(@ludo) add current
            CheckErrors::BadLetSyntax => format!("invalid syntax of 'let'"), // todo(@ludo) suggestion: show an exemple
            CheckErrors::BadSyntaxBinding => format!("invalid syntax binding"), // todo(@ludo) suggestion: show an exemple
            CheckErrors::MaxContextDepthReached => format!("reached depth limit"),
            CheckErrors::UnboundVariable(var_name) => format!("use of unresolved variable"),
            CheckErrors::VariadicNeedsOneArgument => format!("expecting at least 1 argument"),
            CheckErrors::IncorrectArgumentCount(current_count, expected_count) => format!("expecting {} arguments, got {}", expected_count, current_count),
            CheckErrors::IfArmsMustMatch(type_signature_branch_1, type_signature_branch_2) => format!("{:?}", self),
            CheckErrors::DefaultTypesMustMatch(type_signature_branch_1, type_signature_branch_2) => format!("{:?}", self),
            CheckErrors::TooManyExpressions => format!("reached limit of expressions"),
            CheckErrors::IllegalOrUnknownFunctionApplication(function_name) => format!("use of illegal / unresolved function '{}", function_name),
            CheckErrors::UnknownFunction(function_name) => format!("use of unresolved function '{}'", function_name),
            CheckErrors::NotImplemented => format!("use of unimplemented feature"),
            CheckErrors::WriteAttemptedInReadOnly => format!("{:?}", self),
        };

        message
    }

    fn context(&self) -> Option<String> {
        None
    }

    fn suggestion(&self) -> Option<String> {
        None
    }
}