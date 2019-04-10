use vm::representations::SymbolicExpression;
use vm::types::TypeSignature;
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

    // Checker runtime failures
    TypeAlreadyAnnotatedFailure,
    CheckerImplementationFailure,
    TypeNotAnnotatedFailure,
    NotImplemented,

    // tuples
    BadTupleFieldName,
    ExpectedTuple(TypeSignature),
    NoSuchTupleField(String),
    BadTupleConstruction,
    TupleExpectsPairs,

    // data map
    BadMapName,
    NoSuchMap(String),

    // defines
    DefineFunctionBadSignature,
    BadFunctionName,
    BadMapTypeDefinition,
    PublicFunctionMustReturnBool,
    DefineVariableBadSignature,

    // contract-call erros
    NoSuchContract(String),
    NoSuchPublicFunction(String, String),
    ContractAlreadyExists(String),
    ContractCallExpectName,

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
    TooManyExpressions,
    IllegalOrUnknownFunctionApplication(String),
    UnknownFunction(String),
    Generic(String)
}

#[derive(Debug, PartialEq)]
pub struct CheckError {
    pub err: CheckErrors,
    pub expression: Option<SymbolicExpression>
}

impl CheckError {
    pub fn new(err: CheckErrors) -> CheckError {
        CheckError {
            err: err,
            expression: None
        }
    }

    pub fn has_expression(&self) -> bool {
        self.expression.is_some()
    }

    pub fn set_expression(&mut self, expr: &SymbolicExpression) {
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
