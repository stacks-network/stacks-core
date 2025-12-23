use clarity_types::errors::analysis::StaticCheckErrorKind;
use clarity_types::types::{StringSubtype, MAX_TO_ASCII_BUFFER_LEN};
use stacks_common::types::StacksEpochId;

use super::TypeChecker;
use crate::vm::analysis::read_only_checker::check_argument_count;
use crate::vm::analysis::type_checker::contexts::TypingContext;
use crate::vm::analysis::StaticCheckError;
use crate::vm::types::{BufferLength, SequenceSubtype, TypeSignature, TypeSignatureExt as _};
use crate::vm::SymbolicExpression;

/// `to-consensus-buff?` admits exactly one argument:
/// * the Clarity value to serialize
///
/// It returns an `(optional (buff x))`, where `x` is the maximum possible
/// consensus buffer length based on the inferred type of the supplied value.
pub fn check_special_to_consensus_buff(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> Result<TypeSignature, StaticCheckError> {
    check_argument_count(1, args)?;
    let input_type = checker.type_check(&args[0], context)?;
    let buffer_max_len = BufferLength::try_from(input_type.max_serialized_size()?)?;
    Ok(TypeSignature::new_option(TypeSignature::SequenceType(
        SequenceSubtype::BufferType(buffer_max_len),
    ))?)
}

/// `from-consensus-buff?` admits exactly two arguments:
/// * a type signature indicating the expected return type `t1`
/// * a buffer (of up to max length)
///
/// It returns an `(optional t1)`
pub fn check_special_from_consensus_buff(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> Result<TypeSignature, StaticCheckError> {
    check_argument_count(2, args)?;
    let result_type = TypeSignature::parse_type_repr(StacksEpochId::Epoch21, &args[0], checker)?;
    checker.type_check_expects(&args[1], context, &TypeSignature::BUFFER_MAX)?;
    Ok(TypeSignature::new_option(result_type)?)
}

/// `to-ascii?` admits exactly one argument, a value to convert to a
/// `string-ascii`. It can be any of the following types:
/// - `int`
/// - `uint`
/// - `bool`
/// - `principal`
/// - `(buff 524284)`
/// - `(string-utf8 262144)`
///
/// It returns a `(response (string-ascii 1048571) uint)`.
pub fn check_special_to_ascii(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> Result<TypeSignature, StaticCheckError> {
    check_argument_count(1, args)?;
    let input_type = checker.type_check(
        args.first()
            .ok_or(StaticCheckErrorKind::CheckerImplementationFailure)?,
        context,
    )?;

    let result_type = match input_type {
        TypeSignature::IntType => TypeSignature::TO_ASCII_INT_RESULT_MAX,
        TypeSignature::UIntType => TypeSignature::TO_ASCII_UINT_RESULT_MAX,
        TypeSignature::BoolType => TypeSignature::TO_ASCII_BOOL_RESULT_MAX,
        TypeSignature::PrincipalType | TypeSignature::CallableType(_) => {
            TypeSignature::TO_ASCII_PRINCIPAL_RESULT_MAX
        }
        TypeSignature::SequenceType(SequenceSubtype::BufferType(len))
            if u32::from(len.clone()) <= MAX_TO_ASCII_BUFFER_LEN =>
        {
            // Each byte in the buffer becomes two ASCII characters, plus "0x" prefix
            TypeSignature::new_ascii_type((u32::from(len) * 2 + 2).into())?
        }
        TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(len))) => {
            // Each UTF-8 character is exactly one ASCII character
            TypeSignature::new_ascii_type(u32::from(len).into())?
        }
        _ => {
            let types = vec![
                TypeSignature::IntType,
                TypeSignature::UIntType,
                TypeSignature::BoolType,
                TypeSignature::PrincipalType,
                TypeSignature::TO_ASCII_BUFFER_MAX,
                TypeSignature::STRING_UTF8_MAX,
            ];
            return Err(StaticCheckErrorKind::UnionTypeError(types, input_type.into()).into());
        }
    };
    Ok(
        TypeSignature::new_response(result_type, TypeSignature::UIntType).map_err(|_| {
            StaticCheckErrorKind::ExpectsRejectable(
                "FATAL: Legal Clarity response type marked invalid".into(),
            )
        })?,
    )
}
