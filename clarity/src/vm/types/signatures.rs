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

use std::collections::BTreeMap;
use std::fmt;

pub use clarity_types::types::signatures::{
    AssetIdentifier, BufferLength, CallableSubtype, ListTypeData, SequenceSubtype, StringSubtype,
    StringUTF8Length, TupleTypeSignature, TypeSignature,
};
pub use clarity_types::types::Value;
use stacks_common::types::StacksEpochId;

use self::TypeSignature::SequenceType;
use crate::vm::costs::{runtime_cost, CostOverflowingMath};
use crate::vm::errors::{CheckErrorKind, SyntaxBindingError, SyntaxBindingErrorType};
use crate::vm::representations::{
    ClarityName, SymbolicExpression, SymbolicExpressionType, TraitDefinition,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionSignature {
    pub args: Vec<TypeSignature>,
    pub returns: TypeSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixedFunction {
    pub args: Vec<FunctionArg>,
    pub returns: TypeSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FunctionArgSignature {
    Union(Vec<TypeSignature>),
    Single(TypeSignature),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FunctionReturnsSignature {
    TypeOfArgAtPosition(usize),
    Fixed(TypeSignature),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FunctionType {
    Variadic(TypeSignature, TypeSignature),
    Fixed(FixedFunction),
    // Functions where the single input is a union type, e.g., Buffer or Int
    UnionArgs(Vec<TypeSignature>, TypeSignature),
    ArithmeticVariadic,
    ArithmeticUnary,
    ArithmeticBinary,
    ArithmeticComparison,
    Binary(
        FunctionArgSignature,
        FunctionArgSignature,
        FunctionReturnsSignature,
    ),
}

impl FunctionArgSignature {
    pub fn canonicalize(&self, epoch: &StacksEpochId) -> FunctionArgSignature {
        match self {
            FunctionArgSignature::Union(arg_types) => {
                let arg_types = arg_types
                    .iter()
                    .map(|arg_type| arg_type.canonicalize(epoch))
                    .collect();
                FunctionArgSignature::Union(arg_types)
            }
            FunctionArgSignature::Single(arg_type) => {
                let arg_type = arg_type.canonicalize(epoch);
                FunctionArgSignature::Single(arg_type)
            }
        }
    }
}

impl FunctionReturnsSignature {
    pub fn canonicalize(&self, epoch: &StacksEpochId) -> FunctionReturnsSignature {
        match self {
            FunctionReturnsSignature::TypeOfArgAtPosition(_) => self.clone(),
            FunctionReturnsSignature::Fixed(return_type) => {
                let return_type = return_type.canonicalize(epoch);
                FunctionReturnsSignature::Fixed(return_type)
            }
        }
    }
}

impl FunctionType {
    pub fn canonicalize(&self, epoch: &StacksEpochId) -> FunctionType {
        match self {
            FunctionType::Variadic(arg_type, return_type) => {
                let arg_type = arg_type.canonicalize(epoch);
                let return_type = return_type.canonicalize(epoch);
                FunctionType::Variadic(arg_type, return_type)
            }
            FunctionType::Fixed(fixed_function) => {
                let args = fixed_function
                    .args
                    .iter()
                    .map(|arg| FunctionArg {
                        signature: arg.signature.canonicalize(epoch),
                        name: arg.name.clone(),
                    })
                    .collect();
                let returns = fixed_function.returns.canonicalize(epoch);
                FunctionType::Fixed(FixedFunction { args, returns })
            }
            FunctionType::UnionArgs(arg_types, return_type) => {
                let arg_types = arg_types
                    .iter()
                    .map(|arg_type: &TypeSignature| arg_type.canonicalize(epoch))
                    .collect();
                let return_type = return_type.canonicalize(epoch);
                FunctionType::UnionArgs(arg_types, return_type)
            }
            FunctionType::ArithmeticVariadic => FunctionType::ArithmeticVariadic,
            FunctionType::ArithmeticUnary => FunctionType::ArithmeticUnary,
            FunctionType::ArithmeticBinary => FunctionType::ArithmeticBinary,
            FunctionType::ArithmeticComparison => FunctionType::ArithmeticComparison,
            FunctionType::Binary(arg1, arg2, return_type) => {
                let arg1 = arg1.canonicalize(epoch);
                let arg2 = arg2.canonicalize(epoch);
                let return_type = return_type.canonicalize(epoch);
                FunctionType::Binary(arg1, arg2, return_type)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionArg {
    pub signature: TypeSignature,
    pub name: ClarityName,
}

impl From<FixedFunction> for FunctionSignature {
    fn from(data: FixedFunction) -> FunctionSignature {
        let FixedFunction { args, returns } = data;
        let args = args.into_iter().map(|x| x.signature).collect();
        FunctionSignature { args, returns }
    }
}

/// This trait is used to parse type signatures from Clarity expressions.
/// This is not included in clarity-types because it requires the
/// [`CostTracker`] trait.
pub trait TypeSignatureExt {
    fn parse_atom_type(typename: &str) -> Result<TypeSignature, CheckErrorKind>;
    fn parse_list_type_repr<A: CostTracker>(
        epoch: StacksEpochId,
        type_args: &[SymbolicExpression],
        accounting: &mut A,
    ) -> Result<TypeSignature, CheckErrorKind>;
    fn parse_tuple_type_repr<A: CostTracker>(
        epoch: StacksEpochId,
        type_args: &[SymbolicExpression],
        accounting: &mut A,
    ) -> Result<TypeSignature, CheckErrorKind>;
    fn parse_buff_type_repr(
        type_args: &[SymbolicExpression],
    ) -> Result<TypeSignature, CheckErrorKind>;
    fn parse_string_utf8_type_repr(
        type_args: &[SymbolicExpression],
    ) -> Result<TypeSignature, CheckErrorKind>;
    fn parse_string_ascii_type_repr(
        type_args: &[SymbolicExpression],
    ) -> Result<TypeSignature, CheckErrorKind>;
    fn parse_optional_type_repr<A: CostTracker>(
        epoch: StacksEpochId,
        type_args: &[SymbolicExpression],
        accounting: &mut A,
    ) -> Result<TypeSignature, CheckErrorKind>;
    fn parse_response_type_repr<A: CostTracker>(
        epoch: StacksEpochId,
        type_args: &[SymbolicExpression],
        accounting: &mut A,
    ) -> Result<TypeSignature, CheckErrorKind>;
    fn parse_type_repr<A: CostTracker>(
        epoch: StacksEpochId,
        x: &SymbolicExpression,
        accounting: &mut A,
    ) -> Result<TypeSignature, CheckErrorKind>;
    fn parse_trait_type_repr<A: CostTracker>(
        type_args: &[SymbolicExpression],
        accounting: &mut A,
        epoch: StacksEpochId,
        clarity_version: ClarityVersion,
    ) -> Result<BTreeMap<ClarityName, FunctionSignature>, CheckErrorKind>;
    #[cfg(test)]
    fn from_string(val: &str, version: ClarityVersion, epoch: StacksEpochId) -> Self;
}

impl TypeSignatureExt for TypeSignature {
    fn parse_atom_type(typename: &str) -> Result<TypeSignature, CheckErrorKind> {
        match typename {
            "int" => Ok(TypeSignature::IntType),
            "uint" => Ok(TypeSignature::UIntType),
            "bool" => Ok(TypeSignature::BoolType),
            "principal" => Ok(TypeSignature::PrincipalType),
            _ => Err(CheckErrorKind::UnknownTypeName(typename.into())),
        }
    }

    // Parses list type signatures ->
    // (list maximum-length atomic-type)
    fn parse_list_type_repr<A: CostTracker>(
        epoch: StacksEpochId,
        type_args: &[SymbolicExpression],
        accounting: &mut A,
    ) -> Result<TypeSignature, CheckErrorKind> {
        if type_args.len() != 2 {
            return Err(CheckErrorKind::InvalidTypeDescription);
        }

        if let SymbolicExpressionType::LiteralValue(Value::Int(max_len)) = &type_args[0].expr {
            let atomic_type_arg = &type_args[type_args.len() - 1];
            let entry_type = TypeSignature::parse_type_repr(epoch, atomic_type_arg, accounting)?;
            let max_len = u32::try_from(*max_len).map_err(|_| CheckErrorKind::ValueTooLarge)?;
            ListTypeData::new_list(entry_type, max_len).map(|x| x.into())
        } else {
            Err(CheckErrorKind::InvalidTypeDescription)
        }
    }

    // Parses type signatures of the following form:
    // (tuple (key-name-0 value-type-0) (key-name-1 value-type-1))
    fn parse_tuple_type_repr<A: CostTracker>(
        epoch: StacksEpochId,
        type_args: &[SymbolicExpression],
        accounting: &mut A,
    ) -> Result<TypeSignature, CheckErrorKind> {
        let mapped_key_types = parse_name_type_pairs::<_, CheckErrorKind>(
            epoch,
            type_args,
            SyntaxBindingErrorType::TupleCons,
            accounting,
        )?;
        let tuple_type_signature = TupleTypeSignature::try_from(mapped_key_types)?;
        Ok(TypeSignature::from(tuple_type_signature))
    }

    // Parses type signatures of the form:
    // (buff 10)
    fn parse_buff_type_repr(
        type_args: &[SymbolicExpression],
    ) -> Result<TypeSignature, CheckErrorKind> {
        if type_args.len() != 1 {
            return Err(CheckErrorKind::InvalidTypeDescription);
        }
        if let SymbolicExpressionType::LiteralValue(Value::Int(buff_len)) = &type_args[0].expr {
            BufferLength::try_from(*buff_len)
                .map(|buff_len| SequenceType(SequenceSubtype::BufferType(buff_len)))
        } else {
            Err(CheckErrorKind::InvalidTypeDescription)
        }
    }

    // Parses type signatures of the form:
    // (string-utf8 10)
    fn parse_string_utf8_type_repr(
        type_args: &[SymbolicExpression],
    ) -> Result<TypeSignature, CheckErrorKind> {
        if type_args.len() != 1 {
            return Err(CheckErrorKind::InvalidTypeDescription);
        }
        if let SymbolicExpressionType::LiteralValue(Value::Int(utf8_len)) = &type_args[0].expr {
            StringUTF8Length::try_from(*utf8_len).map(|utf8_len| {
                SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(utf8_len)))
            })
        } else {
            Err(CheckErrorKind::InvalidTypeDescription)
        }
    }

    // Parses type signatures of the form:
    // (string-ascii 10)
    fn parse_string_ascii_type_repr(
        type_args: &[SymbolicExpression],
    ) -> Result<TypeSignature, CheckErrorKind> {
        if type_args.len() != 1 {
            return Err(CheckErrorKind::InvalidTypeDescription);
        }
        if let SymbolicExpressionType::LiteralValue(Value::Int(buff_len)) = &type_args[0].expr {
            BufferLength::try_from(*buff_len).map(|buff_len| {
                SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(buff_len)))
            })
        } else {
            Err(CheckErrorKind::InvalidTypeDescription)
        }
    }

    fn parse_optional_type_repr<A: CostTracker>(
        epoch: StacksEpochId,
        type_args: &[SymbolicExpression],
        accounting: &mut A,
    ) -> Result<TypeSignature, CheckErrorKind> {
        if type_args.len() != 1 {
            return Err(CheckErrorKind::InvalidTypeDescription);
        }
        let inner_type = TypeSignature::parse_type_repr(epoch, &type_args[0], accounting)?;

        TypeSignature::new_option(inner_type)
    }

    fn parse_response_type_repr<A: CostTracker>(
        epoch: StacksEpochId,
        type_args: &[SymbolicExpression],
        accounting: &mut A,
    ) -> Result<TypeSignature, CheckErrorKind> {
        if type_args.len() != 2 {
            return Err(CheckErrorKind::InvalidTypeDescription);
        }
        let ok_type = TypeSignature::parse_type_repr(epoch, &type_args[0], accounting)?;
        let err_type = TypeSignature::parse_type_repr(epoch, &type_args[1], accounting)?;
        TypeSignature::new_response(ok_type, err_type)
    }

    fn parse_type_repr<A: CostTracker>(
        epoch: StacksEpochId,
        x: &SymbolicExpression,
        accounting: &mut A,
    ) -> Result<TypeSignature, CheckErrorKind> {
        runtime_cost(ClarityCostFunction::TypeParseStep, accounting, 0)?;

        match x.expr {
            SymbolicExpressionType::Atom(ref atom_type_str) => {
                let atomic_type = TypeSignature::parse_atom_type(atom_type_str)?;
                Ok(atomic_type)
            }
            SymbolicExpressionType::List(ref list_contents) => {
                let (compound_type, rest) = list_contents
                    .split_first()
                    .ok_or(CheckErrorKind::InvalidTypeDescription)?;
                if let SymbolicExpressionType::Atom(ref compound_type) = compound_type.expr {
                    match compound_type.as_ref() {
                        "list" => TypeSignature::parse_list_type_repr(epoch, rest, accounting),
                        "buff" => TypeSignature::parse_buff_type_repr(rest),
                        "string-utf8" => TypeSignature::parse_string_utf8_type_repr(rest),
                        "string-ascii" => TypeSignature::parse_string_ascii_type_repr(rest),
                        "tuple" => TypeSignature::parse_tuple_type_repr(epoch, rest, accounting),
                        "optional" => {
                            TypeSignature::parse_optional_type_repr(epoch, rest, accounting)
                        }
                        "response" => {
                            TypeSignature::parse_response_type_repr(epoch, rest, accounting)
                        }
                        _ => Err(CheckErrorKind::InvalidTypeDescription),
                    }
                } else {
                    Err(CheckErrorKind::InvalidTypeDescription)
                }
            }
            SymbolicExpressionType::TraitReference(_, ref trait_definition)
                if epoch < StacksEpochId::Epoch21 =>
            {
                match trait_definition {
                    TraitDefinition::Defined(trait_id) => {
                        Ok(TypeSignature::TraitReferenceType(trait_id.clone()))
                    }
                    TraitDefinition::Imported(trait_id) => {
                        Ok(TypeSignature::TraitReferenceType(trait_id.clone()))
                    }
                }
            }
            SymbolicExpressionType::TraitReference(_, ref trait_definition) => {
                match trait_definition {
                    TraitDefinition::Defined(trait_id) => Ok(TypeSignature::CallableType(
                        CallableSubtype::Trait(trait_id.clone()),
                    )),
                    TraitDefinition::Imported(trait_id) => Ok(TypeSignature::CallableType(
                        CallableSubtype::Trait(trait_id.clone()),
                    )),
                }
            }
            _ => Err(CheckErrorKind::InvalidTypeDescription),
        }
    }

    fn parse_trait_type_repr<A: CostTracker>(
        type_args: &[SymbolicExpression],
        accounting: &mut A,
        epoch: StacksEpochId,
        clarity_version: ClarityVersion,
    ) -> Result<BTreeMap<ClarityName, FunctionSignature>, CheckErrorKind> {
        let mut trait_signature: BTreeMap<ClarityName, FunctionSignature> = BTreeMap::new();
        let functions_types = type_args
            .first()
            .ok_or_else(|| CheckErrorKind::InvalidTypeDescription)?
            .match_list()
            .ok_or(CheckErrorKind::DefineTraitBadSignature)?;

        for function_type in functions_types.iter() {
            let args = function_type
                .match_list()
                .ok_or(CheckErrorKind::DefineTraitBadSignature)?;
            if args.len() != 3 {
                return Err(CheckErrorKind::InvalidTypeDescription);
            }

            // Extract function's name
            let fn_name = args[0]
                .match_atom()
                .ok_or(CheckErrorKind::DefineTraitBadSignature)?;

            // Extract function's arguments
            let fn_args_exprs = args[1]
                .match_list()
                .ok_or(CheckErrorKind::DefineTraitBadSignature)?;
            let fn_args = fn_args_exprs
                .iter()
                .map(|arg_type| TypeSignature::parse_type_repr(epoch, arg_type, accounting))
                .collect::<Result<_, CheckErrorKind>>()?;

            // Extract function's type return - must be a response
            let fn_return = match TypeSignature::parse_type_repr(epoch, &args[2], accounting) {
                Ok(response) => match response {
                    TypeSignature::ResponseType(_) => Ok(response),
                    _ => Err(CheckErrorKind::DefineTraitBadSignature),
                },
                _ => Err(CheckErrorKind::DefineTraitBadSignature),
            }?;

            if trait_signature
                .insert(
                    fn_name.clone(),
                    FunctionSignature {
                        args: fn_args,
                        returns: fn_return,
                    },
                )
                .is_some()
                && clarity_version >= ClarityVersion::Clarity2
            {
                return Err(CheckErrorKind::DefineTraitDuplicateMethod(
                    fn_name.to_string(),
                ));
            }
        }
        Ok(trait_signature)
    }

    #[cfg(test)]
    fn from_string(val: &str, version: ClarityVersion, epoch: StacksEpochId) -> Self {
        use clarity_types::types::QualifiedContractIdentifier;

        use crate::vm::ast::parse;
        let expr = &parse(
            &QualifiedContractIdentifier::transient(),
            val,
            version,
            epoch,
        )
        .unwrap()[0];
        TypeSignature::parse_type_repr(epoch, expr, &mut ()).unwrap()
    }
}

impl FixedFunction {
    pub fn total_type_size(&self) -> Result<u64, CheckErrorKind> {
        let mut function_type_size = u64::from(self.returns.type_size()?);
        for arg in self.args.iter() {
            function_type_size =
                function_type_size.cost_overflow_add(u64::from(arg.signature.type_size()?))?;
        }
        Ok(function_type_size)
    }
}

impl FunctionSignature {
    pub fn total_type_size(&self) -> Result<u64, CheckErrorKind> {
        let mut function_type_size = u64::from(self.returns.type_size()?);
        for arg in self.args.iter() {
            function_type_size =
                function_type_size.cost_overflow_add(u64::from(arg.type_size()?))?;
        }
        Ok(function_type_size)
    }

    pub fn check_args_trait_compliance(
        &self,
        epoch: &StacksEpochId,
        args: Vec<TypeSignature>,
    ) -> Result<bool, CheckErrorKind> {
        if args.len() != self.args.len() {
            return Ok(false);
        }
        let args_iter = self.args.iter().zip(args.iter());
        for (expected_arg, arg) in args_iter {
            if !arg.admits_type(epoch, expected_arg)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl FunctionSignature {
    pub fn canonicalize(&self, epoch: &StacksEpochId) -> FunctionSignature {
        let canonicalized_args = self
            .args
            .iter()
            .map(|arg| arg.canonicalize(epoch))
            .collect();

        FunctionSignature {
            args: canonicalized_args,
            returns: self.returns.canonicalize(epoch),
        }
    }
}

impl FunctionArg {
    pub fn new(signature: TypeSignature, name: ClarityName) -> FunctionArg {
        FunctionArg { signature, name }
    }
}

use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::costs::CostTracker;
use crate::vm::ClarityVersion;

/// Try to parse a list of (name_i, type_i) pairs into Vec<(ClarityName, TypeSignature)>.
/// On failure, return both the type-check error as well as the index of the symbolic expression which caused
/// the problem (for purposes of reporting the error).
pub fn parse_name_type_pairs<A: CostTracker, E>(
    epoch: StacksEpochId,
    name_type_pairs: &[SymbolicExpression],
    binding_error_type: SyntaxBindingErrorType,
    accounting: &mut A,
) -> Result<Vec<(ClarityName, TypeSignature)>, E>
where
    E: for<'a> From<(CheckErrorKind, &'a SymbolicExpression)>,
{
    // this is a pretty deep nesting here, but what we're trying to do is pick out the values of
    // the form:
    // ((name1 type1) (name2 type2) (name3 type3) ...)
    // which is a list of 2-length lists of atoms.
    use crate::vm::representations::SymbolicExpressionType::List;

    // step 1: parse it into a vec of symbolicexpression pairs.
    let as_pairs: Result<Vec<_>, (CheckErrorKind, &SymbolicExpression)> = name_type_pairs
        .iter()
        .enumerate()
        .map(|(i, key_type_pair)| {
            if let List(ref as_vec) = key_type_pair.expr {
                if as_vec.len() != 2 {
                    Err((
                        CheckErrorKind::BadSyntaxBinding(SyntaxBindingError::InvalidLength(
                            binding_error_type,
                            i,
                        )),
                        key_type_pair,
                    ))
                } else {
                    Ok((&as_vec[0], &as_vec[1]))
                }
            } else {
                Err((
                    SyntaxBindingError::NotList(binding_error_type, i).into(),
                    key_type_pair,
                ))
            }
        })
        .collect();

    // step 2: turn into a vec of (name, typesignature) pairs.
    let key_types: Result<Vec<_>, (CheckErrorKind, &SymbolicExpression)> = (as_pairs?)
        .iter()
        .enumerate()
        .map(|(i, (name_symbol, type_symbol))| {
            let name = name_symbol
                .match_atom()
                .ok_or_else(|| {
                    (
                        CheckErrorKind::BadSyntaxBinding(SyntaxBindingError::NotAtom(
                            binding_error_type,
                            i,
                        )),
                        *name_symbol,
                    )
                })?
                .clone();
            let type_info = TypeSignature::parse_type_repr(epoch, type_symbol, accounting)
                .map_err(|e| (e, *type_symbol))?;
            Ok((name, type_info))
        })
        .collect();

    Ok(key_types?)
}

impl fmt::Display for FunctionArg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.signature)
    }
}

#[cfg(test)]
mod test {
    #[cfg(test)]
    use rstest::rstest;
    #[cfg(test)]
    use rstest_reuse::{self, *};
    use stacks_common::types::StacksEpochId;

    use super::CheckErrorKind::*;
    use super::*;
    use crate::vm::tests::test_clarity_versions;
    use crate::vm::types::QualifiedContractIdentifier;
    use crate::vm::{execute, ClarityVersion};

    fn fail_parse(val: &str, version: ClarityVersion, epoch: StacksEpochId) -> CheckErrorKind {
        use crate::vm::ast::parse;
        let expr = &parse(
            &QualifiedContractIdentifier::transient(),
            val,
            version,
            epoch,
        )
        .unwrap()[0];
        TypeSignature::parse_type_repr(epoch, expr, &mut ()).unwrap_err()
    }

    #[apply(test_clarity_versions)]
    fn type_of_list_of_buffs(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
        let value = execute("(list \"abc\" \"abcde\")").unwrap().unwrap();
        let type_descr = TypeSignature::from_string("(list 2 (string-ascii 5))", version, epoch);
        assert_eq!(TypeSignature::type_of(&value).unwrap(), type_descr);
    }

    #[apply(test_clarity_versions)]
    fn type_signature_way_too_big(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
        // first_tuple.type_size ~= 131
        // second_tuple.type_size = k * (130+130)
        // to get a type-size greater than max_value all by itself,
        //   set k = 4033
        let first_tuple = TypeSignature::from_string("(tuple (a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 bool))", version, epoch);

        let len = 4033;
        let mut keys = Vec::with_capacity(len);
        for i in 0..len {
            let key_name = ClarityName::try_from(format!("a{i:0127}")).unwrap();
            let key_val = first_tuple.clone();
            keys.push((key_name, key_val));
        }

        assert_eq!(
            TupleTypeSignature::try_from(keys).unwrap_err(),
            ValueTooLarge
        );
    }

    #[apply(test_clarity_versions)]
    fn test_construction(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
        let bad_type_descriptions = [
            ("(tuple)", EmptyTuplesNotAllowed),
            ("(list int int)", InvalidTypeDescription),
            ("(list 4294967296 int)", ValueTooLarge),
            ("(list 50 bazel)", UnknownTypeName("bazel".into())),
            ("(buff)", InvalidTypeDescription),
            ("(buff 4294967296)", ValueTooLarge),
            ("(buff int)", InvalidTypeDescription),
            ("(response int)", InvalidTypeDescription),
            ("(optional bazel)", UnknownTypeName("bazel".into())),
            ("(response bazel int)", UnknownTypeName("bazel".into())),
            ("(response int bazel)", UnknownTypeName("bazel".into())),
            ("bazel", UnknownTypeName("bazel".into())),
            ("()", InvalidTypeDescription),
            ("(1234)", InvalidTypeDescription),
            ("(int 3 int)", InvalidTypeDescription),
            ("1234", InvalidTypeDescription),
            ("(list 1 (buff 1048576))", ValueTooLarge),
            ("(list 4294967295 (buff 2))", ValueTooLarge),
            ("(list 2147483647 (buff 2))", ValueTooLarge),
            ("(tuple (l (buff 1048576)))", ValueTooLarge),
        ];

        for (desc, expected) in bad_type_descriptions.iter() {
            assert_eq!(&fail_parse(desc, version, epoch), expected);
        }

        let okay_types = [
            "(list 16 uint)",
            "(list 15 (response int bool))",
            "(list 15 (response bool int))",
            "(buff 1048576)",
            "(list 4400 bool)",
            "(tuple (l (buff 1048550)))",
        ];

        for desc in okay_types.iter() {
            let _ = TypeSignature::from_string(desc, version, epoch); // panics on failed types.
        }
    }
}
