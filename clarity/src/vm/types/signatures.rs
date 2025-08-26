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

pub use clarity_serialization::types::signatures::{
    AssetIdentifier, BufferLength, CallableSubtype, ListTypeData, SequenceSubtype, StringSubtype,
    StringUTF8Length, TupleTypeSignature, TypeSignature, ASCII_40, BUFF_1, BUFF_16, BUFF_20,
    BUFF_21, BUFF_32, BUFF_33, BUFF_64, BUFF_65, UTF8_40,
};
pub use clarity_serialization::types::Value;
use stacks_common::types::StacksEpochId;

use crate::vm::costs::{runtime_cost, CostOverflowingMath};
use crate::vm::errors::CheckErrors;
use crate::vm::representations::{
    ClarityName, SymbolicExpression, SymbolicExpressionType, TraitDefinition,
};

type Result<R> = std::result::Result<R, CheckErrors>;

use self::TypeSignature::SequenceType;

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

/// Parsing functions.
pub trait TupleTypeSignatureExt {
    fn parse_name_type_pair_list<A: CostTracker>(
        epoch: StacksEpochId,
        type_def: &SymbolicExpression,
        accounting: &mut A,
    ) -> Result<TupleTypeSignature>;
}

impl TupleTypeSignatureExt for TupleTypeSignature {
    fn parse_name_type_pair_list<A: CostTracker>(
        epoch: StacksEpochId,
        type_def: &SymbolicExpression,
        accounting: &mut A,
    ) -> Result<TupleTypeSignature> {
        if let SymbolicExpressionType::List(ref name_type_pairs) = type_def.expr {
            let mapped_key_types = parse_name_type_pairs(epoch, name_type_pairs, accounting)?;
            TupleTypeSignature::try_from(mapped_key_types).map_err(CheckErrors::from)
        } else {
            Err(CheckErrors::BadSyntaxExpectedListOfPairs)
        }
    }
}

pub trait TypeSignatureExt {
    fn parse_atom_type(typename: &str) -> Result<TypeSignature>;
    fn parse_list_type_repr<A: CostTracker>(
        epoch: StacksEpochId,
        type_args: &[SymbolicExpression],
        accounting: &mut A,
    ) -> Result<TypeSignature>;
    fn parse_tuple_type_repr<A: CostTracker>(
        epoch: StacksEpochId,
        type_args: &[SymbolicExpression],
        accounting: &mut A,
    ) -> Result<TypeSignature>;
    fn parse_buff_type_repr(type_args: &[SymbolicExpression]) -> Result<TypeSignature>;
    fn parse_string_utf8_type_repr(type_args: &[SymbolicExpression]) -> Result<TypeSignature>;
    fn parse_string_ascii_type_repr(type_args: &[SymbolicExpression]) -> Result<TypeSignature>;
    fn parse_optional_type_repr<A: CostTracker>(
        epoch: StacksEpochId,
        type_args: &[SymbolicExpression],
        accounting: &mut A,
    ) -> Result<TypeSignature>;
    fn parse_response_type_repr<A: CostTracker>(
        epoch: StacksEpochId,
        type_args: &[SymbolicExpression],
        accounting: &mut A,
    ) -> Result<TypeSignature>;
    fn parse_type_repr<A: CostTracker>(
        epoch: StacksEpochId,
        x: &SymbolicExpression,
        accounting: &mut A,
    ) -> Result<TypeSignature>;
    fn parse_trait_type_repr<A: CostTracker>(
        type_args: &[SymbolicExpression],
        accounting: &mut A,
        epoch: StacksEpochId,
        clarity_version: ClarityVersion,
    ) -> Result<BTreeMap<ClarityName, FunctionSignature>>;
    #[cfg(test)]
    fn from_string(val: &str, version: ClarityVersion, epoch: StacksEpochId) -> Self;
}

impl TypeSignatureExt for TypeSignature {
    fn parse_atom_type(typename: &str) -> Result<TypeSignature> {
        match typename {
            "int" => Ok(TypeSignature::IntType),
            "uint" => Ok(TypeSignature::UIntType),
            "bool" => Ok(TypeSignature::BoolType),
            "principal" => Ok(TypeSignature::PrincipalType),
            _ => Err(CheckErrors::UnknownTypeName(typename.into())),
        }
    }

    // Parses list type signatures ->
    // (list maximum-length atomic-type)
    fn parse_list_type_repr<A: CostTracker>(
        epoch: StacksEpochId,
        type_args: &[SymbolicExpression],
        accounting: &mut A,
    ) -> Result<TypeSignature> {
        if type_args.len() != 2 {
            return Err(CheckErrors::InvalidTypeDescription);
        }

        if let SymbolicExpressionType::LiteralValue(Value::Int(max_len)) = &type_args[0].expr {
            let atomic_type_arg = &type_args[type_args.len() - 1];
            let entry_type = TypeSignature::parse_type_repr(epoch, atomic_type_arg, accounting)?;
            let max_len = u32::try_from(*max_len).map_err(|_| CheckErrors::ValueTooLarge)?;
            ListTypeData::new_list(entry_type, max_len)
                .map(|x| x.into())
                .map_err(CheckErrors::from)
        } else {
            Err(CheckErrors::InvalidTypeDescription)
        }
    }

    // Parses type signatures of the following form:
    // (tuple (key-name-0 value-type-0) (key-name-1 value-type-1))
    fn parse_tuple_type_repr<A: CostTracker>(
        epoch: StacksEpochId,
        type_args: &[SymbolicExpression],
        accounting: &mut A,
    ) -> Result<TypeSignature> {
        let mapped_key_types = parse_name_type_pairs(epoch, type_args, accounting)?;
        let tuple_type_signature = TupleTypeSignature::try_from(mapped_key_types)?;
        Ok(TypeSignature::from(tuple_type_signature))
    }

    // Parses type signatures of the form:
    // (buff 10)
    fn parse_buff_type_repr(type_args: &[SymbolicExpression]) -> Result<TypeSignature> {
        if type_args.len() != 1 {
            return Err(CheckErrors::InvalidTypeDescription);
        }
        if let SymbolicExpressionType::LiteralValue(Value::Int(buff_len)) = &type_args[0].expr {
            let buffer_length = BufferLength::try_from(*buff_len)?;
            Ok(SequenceType(SequenceSubtype::BufferType(buffer_length)))
        } else {
            Err(CheckErrors::InvalidTypeDescription)
        }
    }

    // Parses type signatures of the form:
    // (string-utf8 10)
    fn parse_string_utf8_type_repr(type_args: &[SymbolicExpression]) -> Result<TypeSignature> {
        if type_args.len() != 1 {
            return Err(CheckErrors::InvalidTypeDescription);
        }
        if let SymbolicExpressionType::LiteralValue(Value::Int(utf8_len)) = &type_args[0].expr {
            let string_utf8_length = StringUTF8Length::try_from(*utf8_len)?;
            Ok(SequenceType(SequenceSubtype::StringType(
                StringSubtype::UTF8(string_utf8_length),
            )))
        } else {
            Err(CheckErrors::InvalidTypeDescription)
        }
    }

    // Parses type signatures of the form:
    // (string-ascii 10)
    fn parse_string_ascii_type_repr(type_args: &[SymbolicExpression]) -> Result<TypeSignature> {
        if type_args.len() != 1 {
            return Err(CheckErrors::InvalidTypeDescription);
        }
        if let SymbolicExpressionType::LiteralValue(Value::Int(buff_len)) = &type_args[0].expr {
            let buffer_length = BufferLength::try_from(*buff_len)?;
            Ok(SequenceType(SequenceSubtype::StringType(
                StringSubtype::ASCII(buffer_length),
            )))
        } else {
            Err(CheckErrors::InvalidTypeDescription)
        }
    }

    fn parse_optional_type_repr<A: CostTracker>(
        epoch: StacksEpochId,
        type_args: &[SymbolicExpression],
        accounting: &mut A,
    ) -> Result<TypeSignature> {
        if type_args.len() != 1 {
            return Err(CheckErrors::InvalidTypeDescription);
        }
        let inner_type = TypeSignature::parse_type_repr(epoch, &type_args[0], accounting)?;

        TypeSignature::new_option(inner_type).map_err(CheckErrors::from)
    }

    fn parse_response_type_repr<A: CostTracker>(
        epoch: StacksEpochId,
        type_args: &[SymbolicExpression],
        accounting: &mut A,
    ) -> Result<TypeSignature> {
        if type_args.len() != 2 {
            return Err(CheckErrors::InvalidTypeDescription);
        }
        let ok_type = TypeSignature::parse_type_repr(epoch, &type_args[0], accounting)?;
        let err_type = TypeSignature::parse_type_repr(epoch, &type_args[1], accounting)?;
        TypeSignature::new_response(ok_type, err_type).map_err(CheckErrors::from)
    }

    fn parse_type_repr<A: CostTracker>(
        epoch: StacksEpochId,
        x: &SymbolicExpression,
        accounting: &mut A,
    ) -> Result<TypeSignature> {
        runtime_cost(ClarityCostFunction::TypeParseStep, accounting, 0)?;

        match x.expr {
            SymbolicExpressionType::Atom(ref atom_type_str) => {
                let atomic_type = TypeSignature::parse_atom_type(atom_type_str)?;
                Ok(atomic_type)
            }
            SymbolicExpressionType::List(ref list_contents) => {
                let (compound_type, rest) = list_contents
                    .split_first()
                    .ok_or(CheckErrors::InvalidTypeDescription)?;
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
                        _ => Err(CheckErrors::InvalidTypeDescription),
                    }
                } else {
                    Err(CheckErrors::InvalidTypeDescription)
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
            _ => Err(CheckErrors::InvalidTypeDescription),
        }
    }

    fn parse_trait_type_repr<A: CostTracker>(
        type_args: &[SymbolicExpression],
        accounting: &mut A,
        epoch: StacksEpochId,
        clarity_version: ClarityVersion,
    ) -> Result<BTreeMap<ClarityName, FunctionSignature>> {
        let mut trait_signature: BTreeMap<ClarityName, FunctionSignature> = BTreeMap::new();
        let functions_types = type_args
            .first()
            .ok_or_else(|| CheckErrors::InvalidTypeDescription)?
            .match_list()
            .ok_or(CheckErrors::DefineTraitBadSignature)?;

        for function_type in functions_types.iter() {
            let args = function_type
                .match_list()
                .ok_or(CheckErrors::DefineTraitBadSignature)?;
            if args.len() != 3 {
                return Err(CheckErrors::InvalidTypeDescription);
            }

            // Extract function's name
            let fn_name = args[0]
                .match_atom()
                .ok_or(CheckErrors::DefineTraitBadSignature)?;

            // Extract function's arguments
            let fn_args_exprs = args[1]
                .match_list()
                .ok_or(CheckErrors::DefineTraitBadSignature)?;
            let fn_args = fn_args_exprs
                .iter()
                .map(|arg_type| TypeSignature::parse_type_repr(epoch, arg_type, accounting))
                .collect::<Result<_>>()?;

            // Extract function's type return - must be a response
            let fn_return = match TypeSignature::parse_type_repr(epoch, &args[2], accounting) {
                Ok(response) => match response {
                    TypeSignature::ResponseType(_) => Ok(response),
                    _ => Err(CheckErrors::DefineTraitBadSignature),
                },
                _ => Err(CheckErrors::DefineTraitBadSignature),
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
                return Err(CheckErrors::DefineTraitDuplicateMethod(fn_name.to_string()));
            }
        }
        Ok(trait_signature)
    }

    #[cfg(test)]
    fn from_string(val: &str, version: ClarityVersion, epoch: StacksEpochId) -> Self {
        use clarity_serialization::types::QualifiedContractIdentifier;

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
    pub fn total_type_size(&self) -> Result<u64> {
        let mut function_type_size = u64::from(self.returns.type_size()?);
        for arg in self.args.iter() {
            function_type_size =
                function_type_size.cost_overflow_add(u64::from(arg.signature.type_size()?))?;
        }
        Ok(function_type_size)
    }
}

impl FunctionSignature {
    pub fn total_type_size(&self) -> Result<u64> {
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
    ) -> Result<bool> {
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

pub fn parse_name_type_pairs<A: CostTracker>(
    epoch: StacksEpochId,
    name_type_pairs: &[SymbolicExpression],
    accounting: &mut A,
) -> Result<Vec<(ClarityName, TypeSignature)>> {
    // this is a pretty deep nesting here, but what we're trying to do is pick out the values of
    // the form:
    // ((name1 type1) (name2 type2) (name3 type3) ...)
    // which is a list of 2-length lists of atoms.
    use crate::vm::representations::SymbolicExpressionType::List;

    // step 1: parse it into a vec of symbolicexpression pairs.
    let as_pairs: Result<Vec<_>> = name_type_pairs
        .iter()
        .map(|key_type_pair| {
            if let List(ref as_vec) = key_type_pair.expr {
                if as_vec.len() != 2 {
                    Err(CheckErrors::BadSyntaxExpectedListOfPairs)
                } else {
                    Ok((&as_vec[0], &as_vec[1]))
                }
            } else {
                Err(CheckErrors::BadSyntaxExpectedListOfPairs)
            }
        })
        .collect();

    // step 2: turn into a vec of (name, typesignature) pairs.
    let key_types: Result<Vec<_>> = (as_pairs?)
        .iter()
        .map(|(name_symbol, type_symbol)| {
            let name = name_symbol
                .match_atom()
                .ok_or(CheckErrors::BadSyntaxExpectedListOfPairs)?
                .clone();
            let type_info = TypeSignature::parse_type_repr(epoch, type_symbol, accounting)?;
            Ok((name, type_info))
        })
        .collect();

    key_types
}

impl fmt::Display for FunctionArg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.signature)
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use clarity_serialization::types::{
        QualifiedContractIdentifier, TraitIdentifier, MAX_VALUE_SIZE,
    };
    #[cfg(test)]
    use rstest::rstest;
    #[cfg(test)]
    use rstest_reuse::{self, *};
    use stacks_common::types::StacksEpochId;

    use super::CheckErrors::*;
    use super::TypeSignature::{BoolType, IntType, ListUnionType, UIntType};
    use super::*;
    use crate::vm::tests::test_clarity_versions;
    use crate::vm::{execute, ClarityVersion};

    fn fail_parse(val: &str, version: ClarityVersion, epoch: StacksEpochId) -> CheckErrors {
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
            CheckErrors::from(TupleTypeSignature::try_from(keys).unwrap_err()),
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

    #[test]
    fn test_least_supertype() {
        let callables = [
            CallableSubtype::Principal(QualifiedContractIdentifier::local("foo").unwrap()),
            CallableSubtype::Trait(TraitIdentifier {
                name: "foo".into(),
                contract_identifier: QualifiedContractIdentifier::transient(),
            }),
        ];
        let list_union = ListUnionType(callables.clone().into());
        let callables2 = [
            CallableSubtype::Principal(QualifiedContractIdentifier::local("bar").unwrap()),
            CallableSubtype::Trait(TraitIdentifier {
                name: "bar".into(),
                contract_identifier: QualifiedContractIdentifier::transient(),
            }),
        ];
        let list_union2 = ListUnionType(callables2.clone().into());
        let list_union_merged = ListUnionType(HashSet::from_iter(
            [callables, callables2].concat().iter().cloned(),
        ));
        let callable_principals = [
            CallableSubtype::Principal(QualifiedContractIdentifier::local("foo").unwrap()),
            CallableSubtype::Principal(QualifiedContractIdentifier::local("bar").unwrap()),
        ];
        let list_union_principals = ListUnionType(callable_principals.into());

        let notype_pairs = [
            // NoType with X should result in X
            (
                (TypeSignature::NoType, TypeSignature::NoType),
                TypeSignature::NoType,
            ),
            (
                (TypeSignature::NoType, TypeSignature::IntType),
                TypeSignature::IntType,
            ),
            (
                (TypeSignature::NoType, TypeSignature::UIntType),
                TypeSignature::UIntType,
            ),
            (
                (TypeSignature::NoType, TypeSignature::BoolType),
                TypeSignature::BoolType,
            ),
            (
                (TypeSignature::NoType, TypeSignature::min_buffer().unwrap()),
                TypeSignature::min_buffer().unwrap(),
            ),
            (
                (
                    TypeSignature::NoType,
                    TypeSignature::list_of(TypeSignature::IntType, 42).unwrap(),
                ),
                TypeSignature::list_of(TypeSignature::IntType, 42).unwrap(),
            ),
            (
                (
                    TypeSignature::NoType,
                    TypeSignature::bound_string_ascii_type(17).unwrap(),
                ),
                TypeSignature::bound_string_ascii_type(17).unwrap(),
            ),
            (
                (
                    TypeSignature::NoType,
                    TypeSignature::max_string_utf8().unwrap(),
                ),
                TypeSignature::max_string_utf8().unwrap(),
            ),
            (
                (TypeSignature::NoType, TypeSignature::PrincipalType),
                TypeSignature::PrincipalType,
            ),
            (
                (
                    TypeSignature::NoType,
                    TypeSignature::TupleType(
                        TupleTypeSignature::try_from(vec![("a".into(), TypeSignature::IntType)])
                            .unwrap(),
                    ),
                ),
                TypeSignature::TupleType(
                    TupleTypeSignature::try_from(vec![("a".into(), TypeSignature::IntType)])
                        .unwrap(),
                ),
            ),
            (
                (
                    TypeSignature::NoType,
                    TypeSignature::new_option(TypeSignature::IntType).unwrap(),
                ),
                TypeSignature::new_option(TypeSignature::IntType).unwrap(),
            ),
            (
                (
                    TypeSignature::NoType,
                    TypeSignature::new_response(TypeSignature::IntType, TypeSignature::BoolType)
                        .unwrap(),
                ),
                TypeSignature::new_response(TypeSignature::IntType, TypeSignature::BoolType)
                    .unwrap(),
            ),
            (
                (
                    TypeSignature::NoType,
                    TypeSignature::CallableType(CallableSubtype::Principal(
                        QualifiedContractIdentifier::transient(),
                    )),
                ),
                TypeSignature::CallableType(CallableSubtype::Principal(
                    QualifiedContractIdentifier::transient(),
                )),
            ),
            (
                (
                    TypeSignature::NoType,
                    TypeSignature::CallableType(CallableSubtype::Trait(TraitIdentifier {
                        name: "foo".into(),
                        contract_identifier: QualifiedContractIdentifier::transient(),
                    })),
                ),
                TypeSignature::CallableType(CallableSubtype::Trait(TraitIdentifier {
                    name: "foo".into(),
                    contract_identifier: QualifiedContractIdentifier::transient(),
                })),
            ),
            (
                (TypeSignature::NoType, list_union.clone()),
                list_union.clone(),
            ),
        ];

        for (pair, expected) in notype_pairs {
            assert_eq!(
                TypeSignature::least_supertype_v2_1(&pair.0, &pair.1).unwrap(),
                expected
            );
            assert_eq!(
                TypeSignature::least_supertype_v2_1(&pair.1, &pair.0).unwrap(),
                expected
            );
        }

        let simple_pairs = [
            ((IntType, IntType), IntType),
            ((UIntType, UIntType), UIntType),
            ((BoolType, BoolType), BoolType),
            (
                (
                    TypeSignature::max_buffer().unwrap(),
                    TypeSignature::max_buffer().unwrap(),
                ),
                TypeSignature::max_buffer().unwrap(),
            ),
            (
                (
                    TypeSignature::list_of(TypeSignature::IntType, 42).unwrap(),
                    TypeSignature::list_of(TypeSignature::IntType, 42).unwrap(),
                ),
                TypeSignature::list_of(TypeSignature::IntType, 42).unwrap(),
            ),
            (
                (
                    TypeSignature::bound_string_ascii_type(17).unwrap(),
                    TypeSignature::bound_string_ascii_type(17).unwrap(),
                ),
                TypeSignature::bound_string_ascii_type(17).unwrap(),
            ),
            (
                (
                    TypeSignature::max_string_utf8().unwrap(),
                    TypeSignature::max_string_utf8().unwrap(),
                ),
                TypeSignature::max_string_utf8().unwrap(),
            ),
            (
                (TypeSignature::PrincipalType, TypeSignature::PrincipalType),
                TypeSignature::PrincipalType,
            ),
            (
                (
                    TypeSignature::TupleType(
                        TupleTypeSignature::try_from(vec![("a".into(), TypeSignature::IntType)])
                            .unwrap(),
                    ),
                    TypeSignature::TupleType(
                        TupleTypeSignature::try_from(vec![("a".into(), TypeSignature::IntType)])
                            .unwrap(),
                    ),
                ),
                TypeSignature::TupleType(
                    TupleTypeSignature::try_from(vec![("a".into(), TypeSignature::IntType)])
                        .unwrap(),
                ),
            ),
            (
                (
                    TypeSignature::new_option(TypeSignature::IntType).unwrap(),
                    TypeSignature::new_option(TypeSignature::IntType).unwrap(),
                ),
                TypeSignature::new_option(TypeSignature::IntType).unwrap(),
            ),
            (
                (
                    TypeSignature::new_response(TypeSignature::IntType, TypeSignature::BoolType)
                        .unwrap(),
                    TypeSignature::new_response(TypeSignature::IntType, TypeSignature::BoolType)
                        .unwrap(),
                ),
                TypeSignature::new_response(TypeSignature::IntType, TypeSignature::BoolType)
                    .unwrap(),
            ),
            (
                (
                    TypeSignature::CallableType(CallableSubtype::Principal(
                        QualifiedContractIdentifier::transient(),
                    )),
                    TypeSignature::CallableType(CallableSubtype::Principal(
                        QualifiedContractIdentifier::transient(),
                    )),
                ),
                TypeSignature::CallableType(CallableSubtype::Principal(
                    QualifiedContractIdentifier::transient(),
                )),
            ),
            (
                (
                    TypeSignature::CallableType(CallableSubtype::Trait(TraitIdentifier {
                        name: "foo".into(),
                        contract_identifier: QualifiedContractIdentifier::transient(),
                    })),
                    TypeSignature::CallableType(CallableSubtype::Trait(TraitIdentifier {
                        name: "foo".into(),
                        contract_identifier: QualifiedContractIdentifier::transient(),
                    })),
                ),
                TypeSignature::CallableType(CallableSubtype::Trait(TraitIdentifier {
                    name: "foo".into(),
                    contract_identifier: QualifiedContractIdentifier::transient(),
                })),
            ),
            ((list_union.clone(), list_union.clone()), list_union.clone()),
        ];

        for (pair, expected) in simple_pairs {
            assert_eq!(
                TypeSignature::least_supertype_v2_1(&pair.0, &pair.1).unwrap(),
                expected
            );
            assert_eq!(
                TypeSignature::least_supertype_v2_1(&pair.1, &pair.0).unwrap(),
                expected
            );
        }

        let matched_pairs = [
            (
                (
                    TypeSignature::max_buffer().unwrap(),
                    TypeSignature::min_buffer().unwrap(),
                ),
                TypeSignature::max_buffer().unwrap(),
            ),
            (
                (
                    TypeSignature::list_of(TypeSignature::IntType, 17).unwrap(),
                    TypeSignature::list_of(TypeSignature::IntType, 42).unwrap(),
                ),
                TypeSignature::list_of(TypeSignature::IntType, 42).unwrap(),
            ),
            (
                (
                    TypeSignature::min_string_ascii().unwrap(),
                    TypeSignature::bound_string_ascii_type(17).unwrap(),
                ),
                TypeSignature::bound_string_ascii_type(17).unwrap(),
            ),
            (
                (
                    TypeSignature::min_string_utf8().unwrap(),
                    TypeSignature::max_string_utf8().unwrap(),
                ),
                TypeSignature::max_string_utf8().unwrap(),
            ),
            (
                (
                    TypeSignature::PrincipalType,
                    TypeSignature::CallableType(CallableSubtype::Principal(
                        QualifiedContractIdentifier::transient(),
                    )),
                ),
                TypeSignature::PrincipalType,
            ),
            (
                (TypeSignature::PrincipalType, list_union_principals.clone()),
                TypeSignature::PrincipalType,
            ),
            (
                (
                    TypeSignature::CallableType(CallableSubtype::Principal(
                        QualifiedContractIdentifier::local("foo").unwrap(),
                    )),
                    TypeSignature::CallableType(CallableSubtype::Principal(
                        QualifiedContractIdentifier::local("bar").unwrap(),
                    )),
                ),
                list_union_principals.clone(),
            ),
            (
                (list_union.clone(), list_union2.clone()),
                list_union_merged.clone(),
            ),
        ];

        for (pair, expected) in matched_pairs {
            assert_eq!(
                TypeSignature::least_supertype_v2_1(&pair.0, &pair.1).unwrap(),
                expected
            );
            assert_eq!(
                TypeSignature::least_supertype_v2_1(&pair.1, &pair.0).unwrap(),
                expected
            );
        }

        let compound_pairs = [
            (
                (
                    TypeSignature::list_of(
                        TypeSignature::SequenceType(SequenceSubtype::BufferType(
                            16_u32.try_into().unwrap(),
                        )),
                        5,
                    )
                    .unwrap(),
                    TypeSignature::list_of(TypeSignature::min_buffer().unwrap(), 3).unwrap(),
                ),
                TypeSignature::list_of(
                    TypeSignature::SequenceType(SequenceSubtype::BufferType(
                        16_u32.try_into().unwrap(),
                    )),
                    5,
                )
                .unwrap(),
            ),
            (
                (
                    TypeSignature::TupleType(
                        TupleTypeSignature::try_from(vec![(
                            "b".into(),
                            TypeSignature::min_string_ascii().unwrap(),
                        )])
                        .unwrap(),
                    ),
                    TypeSignature::TupleType(
                        TupleTypeSignature::try_from(vec![(
                            "b".into(),
                            TypeSignature::bound_string_ascii_type(17).unwrap(),
                        )])
                        .unwrap(),
                    ),
                ),
                TypeSignature::TupleType(
                    TupleTypeSignature::try_from(vec![(
                        "b".into(),
                        TypeSignature::bound_string_ascii_type(17).unwrap(),
                    )])
                    .unwrap(),
                ),
            ),
            (
                (
                    TypeSignature::new_option(TypeSignature::min_string_ascii().unwrap()).unwrap(),
                    TypeSignature::new_option(TypeSignature::bound_string_ascii_type(17).unwrap())
                        .unwrap(),
                ),
                TypeSignature::new_option(TypeSignature::bound_string_ascii_type(17).unwrap())
                    .unwrap(),
            ),
            (
                (
                    TypeSignature::new_response(TypeSignature::PrincipalType, list_union.clone())
                        .unwrap(),
                    TypeSignature::new_response(
                        TypeSignature::CallableType(CallableSubtype::Principal(
                            QualifiedContractIdentifier::transient(),
                        )),
                        list_union2.clone(),
                    )
                    .unwrap(),
                ),
                TypeSignature::new_response(TypeSignature::PrincipalType, list_union_merged)
                    .unwrap(),
            ),
        ];

        for (pair, expected) in compound_pairs {
            assert_eq!(
                TypeSignature::least_supertype_v2_1(&pair.0, &pair.1).unwrap(),
                expected
            );
            assert_eq!(
                TypeSignature::least_supertype_v2_1(&pair.1, &pair.0).unwrap(),
                expected
            );
        }

        let bad_pairs = [
            (IntType, UIntType),
            (BoolType, IntType),
            (
                TypeSignature::max_buffer().unwrap(),
                TypeSignature::max_string_ascii().unwrap(),
            ),
            (
                TypeSignature::list_of(TypeSignature::UIntType, 42).unwrap(),
                TypeSignature::list_of(TypeSignature::IntType, 42).unwrap(),
            ),
            (
                TypeSignature::min_string_utf8().unwrap(),
                TypeSignature::bound_string_ascii_type(17).unwrap(),
            ),
            (
                TypeSignature::min_string_utf8().unwrap(),
                TypeSignature::min_buffer().unwrap(),
            ),
            (
                TypeSignature::TupleType(
                    TupleTypeSignature::try_from(vec![("a".into(), TypeSignature::IntType)])
                        .unwrap(),
                ),
                TypeSignature::TupleType(
                    TupleTypeSignature::try_from(vec![("a".into(), TypeSignature::UIntType)])
                        .unwrap(),
                ),
            ),
            (
                TypeSignature::new_option(TypeSignature::IntType).unwrap(),
                TypeSignature::new_option(TypeSignature::min_string_utf8().unwrap()).unwrap(),
            ),
            (
                TypeSignature::new_response(TypeSignature::IntType, TypeSignature::BoolType)
                    .unwrap(),
                TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType)
                    .unwrap(),
            ),
            (
                TypeSignature::CallableType(CallableSubtype::Principal(
                    QualifiedContractIdentifier::transient(),
                )),
                TypeSignature::IntType,
            ),
            (
                TypeSignature::CallableType(CallableSubtype::Trait(TraitIdentifier {
                    name: "foo".into(),
                    contract_identifier: QualifiedContractIdentifier::transient(),
                })),
                TypeSignature::PrincipalType,
            ),
            (list_union.clone(), TypeSignature::PrincipalType),
            (
                TypeSignature::min_string_ascii().unwrap(),
                list_union_principals,
            ),
            (
                TypeSignature::list_of(
                    TypeSignature::SequenceType(SequenceSubtype::BufferType(
                        16_u32.try_into().unwrap(),
                    )),
                    5,
                )
                .unwrap(),
                TypeSignature::list_of(TypeSignature::min_string_ascii().unwrap(), 3).unwrap(),
            ),
            (
                TypeSignature::TupleType(
                    TupleTypeSignature::try_from(vec![(
                        "b".into(),
                        TypeSignature::min_string_ascii().unwrap(),
                    )])
                    .unwrap(),
                ),
                TypeSignature::TupleType(
                    TupleTypeSignature::try_from(vec![("b".into(), TypeSignature::UIntType)])
                        .unwrap(),
                ),
            ),
            (
                TypeSignature::new_option(TypeSignature::min_string_ascii().unwrap()).unwrap(),
                TypeSignature::new_option(TypeSignature::min_string_utf8().unwrap()).unwrap(),
            ),
            (
                TypeSignature::new_response(TypeSignature::PrincipalType, list_union).unwrap(),
                TypeSignature::new_response(
                    list_union2,
                    TypeSignature::CallableType(CallableSubtype::Principal(
                        QualifiedContractIdentifier::transient(),
                    )),
                )
                .unwrap(),
            ),
        ];

        for pair in bad_pairs {
            matches!(
                TypeSignature::least_supertype_v2_1(&pair.0, &pair.1)
                    .unwrap_err()
                    .into(),
                CheckErrors::TypeError(..)
            );
            matches!(
                TypeSignature::least_supertype_v2_1(&pair.1, &pair.0)
                    .unwrap_err()
                    .into(),
                CheckErrors::TypeError(..)
            );
        }
    }

    #[test]
    fn test_type_signature_bound_string_ascii_type_returns_check_errors() {
        let err = TypeSignature::bound_string_ascii_type(MAX_VALUE_SIZE + 1).unwrap_err();
        assert_eq!(
            CheckErrors::Expects(
                "FAIL: Max Clarity Value Size is no longer realizable in ASCII Type".to_string()
            ),
            err.into()
        );
    }
}
