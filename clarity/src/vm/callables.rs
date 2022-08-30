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

use std::collections::{BTreeMap, HashMap};
use std::convert::TryInto;
use std::fmt;
use std::iter::FromIterator;

use crate::vm::costs::{cost_functions, runtime_cost};

use crate::vm::analysis::errors::CheckErrors;
use crate::vm::contexts::ContractContext;
use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::errors::{check_argument_count, Error, InterpreterResult as Result};
use crate::vm::representations::{ClarityName, SymbolicExpression};
use crate::vm::types::Value::UInt;
use crate::vm::types::{
    FunctionType, ListData, ListTypeData, OptionalData, PrincipalData, QualifiedContractIdentifier,
    ResponseData, SequenceData, SequenceSubtype, TraitData, TraitIdentifier, TupleData,
    TupleTypeSignature, TypeSignature,
};
use crate::vm::{eval, Environment, LocalContext, Value};

use super::costs::CostOverflowingMath;

pub enum CallableType {
    UserFunction(DefinedFunction),
    NativeFunction(&'static str, NativeHandle, ClarityCostFunction),
    /// These native functions have a new method for calculating input size in 2.05
    /// If the global context's epoch is >= 2.05, the fn field is applied to obtain
    /// the input to the cost function.
    NativeFunction205(
        &'static str,
        NativeHandle,
        ClarityCostFunction,
        &'static dyn Fn(&[Value]) -> Result<u64>,
    ),
    SpecialFunction(
        &'static str,
        &'static dyn Fn(&[SymbolicExpression], &mut Environment, &LocalContext) -> Result<Value>,
    ),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DefineType {
    ReadOnly,
    Public,
    Private,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefinedFunction {
    identifier: FunctionIdentifier,
    name: ClarityName,
    arg_types: Vec<TypeSignature>,
    pub define_type: DefineType,
    arguments: Vec<ClarityName>,
    body: SymbolicExpression,
}

/// This enum handles the actual invocation of the method
/// implementing a native function. Each variant handles
/// different expected number of arguments.
pub enum NativeHandle {
    SingleArg(&'static dyn Fn(Value) -> Result<Value>),
    DoubleArg(&'static dyn Fn(Value, Value) -> Result<Value>),
    MoreArg(&'static dyn Fn(Vec<Value>) -> Result<Value>),
}

impl NativeHandle {
    pub fn apply(&self, mut args: Vec<Value>) -> Result<Value> {
        match self {
            Self::SingleArg(function) => {
                check_argument_count(1, &args)?;
                function(args.pop().unwrap())
            }
            Self::DoubleArg(function) => {
                check_argument_count(2, &args)?;
                let second = args.pop().unwrap();
                let first = args.pop().unwrap();
                function(first, second)
            }
            Self::MoreArg(function) => function(args),
        }
    }
}

pub fn cost_input_sized_vararg(args: &[Value]) -> Result<u64> {
    args.iter()
        .try_fold(0, |sum, value| {
            (value.serialized_size() as u64).cost_overflow_add(sum)
        })
        .map_err(Error::from)
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct FunctionIdentifier {
    identifier: String,
}

impl fmt::Display for FunctionIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.identifier)
    }
}

impl DefinedFunction {
    pub fn new(
        mut arguments: Vec<(ClarityName, TypeSignature)>,
        body: SymbolicExpression,
        define_type: DefineType,
        name: &ClarityName,
        context_name: &str,
    ) -> DefinedFunction {
        let (argument_names, types) = arguments.drain(..).unzip();

        DefinedFunction {
            identifier: FunctionIdentifier::new_user_function(name, context_name),
            name: name.clone(),
            arguments: argument_names,
            define_type,
            body,
            arg_types: types,
        }
    }

    pub fn execute_apply(&self, args: &[Value], env: &mut Environment) -> Result<Value> {
        runtime_cost(
            ClarityCostFunction::UserFunctionApplication,
            env,
            self.arguments.len(),
        )?;

        for arg_type in self.arg_types.iter() {
            runtime_cost(
                ClarityCostFunction::InnerTypeCheckCost,
                env,
                arg_type.size(),
            )?;
        }

        let mut context = LocalContext::new();
        if args.len() != self.arguments.len() {
            Err(CheckErrors::IncorrectArgumentCount(
                self.arguments.len(),
                args.len(),
            ))?
        }

        let mut arg_iterator: Vec<_> = self
            .arguments
            .iter()
            .zip(self.arg_types.iter())
            .zip(args.iter())
            .collect();

        for arg in arg_iterator.drain(..) {
            let ((name, type_sig), value) = arg;

            // Arguments containing principals can be implicitly cast to traits
            // to match parameter types.
            // e.g. `(optional principal)` to `(optional <trait>`)
            // and traits can be implicitly cast to sub-traits
            // e.g. `<foo-and-bar>` to `<foo>`
            let cast_value = implicit_cast(type_sig, value)?;

            match (&type_sig, &cast_value) {
                // FIXME(brice): This first case should be removed after verifying that it doesn't get hit.
                (
                    TypeSignature::TraitReferenceType(_),
                    Value::Principal(PrincipalData::Contract(_)),
                ) => unreachable!("This principal should've been mapped to a Trait"),
                (
                    _,
                    Value::Trait(TraitData {
                        contract_identifier,
                        trait_identifier,
                    }),
                ) => {
                    // Argument is a trait reference, probably leading to a dynamic contract call.
                    // We keep a reference of the mapping (var-name: (callee_contract_id, trait_id)) in the context.
                    // The trait compatibility has been checked by the type-checker.
                    context.callable_contracts.insert(
                        name.clone(),
                        TraitData {
                            contract_identifier: contract_identifier.clone(),
                            trait_identifier: trait_identifier.clone(),
                        },
                    );
                }
                _ => (),
            }
            if !type_sig.admits(&cast_value) {
                return Err(CheckErrors::TypeValueError(type_sig.clone(), cast_value).into());
            }
            if let Some(_) = context.variables.insert(name.clone(), cast_value) {
                return Err(CheckErrors::NameAlreadyUsed(name.to_string()).into());
            }
        }

        let result = eval(&self.body, env, &context);

        // if the error wasn't actually an error, but a function return,
        //    pull that out and return it.
        match result {
            Ok(r) => Ok(r),
            Err(e) => match e {
                Error::ShortReturn(v) => Ok(v.into()),
                _ => Err(e),
            },
        }
    }

    pub fn check_trait_expectations(
        &self,
        contract_defining_trait: &ContractContext,
        trait_identifier: &TraitIdentifier,
    ) -> Result<()> {
        let trait_name = trait_identifier.name.to_string();
        let constraining_trait = contract_defining_trait
            .lookup_trait_definition(&trait_name)
            .ok_or(CheckErrors::TraitReferenceUnknown(trait_name.to_string()))?;
        let expected_sig =
            constraining_trait
                .get(&self.name)
                .ok_or(CheckErrors::TraitMethodUnknown(
                    trait_name.to_string(),
                    self.name.to_string(),
                ))?;

        let args = self.arg_types.iter().map(|a| a.clone()).collect();
        if !expected_sig.check_args_trait_compliance(args) {
            return Err(
                CheckErrors::BadTraitImplementation(trait_name, self.name.to_string()).into(),
            );
        }

        Ok(())
    }

    pub fn is_read_only(&self) -> bool {
        self.define_type == DefineType::ReadOnly
    }

    pub fn apply(&self, args: &[Value], env: &mut Environment) -> Result<Value> {
        match self.define_type {
            DefineType::Private => self.execute_apply(args, env),
            DefineType::Public => env.execute_function_as_transaction(self, args, None),
            DefineType::ReadOnly => env.execute_function_as_transaction(self, args, None),
        }
    }

    pub fn is_public(&self) -> bool {
        match self.define_type {
            DefineType::Public => true,
            DefineType::Private => false,
            DefineType::ReadOnly => true,
        }
    }

    pub fn get_identifier(&self) -> FunctionIdentifier {
        self.identifier.clone()
    }
}

impl CallableType {
    pub fn get_identifier(&self) -> FunctionIdentifier {
        match self {
            CallableType::UserFunction(f) => f.get_identifier(),
            CallableType::NativeFunction(s, _, _) => FunctionIdentifier::new_native_function(s),
            CallableType::SpecialFunction(s, _) => FunctionIdentifier::new_native_function(s),
            CallableType::NativeFunction205(s, _, _, _) => {
                FunctionIdentifier::new_native_function(s)
            }
        }
    }
}

impl FunctionIdentifier {
    fn new_native_function(name: &str) -> FunctionIdentifier {
        let identifier = format!("_native_:{}", name);
        FunctionIdentifier {
            identifier: identifier,
        }
    }

    fn new_user_function(name: &str, context: &str) -> FunctionIdentifier {
        let identifier = format!("{}:{}", context, name);
        FunctionIdentifier {
            identifier: identifier,
        }
    }
}

// Implicitly cast principals to traits and traits to other traits as needed,
// recursing into compound types. This function does not check for legality of
// these casts, as that is done in the type-checker. Note: depth of recursion
// should be capped by earlier checks on the types/values.
fn implicit_cast(type_sig: &TypeSignature, value: &Value) -> Result<Value> {
    Ok(match (type_sig, value) {
        (
            TypeSignature::OptionalType(inner_type),
            Value::Optional(OptionalData {
                data: Some(inner_value),
            }),
        ) => Value::Optional(OptionalData {
            data: Some(Box::new(implicit_cast(inner_type, inner_value)?)),
        }),
        (
            TypeSignature::ResponseType(inner_types),
            Value::Response(ResponseData { committed, data }),
        ) => Value::Response(ResponseData {
            committed: *committed,
            data: Box::new(implicit_cast(
                if *committed {
                    &inner_types.0
                } else {
                    &inner_types.1
                },
                data,
            )?),
        }),
        (
            TypeSignature::SequenceType(SequenceSubtype::ListType(list_type)),
            Value::Sequence(SequenceData::List(ListData {
                data,
                type_signature,
            })),
        ) => {
            let mut values = Vec::new();
            for elem in data {
                values.push(implicit_cast(list_type.get_list_item_type(), elem)?);
            }
            Value::Sequence(SequenceData::List(ListData {
                data: values,
                type_signature: type_signature.clone(),
            }))
        }
        (
            TypeSignature::TupleType(tuple_type),
            Value::Tuple(TupleData {
                type_signature: _,
                data_map,
            }),
        ) => {
            let mut cast_data_map = BTreeMap::new();
            for (name, field_value) in data_map {
                let to_type = match tuple_type.get_type_map().get(name) {
                    Some(ty) => ty,
                    None => {
                        return Err(
                            CheckErrors::TypeValueError(type_sig.clone(), value.clone()).into()
                        )
                    }
                };
                cast_data_map.insert(name.clone(), implicit_cast(to_type, field_value)?);
            }
            Value::Tuple(TupleData {
                type_signature: tuple_type.clone(),
                data_map: cast_data_map,
            })
        }
        (
            TypeSignature::TraitReferenceType(trait_identifier),
            Value::Principal(PrincipalData::Contract(contract_identifier)),
        ) => Value::Trait(TraitData {
            contract_identifier: contract_identifier.clone(),
            trait_identifier: trait_identifier.clone(),
        }),
        _ => value.clone(),
    })
}

#[test]
fn test_implicit_cast() {
    // principal -> <trait>
    let trait_identifier = TraitIdentifier::parse_fully_qualified(
        "SP2PABAF9FTAJYNFZH93XENAJ8FVY99RRM50D2JG9.nft-trait.nft-trait",
    )
    .unwrap();
    let trait_ty = TypeSignature::TraitReferenceType(trait_identifier.clone());
    let contract_identifier =
        QualifiedContractIdentifier::parse("SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR.contract")
            .unwrap();
    let contract = Value::Principal(PrincipalData::Contract(contract_identifier.clone()));
    let cast_contract = implicit_cast(&trait_ty, &contract).unwrap();
    let cast_trait = cast_contract.expect_trait();
    assert_eq!(&cast_trait.contract_identifier, &contract_identifier);
    assert_eq!(&cast_trait.trait_identifier, &trait_identifier);

    // (optional principal) -> (optional <trait>)
    let optional_ty = TypeSignature::new_option(trait_ty.clone()).unwrap();
    let optional_contract = Value::some(contract.clone()).unwrap();
    let cast_optional = implicit_cast(&optional_ty, &optional_contract).unwrap();
    match &cast_optional.expect_optional().unwrap() {
        Value::Trait(TraitData {
            contract_identifier: contract_id,
            trait_identifier: trait_id,
        }) => {
            assert_eq!(contract_id, &contract_identifier);
            assert_eq!(trait_id, &trait_identifier);
        }
        other => panic!("expected Value::Trait, got {:?}", other),
    }

    // (ok principal) -> (ok <trait>)
    let response_ty =
        TypeSignature::new_response(trait_ty.clone(), TypeSignature::UIntType).unwrap();
    let response_contract = Value::okay(contract.clone()).unwrap();
    let cast_response = implicit_cast(&response_ty, &response_contract).unwrap();
    let cast_trait = cast_response.expect_result_ok().expect_trait();
    assert_eq!(&cast_trait.contract_identifier, &contract_identifier);
    assert_eq!(&cast_trait.trait_identifier, &trait_identifier);

    // (err principal) -> (err <trait>)
    let response_ty =
        TypeSignature::new_response(TypeSignature::UIntType, trait_ty.clone()).unwrap();
    let response_contract = Value::error(contract.clone()).unwrap();
    let cast_response = implicit_cast(&response_ty, &response_contract).unwrap();
    let cast_trait = cast_response.expect_result_err().expect_trait();
    assert_eq!(&cast_trait.contract_identifier, &contract_identifier);
    assert_eq!(&cast_trait.trait_identifier, &trait_identifier);

    // (list principal) -> (list <trait>)
    let list_ty = TypeSignature::list_of(trait_ty.clone(), 4).unwrap();
    let list_contract = Value::list_with_type(
        vec![contract.clone(), contract.clone()],
        ListTypeData::new_list(TypeSignature::PrincipalType, 4).unwrap(),
    )
    .unwrap();
    let cast_list = implicit_cast(&list_ty, &list_contract).unwrap();
    let items = cast_list.expect_list();
    for item in items {
        let cast_trait = item.expect_trait();
        assert_eq!(&cast_trait.contract_identifier, &contract_identifier);
        assert_eq!(&cast_trait.trait_identifier, &trait_identifier);
    }

    // {a: principal} -> {a: <trait>}
    let a_name = ClarityName::from("a");
    let tuple_ty = TypeSignature::TupleType(
        TupleTypeSignature::try_from(vec![(a_name.clone(), trait_ty.clone())]).unwrap(),
    );
    let contract_tuple_ty = TypeSignature::TupleType(
        TupleTypeSignature::try_from(vec![(a_name.clone(), TypeSignature::PrincipalType)]).unwrap(),
    );
    let mut data_map = BTreeMap::new();
    data_map.insert(a_name.clone(), contract.clone());
    let tuple_contract = Value::Tuple(TupleData {
        type_signature: TupleTypeSignature::try_from(vec![(
            a_name.clone(),
            TypeSignature::PrincipalType,
        )])
        .unwrap(),
        data_map,
    });
    let cast_tuple = implicit_cast(&tuple_ty, &tuple_contract).unwrap();
    let cast_trait = cast_tuple
        .expect_tuple()
        .get(&a_name)
        .unwrap()
        .clone()
        .expect_trait();
    assert_eq!(&cast_trait.contract_identifier, &contract_identifier);
    assert_eq!(&cast_trait.trait_identifier, &trait_identifier);

    // (list (optional principal)) -> (list (optional <trait>))
    let list_opt_ty = TypeSignature::list_of(optional_ty.clone(), 4).unwrap();
    let list_opt_contract = Value::list_with_type(
        vec![
            Value::some(contract.clone()).unwrap(),
            Value::some(contract.clone()).unwrap(),
        ],
        ListTypeData::new_list(
            TypeSignature::new_option(TypeSignature::PrincipalType).unwrap(),
            4,
        )
        .unwrap(),
    )
    .unwrap();
    let cast_list = implicit_cast(&list_opt_ty, &list_opt_contract).unwrap();
    let items = cast_list.expect_list();
    for item in items {
        let cast_opt = item.expect_optional().unwrap();
        let cast_trait = cast_opt.expect_trait();
        assert_eq!(&cast_trait.contract_identifier, &contract_identifier);
        assert_eq!(&cast_trait.trait_identifier, &trait_identifier);
    }
}
