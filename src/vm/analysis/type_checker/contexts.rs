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

use std::collections::{BTreeMap, HashMap, HashSet};
use vm::representations::{ClarityName, SymbolicExpression};
use vm::types::signatures::FunctionSignature;
use vm::types::{FunctionType, TraitIdentifier, TypeSignature};

use vm::contexts::MAX_CONTEXT_DEPTH;

use vm::analysis::errors::{CheckError, CheckErrors, CheckResult};
use vm::analysis::types::ContractAnalysis;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TypeMap {
    map: HashMap<u64, TypeSignature>,
}

pub struct TypingContext<'a> {
    pub variable_types: HashMap<ClarityName, TypeSignature>,
    pub traits_references: HashMap<ClarityName, TraitIdentifier>,
    pub parent: Option<&'a TypingContext<'a>>,
    pub depth: u16,
}

pub struct ContractContext {
    map_types: HashMap<ClarityName, (TypeSignature, TypeSignature)>,
    variable_types: HashMap<ClarityName, TypeSignature>,
    private_function_types: HashMap<ClarityName, FunctionType>,
    public_function_types: HashMap<ClarityName, FunctionType>,
    read_only_function_types: HashMap<ClarityName, FunctionType>,
    persisted_variable_types: HashMap<ClarityName, TypeSignature>,
    fungible_tokens: HashSet<ClarityName>,
    non_fungible_tokens: HashMap<ClarityName, TypeSignature>,
    traits: HashMap<ClarityName, BTreeMap<ClarityName, FunctionSignature>>,
    pub implemented_traits: HashSet<TraitIdentifier>,
}

impl TypeMap {
    pub fn new() -> TypeMap {
        TypeMap {
            map: HashMap::new(),
        }
    }

    pub fn set_type(
        &mut self,
        expr: &SymbolicExpression,
        type_sig: TypeSignature,
    ) -> CheckResult<()> {
        if self.map.insert(expr.id, type_sig).is_some() {
            Err(CheckError::new(CheckErrors::TypeAlreadyAnnotatedFailure))
        } else {
            Ok(())
        }
    }

    pub fn get_type(&self, expr: &SymbolicExpression) -> Option<&TypeSignature> {
        self.map.get(&expr.id)
    }
}

impl ContractContext {
    pub fn new() -> ContractContext {
        ContractContext {
            variable_types: HashMap::new(),
            private_function_types: HashMap::new(),
            public_function_types: HashMap::new(),
            read_only_function_types: HashMap::new(),
            map_types: HashMap::new(),
            persisted_variable_types: HashMap::new(),
            fungible_tokens: HashSet::new(),
            non_fungible_tokens: HashMap::new(),
            traits: HashMap::new(),
            implemented_traits: HashSet::new(),
        }
    }

    pub fn check_name_used(&self, name: &str) -> CheckResult<()> {
        if self.variable_types.contains_key(name)
            || self.persisted_variable_types.contains_key(name)
            || self.private_function_types.contains_key(name)
            || self.public_function_types.contains_key(name)
            || self.fungible_tokens.contains(name)
            || self.non_fungible_tokens.contains_key(name)
            || self.traits.contains_key(name)
            || self.map_types.contains_key(name)
        {
            Err(CheckError::new(CheckErrors::NameAlreadyUsed(
                name.to_string(),
            )))
        } else {
            Ok(())
        }
    }

    fn check_function_type(&mut self, f_name: &str) -> CheckResult<()> {
        self.check_name_used(f_name)?;
        Ok(())
    }

    pub fn ft_exists(&self, name: &str) -> bool {
        self.fungible_tokens.contains(name)
    }

    pub fn get_nft_type(&self, name: &str) -> Option<&TypeSignature> {
        self.non_fungible_tokens.get(name)
    }

    pub fn add_public_function_type(
        &mut self,
        name: ClarityName,
        func_type: FunctionType,
    ) -> CheckResult<()> {
        self.check_function_type(&name)?;
        self.public_function_types.insert(name, func_type);
        Ok(())
    }

    pub fn add_read_only_function_type(
        &mut self,
        name: ClarityName,
        func_type: FunctionType,
    ) -> CheckResult<()> {
        self.check_function_type(&name)?;
        self.read_only_function_types.insert(name, func_type);
        Ok(())
    }

    pub fn add_private_function_type(
        &mut self,
        name: ClarityName,
        func_type: FunctionType,
    ) -> CheckResult<()> {
        self.check_function_type(&name)?;
        self.private_function_types.insert(name, func_type);
        Ok(())
    }

    pub fn add_map_type(
        &mut self,
        map_name: ClarityName,
        map_type: (TypeSignature, TypeSignature),
    ) -> CheckResult<()> {
        self.check_name_used(&map_name)?;
        self.map_types.insert(map_name, map_type);
        Ok(())
    }

    pub fn add_variable_type(
        &mut self,
        const_name: ClarityName,
        var_type: TypeSignature,
    ) -> CheckResult<()> {
        self.check_name_used(&const_name)?;
        self.variable_types.insert(const_name, var_type);
        Ok(())
    }

    pub fn add_persisted_variable_type(
        &mut self,
        var_name: ClarityName,
        var_type: TypeSignature,
    ) -> CheckResult<()> {
        self.check_name_used(&var_name)?;
        self.persisted_variable_types.insert(var_name, var_type);
        Ok(())
    }

    pub fn add_ft(&mut self, token_name: ClarityName) -> CheckResult<()> {
        self.check_name_used(&token_name)?;
        self.fungible_tokens.insert(token_name);
        Ok(())
    }

    pub fn add_nft(
        &mut self,
        token_name: ClarityName,
        token_type: TypeSignature,
    ) -> CheckResult<()> {
        self.check_name_used(&token_name)?;
        self.non_fungible_tokens.insert(token_name, token_type);
        Ok(())
    }

    pub fn add_trait(
        &mut self,
        trait_name: ClarityName,
        trait_signature: BTreeMap<ClarityName, FunctionSignature>,
    ) -> CheckResult<()> {
        self.traits.insert(trait_name, trait_signature);
        Ok(())
    }

    pub fn add_implemented_trait(&mut self, trait_identifier: TraitIdentifier) -> CheckResult<()> {
        self.implemented_traits.insert(trait_identifier);
        Ok(())
    }

    pub fn get_trait(&self, trait_name: &str) -> Option<&BTreeMap<ClarityName, FunctionSignature>> {
        self.traits.get(trait_name)
    }

    pub fn get_map_type(&self, map_name: &str) -> Option<&(TypeSignature, TypeSignature)> {
        self.map_types.get(map_name)
    }

    pub fn get_variable_type(&self, name: &str) -> Option<&TypeSignature> {
        self.variable_types.get(name)
    }

    pub fn get_persisted_variable_type(&self, name: &str) -> Option<&TypeSignature> {
        self.persisted_variable_types.get(name)
    }

    pub fn get_function_type(&self, name: &str) -> Option<&FunctionType> {
        if let Some(f_type) = self.public_function_types.get(name) {
            Some(f_type)
        } else if let Some(f_type) = self.private_function_types.get(name) {
            Some(f_type)
        } else {
            self.read_only_function_types.get(name)
        }
    }

    /// This function consumes the ContractContext, and puts the relevant information
    ///  into the provided ContractAnalysis
    pub fn into_contract_analysis(mut self, contract_analysis: &mut ContractAnalysis) {
        for (name, function_type) in self.public_function_types.drain() {
            contract_analysis.add_public_function(name.into(), function_type);
        }

        for (name, function_type) in self.read_only_function_types.drain() {
            contract_analysis.add_read_only_function(name.into(), function_type);
        }

        for (name, (key_type, map_type)) in self.map_types.drain() {
            contract_analysis.add_map_type(name.into(), key_type, map_type);
        }

        for (name, function_type) in self.private_function_types.drain() {
            contract_analysis.add_private_function(name.into(), function_type);
        }

        for (name, variable_type) in self.variable_types.drain() {
            contract_analysis.add_variable_type(name.into(), variable_type);
        }

        for (name, persisted_variable_type) in self.persisted_variable_types.drain() {
            contract_analysis.add_persisted_variable_type(name.into(), persisted_variable_type);
        }

        for name in self.fungible_tokens.drain() {
            contract_analysis.add_fungible_token(name.into());
        }

        for (name, nft_type) in self.non_fungible_tokens.drain() {
            contract_analysis.add_non_fungible_token(name.into(), nft_type);
        }

        for (name, trait_signature) in self.traits.drain() {
            contract_analysis.add_defined_trait(name, trait_signature);
        }

        for trait_identifier in self.implemented_traits.drain() {
            contract_analysis.add_implemented_trait(trait_identifier);
        }
    }
}

impl<'a> TypingContext<'a> {
    pub fn new() -> TypingContext<'static> {
        TypingContext {
            variable_types: HashMap::new(),
            traits_references: HashMap::new(),
            depth: 0,
            parent: None,
        }
    }

    pub fn extend<'b>(&'b self) -> CheckResult<TypingContext<'b>> {
        if self.depth >= MAX_CONTEXT_DEPTH {
            Err(CheckError::new(CheckErrors::MaxContextDepthReached))
        } else {
            Ok(TypingContext {
                variable_types: HashMap::new(),
                traits_references: HashMap::new(),
                parent: Some(self),
                depth: self.depth + 1,
            })
        }
    }

    pub fn lookup_variable_type(&self, name: &str) -> Option<&TypeSignature> {
        match self.variable_types.get(name) {
            Some(value) => Some(value),
            None => match self.parent {
                Some(parent) => parent.lookup_variable_type(name),
                None => None,
            },
        }
    }

    pub fn add_trait_reference(&mut self, name: &ClarityName, value: &TraitIdentifier) {
        self.traits_references.insert(name.clone(), value.clone());
    }

    pub fn lookup_trait_reference_type(&self, name: &str) -> Option<&TraitIdentifier> {
        match self.traits_references.get(name) {
            Some(value) => Some(value),
            None => match self.parent {
                Some(parent) => parent.lookup_trait_reference_type(name),
                None => None,
            },
        }
    }
}
