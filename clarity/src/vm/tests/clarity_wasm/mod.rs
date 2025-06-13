use std::collections::{BTreeMap, BTreeSet};

use ouroboros::self_referencing;
use stacks_common::types::StacksEpochId;

use crate::vm::analysis::{AnalysisDatabase, CheckResult, ContractAnalysis};
use crate::vm::database::MemoryBackingStore;
use crate::vm::errors::CheckErrors;
use crate::vm::types::{
    FunctionSignature, FunctionType, QualifiedContractIdentifier, TraitIdentifier,
};
use crate::vm::{ClarityName, ClarityVersion};

#[self_referencing]
pub struct MemoryAnalysisDatabase {
    mem_store: MemoryBackingStore,
    #[not_covariant]
    #[borrows(mut mem_store)]
    pub analysis_db: AnalysisDatabase<'this>,
}

impl MemoryAnalysisDatabase {
    pub fn build() -> Self {
        let mem_store = MemoryBackingStore::new();

        MemoryAnalysisDatabaseBuilder {
            mem_store,
            analysis_db_builder: |mem_store| AnalysisDatabase::new(mem_store),
        }
        .build()
    }

    pub fn begin(&mut self) {
        self.with_analysis_db_mut(|db| db.begin())
    }
}
