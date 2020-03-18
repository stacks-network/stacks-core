
use chainstate::stacks::index::storage::{TrieFileStorage};
use vm::execute as vm_execute;
use chainstate::burn::BlockHeaderHash;
use vm::errors::{Error, CheckErrors, RuntimeErrorType};
use vm::types::{Value, OptionalData, StandardPrincipalData, ResponseData,
                TypeSignature, PrincipalData, QualifiedContractIdentifier};
use vm::contexts::{OwnedEnvironment,GlobalContext, Environment};
use vm::representations::SymbolicExpression;
use vm::contracts::Contract;
use util::hash::hex_bytes;
use vm::database::{MemoryBackingStore, MarfedKV, NULL_HEADER_DB, ClarityDatabase};
use vm::clarity::ClarityInstance;
use vm::ast;

use vm::tests::{with_memory_environment, with_marfed_environment, execute, symbols_from_values};


/*
 * This test exhibits memory inflation -- 
 *   `(define-data-var var-x ...)` uses more than 1048576 bytes of memory.
 *      this is mainly due to using hex encoding in the sqlite storage.
 */
#[test]
pub fn rollback_log_memory_test() {
    let marf = MarfedKV::temporary();
    let mut clarity_instance = ClarityInstance::new(marf);
    let EXPLODE_N = 100;

    let contract_identifier = QualifiedContractIdentifier::local("foo").unwrap();

    {
        let mut conn = clarity_instance.begin_block(&TrieFileStorage::block_sentinel(),
                                                    &BlockHeaderHash::from_bytes(&[0 as u8; 32]).unwrap(),
                                                    &NULL_HEADER_DB);

        let define_data_var = "(define-data-var XZ (buff 1048576) \"a\")";

        let mut contract = define_data_var.to_string();
        for i in 0..20 {
            let cur_size = format!("{}", 2u32.pow(i));
            contract.push_str("\n");
            contract.push_str(
                &format!("(var-set XZ (concat (unwrap-panic (as-max-len? (var-get XZ) u{}))
                                             (unwrap-panic (as-max-len? (var-get XZ) u{}))))",
                        cur_size, cur_size));
        }
        for i in 0..EXPLODE_N {
            let exploder = format!("(define-data-var var-{} (buff 1048576) (var-get XZ))", i);
            contract.push_str("\n");
            contract.push_str(&exploder);
        }

        let (ct_ast, ct_analysis) = conn.analyze_smart_contract(&contract_identifier, &contract).unwrap();
        assert!(format!("{:?}",
                        conn.initialize_smart_contract(
                            &contract_identifier, &ct_ast, &contract, |_,_| false).unwrap_err())
                .contains("MemoryBalanceExceeded"));
    }
}

/*
 */
#[test]
pub fn let_memory_test() {
    let marf = MarfedKV::temporary();
    let mut clarity_instance = ClarityInstance::new(marf);
    let EXPLODE_N = 100;

    let contract_identifier = QualifiedContractIdentifier::local("foo").unwrap();

    {
        let mut conn = clarity_instance.begin_block(&TrieFileStorage::block_sentinel(),
                                                    &BlockHeaderHash::from_bytes(&[0 as u8; 32]).unwrap(),
                                                    &NULL_HEADER_DB);

        let define_data_var = "(define-constant buff-0 \"a\")";

        let mut contract = define_data_var.to_string();
        for i in 0..20 {
            contract.push_str("\n");
            contract.push_str(
                &format!("(define-constant buff-{} (concat buff-{} buff-{}))",
                         i+1, i, i));
        }

        contract.push_str("\n");
        contract.push_str("(let (");

        for i in 0..EXPLODE_N {
            let exploder = format!("(var-{} buff-20) ", i);
            contract.push_str(&exploder);
        }

        contract.push_str(") 1)");

        let (ct_ast, ct_analysis) = conn.analyze_smart_contract(&contract_identifier, &contract).unwrap();
        assert!(format!("{:?}",
                        conn.initialize_smart_contract(
                            &contract_identifier, &ct_ast, &contract, |_,_| false).unwrap_err())
                .contains("MemoryBalanceExceeded"));
    }
}
