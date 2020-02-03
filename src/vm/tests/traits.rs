use vm::types::{Value, TypeSignature, QualifiedContractIdentifier, ResponseData, PrincipalData};
use vm::types::TypeSignature::{IntType, UIntType, BoolType, ListType, BufferType};
use vm::types::signatures::{ListTypeData};
use vm::contexts::{OwnedEnvironment,GlobalContext, Environment};
use vm::execute as vm_execute;
use vm::errors::{CheckErrors, RuntimeErrorType, Error};
use vm::analysis::errors::{CheckError};
use std::convert::TryInto;

use vm::tests::{with_memory_environment, with_marfed_environment, execute, symbols_from_values};


#[test]
fn test_all() {
    let to_test = [
        test_dynamic_dispatch_by_defining_trait,
        test_dynamic_dispatch_by_implementing_imported_trait,
        test_dynamic_dispatch_by_importing_trait,
        test_dynamic_dispatch_including_nested_trait,
        test_dynamic_dispatch_mismatched_args,
        test_dynamic_dispatch_mismatched_returned,
        test_reentrant_dynamic_dispatch,
        ];
    for test in to_test.iter() {
        with_memory_environment(test, false);
        with_marfed_environment(test, false);
    }
}

fn test_dynamic_dispatch_by_defining_trait(owned_env: &mut OwnedEnvironment) {
    let dispatching_contract =
        "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-public (wrapped-get-1 (contract <trait-1>)) 
            (contract-call? contract get-1 u0))";
    let target_contract =
        "(define-public (get-1 (x uint)) (ok u1))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");

    {
        let mut env = owned_env.get_exec_environment(None);
        env.initialize_contract(QualifiedContractIdentifier::local("dispatching-contract").unwrap(), dispatching_contract).unwrap();
        env.initialize_contract(QualifiedContractIdentifier::local("target-contract").unwrap(), target_contract).unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(QualifiedContractIdentifier::local("target-contract").unwrap()));
        let mut env = owned_env.get_exec_environment(Some(p1.clone()));
        assert_eq!(
            env.execute_contract(&QualifiedContractIdentifier::local("dispatching-contract").unwrap(), "wrapped-get-1", &symbols_from_values(vec![target_contract])).unwrap(),
            Value::okay(Value::UInt(1)));
    }
}

fn test_dynamic_dispatch_by_implementing_imported_trait(owned_env: &mut OwnedEnvironment) {
    let contract_defining_trait = 
        "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))";
    let dispatching_contract =
        "(use-trait trait-1 .contract-defining-trait.trait-1)
        (define-public (wrapped-get-1 (contract <trait-1>)) 
            (contract-call? contract get-1 u0))";
    let target_contract =
        "(impl-trait .contract-defining-trait.trait-1)
        (define-public (get-1 (x uint)) (ok u1))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");

    {
        let mut env = owned_env.get_exec_environment(None);
        env.initialize_contract(QualifiedContractIdentifier::local("contract-defining-trait").unwrap(), contract_defining_trait).unwrap();
        env.initialize_contract(QualifiedContractIdentifier::local("dispatching-contract").unwrap(), dispatching_contract).unwrap();
        env.initialize_contract(QualifiedContractIdentifier::local("target-contract").unwrap(), target_contract).unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(QualifiedContractIdentifier::local("target-contract").unwrap()));
        let mut env = owned_env.get_exec_environment(Some(p1.clone()));
        assert_eq!(
            env.execute_contract(&QualifiedContractIdentifier::local("dispatching-contract").unwrap(), "wrapped-get-1", &symbols_from_values(vec![target_contract])).unwrap(),
            Value::okay(Value::UInt(1)));
    }
}

fn test_dynamic_dispatch_by_importing_trait(owned_env: &mut OwnedEnvironment) {
    let contract_defining_trait = 
        "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))";
    let dispatching_contract =
        "(use-trait trait-1 .contract-defining-trait.trait-1)
         (define-public (wrapped-get-1 (contract <trait-1>)) 
            (contract-call? contract get-1 u0))";
    let target_contract =
        "(define-public (get-1 (x uint)) (ok u1))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");

    {
        let mut env = owned_env.get_exec_environment(None);
        env.initialize_contract(QualifiedContractIdentifier::local("contract-defining-trait").unwrap(), contract_defining_trait).unwrap();
        env.initialize_contract(QualifiedContractIdentifier::local("dispatching-contract").unwrap(), dispatching_contract).unwrap();
        env.initialize_contract(QualifiedContractIdentifier::local("target-contract").unwrap(), target_contract).unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(QualifiedContractIdentifier::local("target-contract").unwrap()));
        let mut env = owned_env.get_exec_environment(Some(p1.clone()));
        assert_eq!(
            env.execute_contract(&QualifiedContractIdentifier::local("dispatching-contract").unwrap(), "wrapped-get-1", &symbols_from_values(vec![target_contract])).unwrap(),
            Value::okay(Value::UInt(1)));
    }
}

fn test_dynamic_dispatch_including_nested_trait(owned_env: &mut OwnedEnvironment) {
    let contract_defining_nested_trait = 
    "(define-trait trait-a (
        (get-a (uint) (response uint uint))))";
    let contract_defining_trait = 
        "(use-trait trait-a .contract-defining-nested-trait.trait-a)
        (define-trait trait-1 (
            (get-1 (<trait-a>) (response uint uint))))";
    let dispatching_contract =
        "(use-trait trait-1 .contract-defining-trait.trait-1)
         (use-trait trait-a .contract-defining-trait.trait-a)
         (define-public (wrapped-get-1 (contract <trait-1>) (nested-contract <trait-a>)) 
            (contract-call? contract get-1 nested-contract))";
    let target_contract =
        "(use-trait trait-a .contract-defining-nested-trait.trait-a)
        (define-public (get-1 (nested-contract <trait-a>))
            (contract-call? nested-contract get-a u0))";
    let target_nested_contract =
        "(define-public (get-a (x uint)) (ok u99))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");

    {
        let mut env = owned_env.get_exec_environment(None);
        env.initialize_contract(QualifiedContractIdentifier::local("contract-defining-nested-trait").unwrap(), contract_defining_nested_trait).unwrap();
        env.initialize_contract(QualifiedContractIdentifier::local("contract-defining-trait").unwrap(), contract_defining_trait).unwrap();
        env.initialize_contract(QualifiedContractIdentifier::local("dispatching-contract").unwrap(), dispatching_contract).unwrap();
        env.initialize_contract(QualifiedContractIdentifier::local("target-contract").unwrap(), target_contract).unwrap();
        env.initialize_contract(QualifiedContractIdentifier::local("target-nested-contract").unwrap(), target_nested_contract).unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(QualifiedContractIdentifier::local("target-contract").unwrap()));
        let target_nested_contract = Value::from(PrincipalData::Contract(QualifiedContractIdentifier::local("target-nested-contract").unwrap()));
        let mut env = owned_env.get_exec_environment(Some(p1.clone()));
        assert_eq!(
            env.execute_contract(&QualifiedContractIdentifier::local("dispatching-contract").unwrap(), "wrapped-get-1", &symbols_from_values(vec![target_contract, target_nested_contract])).unwrap(),
            Value::okay(Value::UInt(99)));
    }
}

fn test_dynamic_dispatch_mismatched_args(owned_env: &mut OwnedEnvironment) {
    let dispatching_contract =
        "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-public (wrapped-get-1 (contract <trait-1>)) 
            (contract-call? contract get-1 u0))";
    let target_contract =
        "(define-public (get-1 (x int)) (ok u1))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");

    {
        let mut env = owned_env.get_exec_environment(None);
        env.initialize_contract(QualifiedContractIdentifier::local("dispatching-contract").unwrap(), dispatching_contract).unwrap();
        env.initialize_contract(QualifiedContractIdentifier::local("target-contract").unwrap(), target_contract).unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(QualifiedContractIdentifier::local("target-contract").unwrap()));
        let mut env = owned_env.get_exec_environment(Some(p1.clone()));
        let err_result = env.execute_contract(&QualifiedContractIdentifier::local("dispatching-contract").unwrap(), "wrapped-get-1", &symbols_from_values(vec![target_contract])).unwrap_err();
        match err_result {
            Error::Unchecked(CheckErrors::BadTraitImplementation(_, _)) => {},
            _ => {
                println!("{:?}", err_result);
                panic!("Attempt to call init-factorial should fail!")
            }
        }
    }
}

fn test_dynamic_dispatch_mismatched_returned(owned_env: &mut OwnedEnvironment) {
    let dispatching_contract =
        "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-public (wrapped-get-1 (contract <trait-1>)) 
            (contract-call? contract get-1 u0))";
    let target_contract =
        "(define-public (get-1 (x uint)) (ok 1))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");

    {
        let mut env = owned_env.get_exec_environment(None);
        env.initialize_contract(QualifiedContractIdentifier::local("dispatching-contract").unwrap(), dispatching_contract).unwrap();
        env.initialize_contract(QualifiedContractIdentifier::local("target-contract").unwrap(), target_contract).unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(QualifiedContractIdentifier::local("target-contract").unwrap()));
        let mut env = owned_env.get_exec_environment(Some(p1.clone()));
        let err_result = env.execute_contract(&QualifiedContractIdentifier::local("dispatching-contract").unwrap(), "wrapped-get-1", &symbols_from_values(vec![target_contract])).unwrap_err();
        match err_result {
            Error::Unchecked(CheckErrors::ReturnTypesMustMatch(_, _)) => {},
            _ => {
                println!("{:?}", err_result);
                panic!("Attempt to call init-factorial should fail!")
            }
        }
    }
}

fn test_reentrant_dynamic_dispatch(owned_env: &mut OwnedEnvironment) {
    let dispatching_contract =
        "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-public (wrapped-get-1 (contract <trait-1>)) 
            (internal-get-1 contract))
        (define-private (internal-get-1 (contract <trait-1>)) 
            (contract-call? contract get-1 u0))";
    let target_contract =
        "(define-public (get-1 (x uint)) (contract-call? .dispatching-contract wrapped-get-1 .target-contract))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");

    {
        let mut env = owned_env.get_exec_environment(None);
        env.initialize_contract(QualifiedContractIdentifier::local("dispatching-contract").unwrap(), dispatching_contract).unwrap();
        env.initialize_contract(QualifiedContractIdentifier::local("target-contract").unwrap(), target_contract).unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(QualifiedContractIdentifier::local("target-contract").unwrap()));
        let mut env = owned_env.get_exec_environment(Some(p1.clone()));
        let err_result = env.execute_contract(&QualifiedContractIdentifier::local("dispatching-contract").unwrap(), "wrapped-get-1", &symbols_from_values(vec![target_contract])).unwrap_err();
        match err_result {
            Error::Unchecked(CheckErrors::CircularReference(_)) => {},
            _ => {
                println!("{:?}", err_result);
                panic!("Attempt to call init-factorial should fail!")
            }
        }
    }
}

// todo(ludo): add tests for ACL

// fn test_reentrant_dynamic_dispatch(owned_env: &mut OwnedEnvironment) {
//     let dispatching_contract =
//         "(define-public (wrapped-get-1 (x uint)) (contract-call? .target-contract get-1 u0))";
//     let target_contract =
//         "(define-public (get-1 (x uint)) (contract-call? .dispatching-contract wrapped-get-1 u0))";

//     let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");

//     {
//         let mut env = owned_env.get_exec_environment(None);
//         env.initialize_contract(QualifiedContractIdentifier::local("dispatching-contract").unwrap(), dispatching_contract).unwrap();
//         env.initialize_contract(QualifiedContractIdentifier::local("target-contract").unwrap(), target_contract).unwrap();
//     }

//     {
//         let target_contract = Value::from(PrincipalData::Contract(QualifiedContractIdentifier::local("target-contract").unwrap()));
//         let mut env = owned_env.get_exec_environment(Some(p1.clone()));
//         let err_result = env.execute_contract(&QualifiedContractIdentifier::local("dispatching-contract").unwrap(), "wrapped-get-1", &symbols_from_values(vec![Value::UInt(0)])).unwrap_err();
//         match err_result {
//             Error::Unchecked(CheckErrors::BadTraitImplementation(_, _)) => {},
//             _ => {
//                 println!("{:?}", err_result);
//                 panic!("Attempt to call init-factorial should fail!")
//             }
//         }
//     }
// }
