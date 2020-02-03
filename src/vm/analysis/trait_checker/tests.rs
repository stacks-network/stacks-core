use vm::ast::parse;
use vm::analysis::errors::CheckErrors;
use vm::analysis::{AnalysisDatabase, contract_interface_builder::build_contract_interface};
use vm::database::MemoryBackingStore;
use vm::analysis::mem_type_check;
use vm::analysis::type_check;
use vm::types::QualifiedContractIdentifier;

#[test]
fn test_dynamic_dispatch_by_defining_trait() {
    let dispatching_contract_src =
        "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-public (wrapped-get-1 (contract <trait-1>)) 
            (contract-call? contract get-1 u0))";
    let target_contract_src =
        "(define-public (get-1 (x uint)) (ok u1))";

    let dispatching_contract_id = QualifiedContractIdentifier::local("dispatching-contract").unwrap();
    let target_contract_id = QualifiedContractIdentifier::local("target-contract").unwrap();

    let mut dispatching_contract = parse(&dispatching_contract_id, dispatching_contract_src).unwrap();
    let mut target_contract = parse(&target_contract_id, target_contract_src).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    db.execute(|db| {
        type_check(&dispatching_contract_id, &mut dispatching_contract, db, true)?;
        type_check(&target_contract_id, &mut target_contract, db, true)
    }).unwrap();
}

#[test]
fn test_dynamic_dispatch_collision_trait() {
    let contract_defining_trait_src = 
        "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))";
    let dispatching_contract_src =
        "(use-trait trait-1 .contract-defining-trait.trait-1)
        (define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-public (wrapped-get-1 (contract <trait-1>)) 
            (contract-call? contract get-1 u0))";

    let contract_defining_trait_id = QualifiedContractIdentifier::local("contract-defining-trait").unwrap();
    let dispatching_contract_id = QualifiedContractIdentifier::local("dispatching-contract").unwrap();

    let mut contract_defining_trait = parse(&contract_defining_trait_id, contract_defining_trait_src).unwrap();
    let mut dispatching_contract = parse(&dispatching_contract_id, dispatching_contract_src).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    let err = db.execute(|db| {
        type_check(&contract_defining_trait_id, &mut contract_defining_trait, db, true)?;
        type_check(&dispatching_contract_id, &mut dispatching_contract, db, true)
    }).unwrap_err();
    match err.err {
        CheckErrors::NameAlreadyUsed(_) => {},
        _ => {
            println!("{:?}", err);
            panic!("Attempt to call init-factorial should fail!")
        }
    }
}

#[test]
fn test_dynamic_dispatch_importing_non_existant_trait() {
    let contract_defining_trait_src = 
        "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))";
    let dispatching_contract_src =
        "(use-trait trait-1 .contract-defining-trait.trait-2)
        (define-public (wrapped-get-1 (contract <trait-1>)) 
            (contract-call? contract get-1 u0))";
    let target_contract_src =
        "(impl-trait .contract-defining-trait.trait-2)
        (define-public (get-1 (x uint)) (ok u1))";

    let contract_defining_trait_id = QualifiedContractIdentifier::local("contract-defining-trait").unwrap();
    let dispatching_contract_id = QualifiedContractIdentifier::local("dispatching-contract").unwrap();
    let target_contract_id = QualifiedContractIdentifier::local("target-contract").unwrap();

    let mut contract_defining_trait = parse(&contract_defining_trait_id, contract_defining_trait_src).unwrap();
    let mut dispatching_contract = parse(&dispatching_contract_id, dispatching_contract_src).unwrap();
    let mut target_contract = parse(&target_contract_id, target_contract_src).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    let err = db.execute(|db| {
        type_check(&contract_defining_trait_id, &mut contract_defining_trait, db, true)?;
        type_check(&dispatching_contract_id, &mut dispatching_contract, db, true)?;
        type_check(&target_contract_id, &mut target_contract, db, true)
    }).unwrap_err();
    match err.err {
        CheckErrors::TraitReferenceUnknown(_) => {},
        _ => {
            println!("{:?}", err);
            panic!("Attempt to call init-factorial should fail!")
        }
    }
}

#[test]
fn test_dynamic_dispatch_importing_trait() {
    let contract_defining_trait_src = 
        "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))";
    let dispatching_contract_src =
        "(use-trait trait-1 .contract-defining-trait.trait-1)
        (define-public (wrapped-get-1 (contract <trait-1>)) 
            (contract-call? contract get-1 u0))";
    let target_contract_src =
        "(impl-trait .contract-defining-trait.trait-1)
        (define-public (get-1 (x uint)) (ok u1))";

    let contract_defining_trait_id = QualifiedContractIdentifier::local("contract-defining-trait").unwrap();
    let dispatching_contract_id = QualifiedContractIdentifier::local("dispatching-contract").unwrap();
    let target_contract_id = QualifiedContractIdentifier::local("target-contract").unwrap();

    let mut contract_defining_trait = parse(&contract_defining_trait_id, contract_defining_trait_src).unwrap();
    let mut dispatching_contract = parse(&dispatching_contract_id, dispatching_contract_src).unwrap();
    let mut target_contract = parse(&target_contract_id, target_contract_src).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    db.execute(|db| {
        type_check(&contract_defining_trait_id, &mut contract_defining_trait, db, true)?;
        type_check(&dispatching_contract_id, &mut dispatching_contract, db, true)?;
        type_check(&target_contract_id, &mut target_contract, db, true)
    }).unwrap();
}

#[test]
fn test_dynamic_dispatch_including_nested_trait() {
    let contract_defining_nested_trait_src = 
    "(define-trait trait-a (
        (get-a (uint) (response uint uint))))";
    let contract_defining_trait_src = 
        "(use-trait trait-a .contract-defining-nested-trait.trait-a)
        (define-trait trait-1 (
            (get-1 (<trait-a>) (response uint uint))))";
    let dispatching_contract_src =
        "(use-trait trait-1 .contract-defining-trait.trait-1)
         (use-trait trait-a .contract-defining-trait.trait-a)
         (define-public (wrapped-get-1 (contract <trait-1>) (nested-contract <trait-a>)) 
            (contract-call? contract get-1 nested-contract))";
    let target_contract_src =
        "(use-trait trait-a .contract-defining-nested-trait.trait-a)
        (define-public (get-1 (nested-contract <trait-a>))
            (contract-call? nested-contract get-a u0))";
    let target_nested_contract_src =
        "(define-public (get-a (x uint)) (ok u99))";

    let contract_defining_trait_id = QualifiedContractIdentifier::local("contract-defining-trait").unwrap();
    let dispatching_contract_id = QualifiedContractIdentifier::local("dispatching-contract").unwrap();
    let target_contract_id = QualifiedContractIdentifier::local("target-contract").unwrap();
    let contract_defining_nested_trait_id = QualifiedContractIdentifier::local("contract-defining-nested-trait").unwrap();
    let target_nested_contract_id = QualifiedContractIdentifier::local("target-nested-contract").unwrap();

    let mut contract_defining_trait = parse(&contract_defining_trait_id, contract_defining_trait_src).unwrap();
    let mut dispatching_contract = parse(&dispatching_contract_id, dispatching_contract_src).unwrap();
    let mut target_contract = parse(&target_contract_id, target_contract_src).unwrap();
    let mut contract_defining_nested_trait = parse(&contract_defining_nested_trait_id, contract_defining_nested_trait_src).unwrap();
    let mut target_nested_contract = parse(&target_nested_contract_id, target_nested_contract_src).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    db.execute(|db| {
        type_check(&contract_defining_nested_trait_id, &mut contract_defining_nested_trait, db, true)?;
        type_check(&contract_defining_trait_id, &mut contract_defining_trait, db, true)?;
        type_check(&dispatching_contract_id, &mut dispatching_contract, db, true)?;
        type_check(&target_contract_id, &mut target_contract, db, true)?;
        type_check(&target_nested_contract_id, &mut target_nested_contract, db, true)
    }).unwrap();
    
}

#[test]
fn test_dynamic_dispatch_mismatched_args() {
    let dispatching_contract_src =
        "(define-trait trait-1 (
            (get-1 (int) (response uint uint))))
        (define-public (wrapped-get-1 (contract <trait-1>)) 
            (contract-call? contract get-1 u0))";
    let target_contract_src =
        "(impl-trait .dispatching-contract.trait-1)
        (define-public (get-1 (x uint)) (ok u1))";

    let dispatching_contract_id = QualifiedContractIdentifier::local("dispatching-contract").unwrap();
    let target_contract_id = QualifiedContractIdentifier::local("target-contract").unwrap();

    let mut dispatching_contract = parse(&dispatching_contract_id, dispatching_contract_src).unwrap();
    let mut target_contract = parse(&target_contract_id, target_contract_src).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    let err = db.execute(|db| {
        type_check(&dispatching_contract_id, &mut dispatching_contract, db, true)?;
        type_check(&target_contract_id, &mut target_contract, db, true)
    }).unwrap_err();
    match err.err {
        CheckErrors::TypeError(_, _) => {},
        _ => {
            println!("{:?}", err);
            panic!("Attempt to call init-factorial should fail!")
        }
    }
}

#[test]
fn test_dynamic_dispatch_mismatched_returns() {
    let dispatching_contract_src =
        "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-public (wrapped-get-1 (contract <trait-1>)) 
            (contract-call? contract get-1 u0))";
    let target_contract_src =
        "(impl-trait .dispatching-contract.trait-1)
        (define-public (get-1 (x uint)) (ok \"buffer\"))";

    let dispatching_contract_id = QualifiedContractIdentifier::local("dispatching-contract").unwrap();
    let target_contract_id = QualifiedContractIdentifier::local("target-contract").unwrap();

    let mut dispatching_contract = parse(&dispatching_contract_id, dispatching_contract_src).unwrap();
    let mut target_contract = parse(&target_contract_id, target_contract_src).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    let err = db.execute(|db| {
        type_check(&dispatching_contract_id, &mut dispatching_contract, db, true)?;
        type_check(&target_contract_id, &mut target_contract, db, true)
    }).unwrap_err();
    match err.err {
        CheckErrors::BadTraitImplementation(_, _) => {},
        _ => {
            println!("{:?}", err);
            panic!("Attempt to call init-factorial should fail!")
        }
    }
}


