#![no_main]

use libfuzzer_sys::fuzz_target;

use clarity::vm::analysis::run_analysis;
use clarity::vm::ast::definition_sorter::DefinitionSorter;
use clarity::vm::ast::expression_identifier::ExpressionIdentifier;
use clarity::vm::ast::stack_depth_checker::{StackDepthChecker, VaryStackDepthChecker};
use clarity::vm::ast::sugar_expander::SugarExpander;
use clarity::vm::ast::traits_resolver::TraitsResolver;
use clarity::vm::ast::types::BuildASTPass;
use clarity::vm::ast::types::ContractAST;
use clarity::vm::costs::LimitedCostTracker;
use clarity::vm::database::MemoryBackingStore;
use clarity::vm::representations::PreSymbolicExpression;
use clarity::vm::types::QualifiedContractIdentifier;
use clarity::vm::ClarityVersion;

// fuzz_target!(|data: &[u8]| {
//     if let Ok(s) = std::str::from_utf8(data) {
//         if !s.is_ascii() {
//             return;
//         }
//         build_ast_with_rules(
//             &QualifiedContractIdentifier::transient(),
//             s,
//             &mut (),
//             ClarityVersion::Clarity1,
//             StacksEpochId::Epoch2_05,
//             ASTRules::PrecheckSize,
//         );
//     }
// });

fuzz_target!(|exprs: Vec<PreSymbolicExpression>| {
    let clarity_version: ClarityVersion = ClarityVersion::Clarity1;
    let contract_id = QualifiedContractIdentifier::local("foo").unwrap();
    let mut contract_ast = ContractAST::new(contract_id.clone(), exprs);

    match StackDepthChecker::run_pass(&mut contract_ast, clarity_version) {
        Err(e) => println!("Error: {:?}", e),
        _ => (),
    }
    match VaryStackDepthChecker::run_pass(&mut contract_ast, clarity_version) {
        Err(e) => println!("Error: {:?}", e),
        _ => (),
    }
    match ExpressionIdentifier::run_pre_expression_pass(&mut contract_ast, clarity_version) {
        Err(e) => println!("Error: {:?}", e),
        _ => (),
    }
    match DefinitionSorter::run_pass(&mut contract_ast, &mut (), clarity_version) {
        Err(e) => println!("Error: {:?}", e),
        _ => (),
    }
    match TraitsResolver::run_pass(&mut contract_ast, clarity_version) {
        Err(e) => println!("Error: {:?}", e),
        _ => (),
    }
    match SugarExpander::run_pass(&mut contract_ast, clarity_version) {
        Err(e) => println!("Error: {:?}", e),
        _ => (),
    }
    match ExpressionIdentifier::run_expression_pass(&mut contract_ast, clarity_version) {
        Err(e) => println!("Error: {:?}", e),
        _ => (),
    }
    // println!("AST: {:?}", contract_ast);

    let mut marf = MemoryBackingStore::new();
    let mut analysis_db = marf.as_analysis_db();
    let cost_tracker = LimitedCostTracker::new_free();
    match run_analysis(
        &contract_id,
        &mut contract_ast.expressions,
        &mut analysis_db,
        false,
        cost_tracker,
        clarity_version,
    ) {
        Ok(_) => println!("Success"),
        Err((e, _)) => println!("Error: {:?}", e),
    }
});
