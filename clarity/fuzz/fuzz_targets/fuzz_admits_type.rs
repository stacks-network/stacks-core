#![no_main]

use clarity::vm::types::signatures::CallableSubtype;
use clarity::vm::types::TypeSignature;
use stacks_common::types::StacksEpochId;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|types: (TypeSignature, TypeSignature)| {
    let epoch = StacksEpochId::Epoch23;
    println!("types: {}, {}", types.0, types.1);
    if TypeSignature::contains_invalid_type_lhs(&types.0)
        || TypeSignature::contains_invalid_type_rhs(&types.1) {
        return;
    }

    // The admitting type cannot be a callable principal or a list-union
    match types.0 {
        TypeSignature::CallableType(CallableSubtype::Principal(_)) => return,
        TypeSignature::ListUnionType(_) => return,
        _ => (),
    }

    // If the type can't be converted, then we can't compare the results.
    let old_types = match (
        TypeSignature::new_type_to_old(&types.0),
        TypeSignature::new_type_to_old(&types.1),
    ) {
        (Ok(old_type1), Ok(old_type2)) => (old_type1, old_type2),
        _ => return,
    };
    println!("old_types: {}, {}", old_types.0, old_types.1);

    let new_res = types.0.admits_type(&epoch, &types.1).unwrap();
    let old_res = old_types.0.admits_type_v2_0(&old_types.1).unwrap();
    assert_eq!(old_res, new_res)
});
