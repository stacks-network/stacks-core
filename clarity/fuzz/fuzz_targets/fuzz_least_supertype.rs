#![no_main]

use clarity::vm::analysis::CheckErrors::TypeError;
use clarity::vm::types::TypeSignature;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|types: (TypeSignature, TypeSignature)| {
    println!("types: {}, {}", types.0, types.1);
    if TypeSignature::contains_invalid_notype(&types.0)
        || TypeSignature::contains_invalid_notype(&types.1)
    {
        return;
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

    let mut new_res = TypeSignature::least_supertype(&types.0, &types.1);
    let old_res = TypeSignature::old_least_supertype(&old_types.0, &old_types.1);
    println!("## old: {:?}\n## new: {:?}", old_res, new_res);

    match (&old_res, &new_res) {
        (Err(TypeError(TypeSignature::PrincipalType, TypeSignature::TraitReferenceType(_))), _)
        | (Err(TypeError(TypeSignature::TraitReferenceType(_), TypeSignature::PrincipalType)), _)
        | (
            Err(TypeError(
                TypeSignature::TraitReferenceType(_),
                TypeSignature::TraitReferenceType(_),
            )),
            _,
        ) => (),
        _ => {
            // Convert the new result to the old type system for comparison.
            new_res = match new_res {
                Ok(res) => Ok(TypeSignature::new_type_to_old(&res).unwrap()),
                Err(TypeError(type1, type2)) => Err(TypeError(
                    TypeSignature::new_type_to_old(&type1).unwrap(),
                    TypeSignature::new_type_to_old(&type2).unwrap(),
                )),
                _ => new_res,
            };
            assert_eq!(old_res, new_res)
        }
    }
});
