extern crate blockstack_vm;

use blockstack_vm::types::{ValueType, TypeSignature, AtomTypeIdentifier};

use blockstack_vm::execute;

#[test]
fn test_simple_map() {
    let test1 =
        "(define-map proper-tea ((tea-type int)) ((amount int)))
         (define (stock tea amount)
           (set-entry! proper-tea (tuple #tea-type tea) (tuple #amount amount)))
         (define (consume tea)
           (let ((current (get amount (fetch-entry proper-tea (tuple #tea-type tea)))))
              (if (and (not (eq? current 'null)) 
                       (>= current 1))
                  (begin
                    (set-entry! proper-tea (tuple #tea-type tea) 
                                                  (tuple #amount (- current 1)))
                    'true)
                  'false)))
        (stock 1 3)
        (stock 2 5)
        (list (consume 1)
              (consume 1)
              (consume 2)
              (consume 2)
              (consume 2)
              (consume 1)
              (consume 1)
              (consume 2)
              (consume 2)
              (consume 2)
              (consume 2)
              (consume 3))
        ";

    let expected = ValueType::ListType(
        vec![
            ValueType::BoolType(true),
            ValueType::BoolType(true),
            ValueType::BoolType(true),
            ValueType::BoolType(true),
            ValueType::BoolType(true),
            ValueType::BoolType(true),
            ValueType::BoolType(false),
            ValueType::BoolType(true),
            ValueType::BoolType(true),
            ValueType::BoolType(false),
            ValueType::BoolType(false),
            ValueType::BoolType(false)],
        TypeSignature::new(AtomTypeIdentifier::BoolType, 1));

    assert_eq!(Ok(expected), execute(test1));
}
