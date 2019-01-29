extern crate blockstack_vm;

use blockstack_vm::types::{ValueType, TypeSignature, AtomTypeIdentifier};

use blockstack_vm::execute;

#[test]
fn test_simple_tea_shop() {
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

#[test]
fn silly_naming_system() {
    let test1 =
        "(define-map silly-names ((name int)) ((owner int)))
         (define (register name owner)
           (if (insert-entry! silly-names (tuple #name name) (tuple #owner owner))
               1 0))
         (define (who-owns? name)
           (let ((owner (get owner (fetch-entry silly-names (tuple #name name)))))
                (if (eq? 'null owner) (- 1) owner)))
         (define (invalidate! name owner)
           (let ((current-owner (get owner (fetch-entry silly-names (tuple #name name)))))
                (if (eq? current-owner owner)
                    (if (delete-entry! silly-names (tuple #name name)) 1 0)
                    0)))
        (list (register 0 0)
              (register 0 1)
              (register 1 1)
              (register 1 0)
              (who-owns? 0)
              (who-owns? 1)
              (invalidate! 0 1)
              (invalidate! 1 1)
              (who-owns? 0)
              (who-owns? 1))
        ";

    let expected = ValueType::ListType(
        vec![
            ValueType::IntType(1),
            ValueType::IntType(0),
            ValueType::IntType(1),
            ValueType::IntType(0),
            ValueType::IntType(0),
            ValueType::IntType(1),
            ValueType::IntType(0),
            ValueType::IntType(1),
            ValueType::IntType(0),
            ValueType::IntType(-1),
        ],
        TypeSignature::new(AtomTypeIdentifier::IntType, 1));

    assert_eq!(Ok(expected), execute(test1));
}
