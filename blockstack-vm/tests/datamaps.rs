extern crate blockstack_vm;

use blockstack_vm::errors::Error;
use blockstack_vm::types::{Value, TypeSignature, AtomTypeIdentifier};

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

    if let Ok(type_sig) = TypeSignature::new_list(AtomTypeIdentifier::BoolType, 12, 1) {
        let expected = Value::List(
            vec![
                Value::Bool(true),
                Value::Bool(true),
                Value::Bool(true),
                Value::Bool(true),
                Value::Bool(true),
                Value::Bool(true),
                Value::Bool(false),
                Value::Bool(true),
                Value::Bool(true),
                Value::Bool(false),
                Value::Bool(false),
            Value::Bool(false)],
            type_sig
        );
        
        assert_eq!(Ok(expected), execute(test1));
    } else {
        panic!("Error in type construction")
    }

}

#[test]
fn test_factorial_contract() {
    let test1 =
        "(define-map factorials ((id int)) ((current int) (index int)))
         (define (init-factorial id factorial)
           (insert-entry! factorials (tuple #id id) (tuple #current 1 #index factorial)))
         (define (compute id)
           (let ((entry (fetch-entry factorials (tuple #id id))))
                (if (eq? entry 'null)
                    0
                    (let ((current (get current entry))
                          (index   (get index entry)))
                         (if (<= index 1)
                             current
                             (begin
                               (set-entry! factorials (tuple #id id)
                                                      (tuple #current (* current index)
                                                             #index (- index 1)))
                               0))))))
        (init-factorial 1337 3)
        (init-factorial 8008 5)
        (list (compute 1337)
              (compute 1337)
              (compute 1337)
              (compute 1337)
              (compute 1337)
              (compute 8008)
              (compute 8008)
              (compute 8008)
              (compute 8008)
              (compute 8008)
              (compute 8008))
        ";

    let expected = Value::new_list(vec![
        Value::Int(0),
        Value::Int(0),
        Value::Int(6),
        Value::Int(6),
        Value::Int(6),
        Value::Int(0),
        Value::Int(0),
        Value::Int(0),
        Value::Int(0),
        Value::Int(120),
        Value::Int(120),
    ]);
        
    assert_eq!(expected, execute(test1));
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

    let expected = Value::new_list(vec![
        Value::Int(1),
        Value::Int(0),
        Value::Int(1),
        Value::Int(0),
        Value::Int(0),
        Value::Int(1),
        Value::Int(0),
        Value::Int(1),
        Value::Int(0),
        Value::Int(-1),
    ]);
    assert_eq!(expected, execute(test1));
}

#[test]
fn lists_system() {
    let test1 =
        "(define-map lists ((name int)) ((contents list-int-1-5)))
         (define (add-list name content)
           (insert-entry! lists (tuple #name name)
                                (tuple #contents content)))
         (define (get-list name)
            (get contents (fetch-entry lists (tuple #name name))))
         (add-list 0 (list 1 2 3 4 5))
         (add-list 1 (list 1 2 3))
         (list      (get-list 0)
                    (get-list 1))
        ";

    let mut test2 = test1.to_string();
    test2.push_str("(add-list 2 (list 1 2 3 4 5 6))");

    let expected = || {
        let list1 = Value::new_list(vec![
            Value::Int(1),
            Value::Int(2),
            Value::Int(3),
            Value::Int(4),
            Value::Int(5)])?;
        let list2 = Value::new_list(vec![
            Value::Int(1),
            Value::Int(2),
            Value::Int(3)])?;
        Value::new_list(vec![list1, list2])
    };
    
    assert_eq!(expected(), execute(test1));

    let expected_error = match execute(&test2) {
        Err(Error::TypeError(_,_)) => true,
        _ => false
    };

    assert!(expected_error);
}


#[test]
fn bad_tuples() {
    let test1 = "(tuple #name 1 #name 3)";
    let test2 = "(tuple #name 'null)";
    let test3 = "(get value (tuple #name 1))";
    let test4 = "(define-map lists ((name int)) ((contents list-int-0-5)))";

    let matched = match execute(test1) {
        Err(Error::InvalidArguments(_)) => true,
        _ => false
    };
    assert!(matched);

    let matched2 = match execute(test2) {
        Err(Error::InvalidArguments(_)) => true,
        _ => false
    };

    assert!(matched2);

    let expected = Err(Error::InvalidArguments(
        "No such field \"value\" in tuple".to_string()));
    assert_eq!(expected, execute(test3));


    let expected_bad_list = Err(Error::InvalidArguments(
        "Cannot construct list of dimension 0".to_string()));
    assert_eq!(expected_bad_list, execute(test4));    
}
