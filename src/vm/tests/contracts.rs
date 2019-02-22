use vm::errors::Error;
use vm::types::{Value};
use vm::contexts::{MemoryGlobalContext};
use vm::representations::SymbolicExpression;
use vm::contracts::Contract;

fn symbols_from_values(mut vec: Vec<Value>) -> Vec<SymbolicExpression> {
    vec.drain(..).map(|value| SymbolicExpression::AtomValue(value)).collect()
}

#[test]
fn test_factorial_contract() {
    let contract_defn =
        "(define-map factorials ((id int)) ((current int) (index int)))
         (define (init-factorial id factorial)
           (insert-entry! factorials (tuple #id id) (tuple #current 1 #index factorial)))
         (define-public (compute (id int))
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
        (begin (init-factorial 1337 3)
               (init-factorial 8008 5)
               'null)
        ";


    let mut global_context = MemoryGlobalContext::new();
    let mut contract = Contract::initialize(contract_defn).unwrap();

    let tx_name = "compute";
    let arguments_to_test = [symbols_from_values(vec![Value::Int(1337)]),  
                             symbols_from_values(vec![Value::Int(1337)]),
                             symbols_from_values(vec![Value::Int(1337)]),
                             symbols_from_values(vec![Value::Int(1337)]),
                             symbols_from_values(vec![Value::Int(1337)]),
                             symbols_from_values(vec![Value::Int(8008)]),
                             symbols_from_values(vec![Value::Int(8008)]),
                             symbols_from_values(vec![Value::Int(8008)]),
                             symbols_from_values(vec![Value::Int(8008)]),
                             symbols_from_values(vec![Value::Int(8008)]),
                             symbols_from_values(vec![Value::Int(8008)])];


    let expected = vec![
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
    ];
        
    let sender = Value::Principal(1, [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]);

    arguments_to_test.iter().zip(expected.iter())
        .for_each(|(arguments, expectation)| assert_eq!(Ok(expectation.clone()),
                                                        contract.execute_transaction(
                                                            &sender,
                                                            &tx_name,
                                                            arguments,
                                                            &mut global_context)));

    let err_result = contract.execute_transaction(&sender, &"init-factorial",
                                                  &symbols_from_values(vec![Value::Int(9000),
                                                                            Value::Int(15)]),
                                                  &mut global_context);
    match err_result {
        Err(Error::Undefined(_)) => {},
        _ => {
            println!("{:?}", err_result);
            assert!(false, "Attempt to call init-factorial should fail!")
        }
    }

    let err_result = contract.execute_transaction(&sender, &"compute",
                                                  &symbols_from_values(vec![Value::Void]),
                                                  &mut global_context);
    match err_result {
        Err(Error::TypeError(_, _)) => {},
        _ => {
            println!("{:?}", err_result);
            assert!(false, "Attempt to call compute with void type should fail!")
        }
    }

}
