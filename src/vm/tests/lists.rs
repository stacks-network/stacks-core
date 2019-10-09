use vm::types::{Value, TypeSignature};
use vm::types::TypeSignature::{IntType, BoolType};

use vm::execute;
use vm::errors::{CheckErrors, RuntimeErrorType, Error};

#[test]
fn test_simple_list_admission() {
    let defines =
        "(define-private (square (x int)) (* x x))
         (define-private (square-list (x (list 4 int))) (map square x))";
    let t1 = format!("{} (square-list (list 1 2 3 4))", defines);
    let t2 = format!("{} (square-list (list))", defines);
    let t3 = format!("{} (square-list (list 1 2 3 4 5))", defines);
    

    let expected = Value::list_from(vec![
        Value::Int(1),
        Value::Int(4),
        Value::Int(9),
        Value::Int(16)]).unwrap();

    assert_eq!(expected, execute(&t1).unwrap().unwrap());
    assert_eq!(Value::list_from(vec![]).unwrap(), execute(&t2).unwrap().unwrap());
    let err = execute(&t3).unwrap_err();
    assert!(match err {
        Error::Unchecked(CheckErrors::TypeValueError(_, _)) => true,
        _ => {
            eprintln!("Expected TypeError, but found: {:?}", err);
            false
        }
    });
}

#[test]
fn test_simple_map_list() {
    let test1 =
        "(define-private (square (x int)) (* x x))
         (map square (list 1 2 3 4))";

    let expected = Value::list_from(vec![
        Value::Int(1),
        Value::Int(4),
        Value::Int(9),
        Value::Int(16)]).unwrap();

    assert_eq!(expected, execute(test1).unwrap().unwrap());

    // let's test lists of lists.
    let test2 = "(define-private (multiply (x int) (acc int)) (* x acc))
                 (define-private (multiply-all (x (list 10 int))) (fold multiply x 1))
                 (map multiply-all (list (list 1 1 1) (list 2 2 1) (list 3 3) (list 2 2 2 2)))";
    assert_eq!(expected, execute(test2).unwrap().unwrap());

    // let's test empty lists.
    let test2 = "(define-private (double (x int)) (* x 2))
                 (map double (list))";
    assert_eq!(Value::list_from(vec![]).unwrap(), execute(test2).unwrap().unwrap());
}

// todo(ludo): test failing cases (append "123" "23"), etc.

#[test]
fn test_simple_map_append() {
    let test1 =
        "(append (list 1 2) 6)";

    let expected = Value::list_from(vec![
        Value::Int(1),
        Value::Int(2),
        Value::Int(6)]).unwrap();
    assert_eq!(expected, execute(test1).unwrap().unwrap());
}

#[test]
fn test_simple_buff_append() {
    let test1 =
        "(append \"012\" \"4\")";

    let expected = Value::buff_from(vec![48, 49, 50, 52]).unwrap();
    assert_eq!(expected, execute(test1).unwrap().unwrap());
}

#[test]
fn test_simple_map_concat() {
    let test1 =
        "(concat (list 1 2) (list 4 8))";

    let expected = Value::list_from(vec![
        Value::Int(1),
        Value::Int(2),
        Value::Int(4),
        Value::Int(8)]).unwrap();
    assert_eq!(expected, execute(test1).unwrap().unwrap());
}

#[test]
fn test_simple_buff_concat() {
    let test1 =
        "(concat \"012\" \"34\")";

    let expected = Value::buff_from(vec![48, 49, 50, 51, 52]).unwrap();
    assert_eq!(expected, execute(test1).unwrap().unwrap());
}

#[test]
fn test_simple_buff_assert_max_len() {
    let test1 =
        "(asserts-max-len! \"123\" u3)";

    let expected = Value::buff_from(vec![49, 50, 51]).unwrap();
    assert_eq!(expected, execute(test1).unwrap().unwrap());
}

#[test]
fn test_simple_list_assert_max_len() {
    let test1 =
        "(asserts-max-len! (list 1 2 3) u3)";

    let expected = Value::list_from(vec![
        Value::Int(1),
        Value::Int(2),
        Value::Int(3)]).unwrap();
    assert_eq!(expected, execute(test1).unwrap().unwrap());
}

#[test]
fn test_simple_map_buffer() {
    let test1 =
        "(define-private (incr (x (buff 1))) \"1\")
         (map incr \"0000\")";

    let expected = Value::list_from(vec![
        Value::buff_from(vec![49]).unwrap(), 
        Value::buff_from(vec![49]).unwrap(), 
        Value::buff_from(vec![49]).unwrap(), 
        Value::buff_from(vec![49]).unwrap()]).unwrap();
    assert_eq!(expected, execute(test1).unwrap().unwrap());
}


#[test]
fn test_simple_filter_list() {
    let test1 = "(define-private (test (x int)) (eq? 0 (mod x 2)))
                 (filter test (list 1 2 3 4 5))";

    let bad_tests = [
        "(filter 123 (list 123))",     // must have function name supplied
        "(filter not (list 123) 3)",  // must be 2 args
        "(filter +)",  // must be 2 args
        "(filter not 'false)",       // must supply list
        "(filter - (list 1 2 3))"]; // must return bool


    let expected = Value::list_from(vec![
        Value::Int(2),
        Value::Int(4)]).unwrap();

    assert_eq!(expected, execute(test1).unwrap().unwrap());

    for t in bad_tests.iter() {
        execute(t).unwrap_err();
    }
}

#[test]
fn test_simple_filter_buffer() {
    let test1 = "(define-private (test (x (buff 1))) (not (eq? x \"0\")))
                 (filter test \"000123\")";

    let expected = Value::buff_from(vec![49, 50, 51]).unwrap();
    assert_eq!(expected, execute(test1).unwrap().unwrap());
}

#[test]
fn test_list_tuple_admission() {
    let test = 
        "(define-private (bufferize (x int)) (if (eq? x 1) \"abc\" \"ab\"))
         (define-private (tuplize (x int))
           (tuple (value (bufferize x))))
         (map tuplize (list 0 1 0 1 0 1))";

    let expected_type = 
        "(list (tuple (value \"012\"))
               (tuple (value \"012\"))
               (tuple (value \"012\"))
               (tuple (value \"012\"))
               (tuple (value \"012\"))
               (tuple (value \"012\")))";

    let not_expected_type = 
        "(list (tuple (value \"01\"))
               (tuple (value \"02\"))
               (tuple (value \"12\"))
               (tuple (value \"12\"))
               (tuple (value \"01\"))
               (tuple (value \"02\")))";

    
    let result_type = TypeSignature::type_of(&execute(test).unwrap().unwrap());
    let expected_type = TypeSignature::type_of(&execute(expected_type).unwrap().unwrap());
    let testing_value = &execute(not_expected_type).unwrap().unwrap();
    let not_expected_type = TypeSignature::type_of(testing_value);

    assert_eq!(expected_type, result_type);
    assert!(not_expected_type != result_type);
    assert!(result_type.admits(&testing_value));
}

#[test]
fn test_simple_folds_list() {
    let test1 =
        "(define-private (multiply-all (x int) (acc int)) (* x acc))
         (fold multiply-all (list 1 2 3 4) 1)";

    let expected = Value::Int(24);

    assert_eq!(expected, execute(test1).unwrap().unwrap());
}

#[test]
fn test_simple_folds_buffer() {
    let test1 =
        "(define-private (get-len (x (buff 1)) (acc int)) (+ acc 1))
         (fold get-len \"blockstack\" 0)";

    let expected = Value::Int(10);

    assert_eq!(expected, execute(test1).unwrap().unwrap());
}

#[test]
fn test_list_len() {
    let test1 = "(len (list 1 2 3 4))";
    let expected = Value::UInt(4);
    assert_eq!(expected, execute(test1).unwrap().unwrap());
}

#[test]
fn test_buff_len() {
    let test1 = "(len \"blockstack\")";
    let expected = Value::UInt(10);
    assert_eq!(expected, execute(test1).unwrap().unwrap());
}


#[test]
fn test_construct_bad_list() {
    let test1 = "(list 1 2 3 'true)";
    assert_eq!(execute(test1).unwrap_err(), 
               CheckErrors::TypeError(IntType, BoolType).into());

    let test2 = "(define-private (bad-function (x int)) (if (eq? x 1) 'true x))
                 (map bad-function (list 0 1 2 3))";
    assert_eq!(execute(test2).unwrap_err(),
               CheckErrors::TypeError(IntType, BoolType).into());

    let bad_2d_list = "(list (list 1 2 3) (list 'true 'false 'true))";
    let bad_high_order_list = "(list (list 1 2 3) (list (list 1 2 3)))";

    assert_eq!(execute(bad_2d_list).unwrap_err(),
               CheckErrors::TypeError(IntType, BoolType).into());
    assert_eq!(execute(bad_high_order_list).unwrap_err(),
               CheckErrors::TypeError(IntType, 
                                      TypeSignature::from("(list 3 int)")).into());
}

#[test]
fn test_eval_func_arg_panic() {
    let test1 = "(fold (lambda (x y) (* x y)) (list 1 2 3 4) 1)";
    let e: Error = CheckErrors::ExpectedName.into();
    assert_eq!(e, execute(test1).unwrap_err());

    let test2 = "(map (lambda (x) (* x x)) (list 1 2 3 4))";
    let e: Error = CheckErrors::ExpectedName.into();
    assert_eq!(e, execute(test2).unwrap_err());

    let test3 = "(map square (list 1 2 3 4) 2)";
    let e: Error = CheckErrors::IncorrectArgumentCount(2, 3).into();
    assert_eq!(e, execute(test3).unwrap_err());

    let test4 = "(define-private (multiply-all (x int) (acc int)) (* x acc))
         (fold multiply-all (list 1 2 3 4))";
    let e: Error = CheckErrors::IncorrectArgumentCount(3, 2).into();
    assert_eq!(e, execute(test4).unwrap_err());
}
