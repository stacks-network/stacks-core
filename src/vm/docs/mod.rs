use vm::functions::NativeFunctions;
use vm::checker::typecheck::{FunctionType, TypedNativeFunction};
use vm::checker::typecheck::natives::SimpleNativeFunction;

#[derive(Serialize, Deserialize)]
struct FunctionAPI {
    input_type: String,
    output_type: String,
    signature: String,
    description: String,
    example: String
}

struct SimpleFunctionAPI {
    signature: &'static str,
    description: &'static str,
    example: &'static str,
}

const ADD_API: SimpleFunctionAPI = SimpleFunctionAPI {
    signature: "(+ i1 i2...)",
    description: "Adds a variable number of integer inputs and returns the result. In the event of an _overflow_, throws a runtime error.",
    example: "(+ 1 2 3) => 6"
};

const SUB_API: SimpleFunctionAPI = SimpleFunctionAPI {
    signature: "(- i1 i2...)",
    description: "Subtracts a variable number of integer inputs and returns the result. In the event of an _underflow_, throws a runtime error.",
    example: "(- 2 1 1) => 0
(- 0 3) => -3
"
};

const DIV_API: SimpleFunctionAPI = SimpleFunctionAPI {
    signature: "(/ i1 i2...)",
    description: "Integer divides a variable number of integer inputs and returns the result. In the event of division by zero, throws a runtime error.",
    example: "(/ 2 3) => 0
(/ 5 2) => 2
(/ 4 2 2) => 1
"
};

const MUL_API: SimpleFunctionAPI = SimpleFunctionAPI {
    signature: "(* i1 i2...)",
    description: "Multiplies a variable number of integer inputs and returns the result. In the event of an _overflow_, throws a runtime error.",
    example: "(* 2 3) => 6
(* 5 2) => 10
(* 2 2 2) => 8
"
};

const MOD_API: SimpleFunctionAPI = SimpleFunctionAPI {
    signature: "(mod i1 i2)",
    description: "Returns the integer remainder from integer dividing i1 by i2. In the event of a division by zero, throws a runtime error.",
    example: "(mod 2 3) => 0
(mod 5 2) => 1
(mod 7 1) => 0
"
};

const POW_API: SimpleFunctionAPI = SimpleFunctionAPI {
    signature: "(pow i1 i2)",
    description: "Returns the result of raising i1 to the power of i2. In the event of an _overflow_, throws a runtime error.",
    example: "(pow 2 3) => 8
(pow 2 2) => 4
(pow 7 1) => 7
"
};

const XOR_API: SimpleFunctionAPI = SimpleFunctionAPI {
    signature: "(xor i1 i2)",
    description: "Returns the result of bitwise exclusive or'ing i1 with i2.",
    example: "(xor 1 2) => 3
(xor 120 280) => 352
"
};

const AND_API: SimpleFunctionAPI = SimpleFunctionAPI {
    signature: "(and b1 b2 ...)",
    description: "Returns true if all boolean inputs are true. Importantly, the supplied arguments are evaluated in-order and lazily, such that if one of the arguments returns false, no subsequent arguments are evaluated.",
    example: "(and 'true 'false) => false
(and (eq? (+ 1 2) 1) (eq? 4 4)) => false
(and (eq? (+ 1 2) 3) (eq? 4 4)) => true
"
};

const OR_API: SimpleFunctionAPI = SimpleFunctionAPI {
    signature: "(or b1 b2 ...)",
    description: "Returns true if any boolean inputs are true. Importantly, the supplied arguments are evaluated in-order and lazily, such that if one of the arguments returns true, no subsequent arguments are evaluated.",
    example: "(or 'true 'false) => true
(or (eq? (+ 1 2) 1) (eq? 4 4)) => true
(or (eq? (+ 1 2) 1) (eq? 3 4)) => false
(or (eq? (+ 1 2) 3) (eq? 4 4)) => true
"
};

const NOT_API: SimpleFunctionAPI = SimpleFunctionAPI {
    signature: "(not b1)",
    description: "Returns the inverse of the boolean input.",
    example: "(not 'true) => false
(not (eq? 1 2)) => true
"
};

const GEQ_API: SimpleFunctionAPI = SimpleFunctionAPI {
    signature: "(>= i1 i2)",
    description: "Compares two integers, returning true if i1 is greater than or equal to i2 and false otherwise.",
    example: "(>= 1 1) => true
(>= 5 2) => true
"
};

const LEQ_API: SimpleFunctionAPI = SimpleFunctionAPI {
    signature: "(> i1 i2)",
    description: "Compares two integers, returning true if i1 is less than or equal to i2 and false otherwise.",
    example: "(<= 1 1) => true
(<= 5 2) => false
"
};

const EQUALS_API: SimpleFunctionAPI = SimpleFunctionAPI {
    signature: "(eq? v1 v2...)",
    description: "Compares the inputted values, returning true if they are all equal. Note that _unlike_ the `(and ...)` function, `(eq? ...)` will _not_ short-circuit.",
    example: "(eq? 1 1) => true
(eq? 1 'null) => false
(eq? \"abc\" 234 234) => false
"
};

const GREATER_API: SimpleFunctionAPI = SimpleFunctionAPI {
    signature: "(> i1 i2)",
    description: "Compares two integers, returning true if i1 is greater than i2 and false otherwise.",
    example: "(> 1 2) => false
(> 5 2) => true
"
};

const LESS_API: SimpleFunctionAPI = SimpleFunctionAPI {
    signature: "(< i1 i2)",
    description: "Compares two integers, returning true if i1 is less than i2 and false otherwise.",
    example: "(< 1 2) => true
(< 5 2) => false
"
};

fn make_for_simple_native(api: &SimpleFunctionAPI, function: &NativeFunctions) -> FunctionAPI {
    let (input_type, output_type) = {
        if let TypedNativeFunction::Simple(SimpleNativeFunction(function_type)) = TypedNativeFunction::type_native_function(&function) {
            let input_type = match function_type {
                FunctionType::Variadic(ref in_type, _) => {
                    format!("{} ...", in_type)
                },
                FunctionType::Fixed(ref in_types, _) => {
                    let in_types: Vec<String> = in_types.iter().map(|x| format!("{}", x)).collect();
                    in_types.join(", ")
                },
            };
            let output_type = match function_type {
                FunctionType::Variadic(_, ref out_type) => {
                    format!("{}", out_type)
                },
                FunctionType::Fixed(_, ref out_type) => {
                    format!("{}", out_type)
            },
            };
            (input_type, output_type)
        } else {
            panic!("Attempted to auto-generate docs for non-simple native function.")
        }
    };

    FunctionAPI {
        input_type: input_type,
        output_type: output_type,
        signature: api.signature.to_string(),
        description: api.description.to_string(),
        example: api.example.to_string()
    }
}

fn make_api_reference(function: &NativeFunctions) -> FunctionAPI {
    use vm::functions::NativeFunctions::*;
    match function {
        Add => make_for_simple_native(&ADD_API, &Add),
        Subtract => make_for_simple_native(&SUB_API, &Subtract),
        Multiply => make_for_simple_native(&MUL_API, &Multiply),
        Divide => make_for_simple_native(&DIV_API, &Divide),
        CmpGeq => make_for_simple_native(&GEQ_API, &CmpGeq),
        CmpLeq => make_for_simple_native(&LEQ_API, &CmpLeq),
        CmpLess => make_for_simple_native(&LESS_API, &CmpLess),
        CmpGreater => make_for_simple_native(&GREATER_API, &CmpGreater),
        Modulo => make_for_simple_native(&MOD_API, &Modulo),
        Power => make_for_simple_native(&POW_API, &Power),
        BitwiseXOR => make_for_simple_native(&XOR_API, &BitwiseXOR),
        And => make_for_simple_native(&AND_API, &And),
        Or => make_for_simple_native(&OR_API, &Or),
        Not => make_for_simple_native(&NOT_API, &Not),
        Equals => make_for_simple_native(&EQUALS_API, &Equals),
        If => panic!("NotImplemeneted"),
        Let => panic!("NotImplemeneted"),
        Map => panic!("NotImplemeneted"),
        Fold => panic!("NotImplemeneted"),
        ListCons => panic!("NotImplemeneted"),
        FetchEntry => panic!("NotImplemeneted"),
        FetchContractEntry => panic!("NotImplemeneted"),
        SetEntry => panic!("NotImplemeneted"),
        InsertEntry => panic!("NotImplemeneted"),
        DeleteEntry => panic!("NotImplemeneted"),
        TupleCons => panic!("NotImplemeneted"),
        TupleGet => panic!("NotImplemeneted"),
        Begin => panic!("NotImplemeneted"),
        Hash160 => panic!("NotImplemeneted"),
        Print => panic!("NotImplemeneted"),
        ContractCall => panic!("NotImplemeneted"),
        AsContract => panic!("NotImplemeneted"),
    }
}

pub fn make_json_api_reference() -> String {
    use vm::functions::NativeFunctions::*;
    let natives = [ Add, Subtract, Multiply, Divide, CmpGeq, CmpLeq, CmpLess, CmpGreater, Modulo, Power,
                    BitwiseXOR, And, Or, Not, Equals ];
    let json_references: Vec<String> = natives.iter()
        .map(|x| make_api_reference(x))
        .map(|x| serde_json::to_string(&x)
             .expect("Failed to serialize documentation"))
        .collect();
    format!("[{}]", json_references.join(",\n"))
}
