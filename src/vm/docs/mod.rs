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

struct SpecialAPI {
    output_type: &'static str,
    input_type: &'static str,
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
                    format!("{}, ...", in_type)
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

const IF_API: SpecialAPI = SpecialAPI {
    input_type: "bool, A, A",
    output_type: "A",
    signature: "(if bool1 expr1 expr2)",
    description: "The `if` function admits a boolean argument and two expressions 
which must return the same type. In the case that the boolean input is `true`, the
`if` function evaluates and returns `expr1`. If the boolean input is `false`, the
`if` function evaluates and returns `expr2`.",
    example: "(if true 1 2) => 1
(if (> 1 2) 1 2) => 2"
};

const LET_API: SpecialAPI = SpecialAPI {
    input_type: "((name2 AnyType) (name2 AnyType) ...), A",
    output_type: "A",
    signature: "(let ((name1 expr1) (name2 expr2) ...) expr-body)",
    description: "The `let` function accepts a list of `variable name` and `expression` pairs,
evaluating each expression and _binding_ it to the corresponding variable name. The _context_
created by this set of bindings is used for evaluating and return the value of `expr-body`.",
    example: "(let ((a 2) (b (+ 5 6 7))) (+ a b)) => 20"
};

const MAP_API: SpecialAPI = SpecialAPI {
    input_type: "Function(A) -> B, (list A)",
    output_type: "(list B)",
    signature: "(map func list)",
    description: "The `map` function applies the input function `func` to each element of the
input list, and outputs a list containing the _outputs_ from those function applications.",
    example: "(map not (list true false true false)) -> false true false true"
};

const FOLD_API: SpecialAPI = SpecialAPI {
    input_type: "Function(A, B) -> B, (list A)",
    output_type: "B",
    signature: "(fold func list initial-value)",
    description: "The `fold` function applies the input function `func` to each element of the
input list _and_ the output of the previous application of the `fold` function. When invoked on
the first list element, it uses the `initial-value` as the second input. `fold` returns the last
value return by the successive applications.",
    example: "(fold * (list 2 2 2) 1) => 8
(fold * (list 2 2 2) 0) => 0"
};

const LIST_API: SpecialAPI = SpecialAPI {
    input_type: "A, ...",
    output_type: "(list A)",
    signature: "(list expr1 expr2 expr3 ...)",
    description: "The `list` function constructs a list composed of the inputted values. Each
supplied value must be of the same type.",
    example: "(list (+ 1 2) 4 5) => [3 4 5]",
};

const BEGIN_API: SpecialAPI = SpecialAPI {
    input_type: "AnyType, ... A",
    output_type: "A",
    signature: "(begin expr1 expr2 expr3 ... expr-last)",
    description: "The `begin` function evaluates each of its input expressions, returning the
return value of the last such expression.",
    example: "(begin (+ 1 2) 4 5) => 5",
};

const PRINT_API: SpecialAPI = SpecialAPI {
    input_type: "A",
    output_type: "A",
    signature: "(print expr)",
    description: "The `print` function evaluates and returns its input expression. On blockstack-core
nodes configured for development (as opposed to production mining nodes), this function will also
cause blockstack-core to print the resulting value to STDOUT.",
    example: "(print (+ 1 2 3)) => 6",
};

const FETCH_API: SpecialAPI = SpecialAPI {
    input_type: "MapName, Tuple",
    output_type: "Tuple|Void",
    signature: "(fetch-entry map-name key-tuple)",
    description: "The `fetch-entry` function looks up and returns an entry from a contract's data map.
The value is looked up using `key-tuple`. If there is no value associated with that key in the data
map, the function returns Void.",
    example: "(fetch-entry names-map (tuple (name \"blockstack\"))) => (tuple (id 1337))",
};

const SET_API: SpecialAPI = SpecialAPI {
    input_type: "MapName, TupleA, TupleB",
    output_type: "Void",
    signature: "(set-entry! map-name key-tuple value-tuple)",
    description: "The `set-entry!` function sets the value associated with the input key to the 
inputted value. This function performs a _blind_ update; whether or not a value is already associated
with the key, the function overwrites that existing association.",
    example: "(set-entry! names-map (tuple (name \"blockstack\")) (tuple (id 1337))) => Void",
};

const INSERT_API: SpecialAPI = SpecialAPI {
    input_type: "MapName, TupleA, TupleB",
    output_type: "bool",
    signature: "(insert-entry! map-name key-tuple value-tuple)",
    description: "The `insert-entry!` function sets the value associated with the input key to the 
inputted value if and only if there is not already a value associated with the key in the map.
In the event that an insert occurred, the function returns `true`. If a value already existed for
this key in the data map, the function returns `false`.",
    example: "(insert-entry! names-map (tuple (name \"blockstack\")) (tuple (id 1337))) => true
(insert-entry! names-map (tuple (name \"blockstack\")) (tuple (id 1337))) => false
",
};

const DELETE_API: SpecialAPI = SpecialAPI {
    input_type: "MapName, Tuple",
    output_type: "bool",
    signature: "(delete-entry! map-name key-tuple)",
    description: "The `delete-entry!` function removes the value associated with the input key for
the given map. In the event that an item existed, and was removed, the function returns `true`.
If a value did not exist for this key in the data map, the function returns `false`.",
    example: "(delete-entry! names-map (tuple (name \"blockstack\"))) => true
(delete-entry! names-map (tuple (name \"blockstack\"))) => false
",
};

const FETCH_CONTRACT_API: SpecialAPI = SpecialAPI {
    input_type: "ContractName, MapName, Tuple",
    output_type: "Tuple|Void",
    signature: "(fetch-contract-entry contract-name map-name key-tuple)",
    description: "The `fetch-contract-entry` function looks up and returns an entry from a
contract other than the current contract's data map. The value is looked up using `key-tuple`.
If there is no value associated with that key in the data map, the function returns Void.",
    example: "(fetch-contract-entry names-contract names-map (tuple (name \"blockstack\"))) => (tuple (id 1337))",
};

const TUPLE_CONS_API: SpecialAPI = SpecialAPI {
    input_type: "(list (KeyName AnyType))",
    output_type: "Tuple",
    signature: "(tuple ((key0 expr0) (key1 expr1) ...))",
    description: "The `tuple` function constructs a typed tuple from the supplied key and expression pairs.
Typed tuples can be used as inputs to the `get` function, which selects specific values from a given tuple.
Key names may not appear multiple times in the same tuple definition. Supplied expressions are evaluated and
associated with the expressions' paired key name.",
    example: "(tuple (name \"blockstack\") (id 1337))"
};

const TUPLE_GET_API: SpecialAPI = SpecialAPI {
    input_type: "KeyName, Tuple|Void",
    output_type: "AnyType",
    signature: "(get key-name tuple)",
    description: "The `get` function fetches the value associated with a given key from the supplied typed tuple.
If a Void value is supplied as the inputted tuple, `get` returns Void.",
    example: "(get id (tuple (name \"blockstack\") (id 1337))) => 1337
(get id 'null) => 'null
"
};

const HASH160_API: SpecialAPI = SpecialAPI {
    input_type: "buff|int",
    output_type: "(buff 20)",
    signature: "(hash160 value)",
    description: "The `hash160` function computes RIPEMD160(SHA256(x)) of the inputted value.
If an integer (128 bit) is supplied the hash is computed over the little endian representation of the
integer.",
    example: "(hash160 0) => 0xe4352f72356db555721651aa612e00379167b30f"
};

const SHA256_API: SpecialAPI = SpecialAPI {
    input_type: "buff|int",
    output_type: "(buff 32)",
    signature: "(sha256 value)",
    description: "The `sha256` function computes SHA256(x) of the inputted value.
If an integer (128 bit) is supplied the hash is computer over the little endian representation of the
integer.",
    example: "(sha256 0) => 0x374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb"
};

const KECCAK256_API: SpecialAPI = SpecialAPI {
    input_type: "buff|int",
    output_type: "(buff 32)",
    signature: "(keccak256 value)",
    description: "The `keccak256` function computes KECCAK256(value) of the inputted value.
Note that this differs from the NIST SHA-3 (i.e. FIPS 202) standard. If an integer (128 bit) 
is supplied the hash is computer over the little endian representation of the integer.",
    example: "(keccak256 0) => 0xf490de2920c8a35fabeb13208852aa28c76f9be9b03a4dd2b3c075f7a26923b4"
};

const CONTRACT_CALL_API: SpecialAPI = SpecialAPI {
    input_type: "ContractName, PublicFunctionName, Arg0, ...",
    output_type: "BoolType",
    signature: "(contract-call! contract-name function-name arg0 arg1 ...)",
    description: "The `contract-call!` function executes the given public function of the given contract.
This function _may not_ be used to call a public function defined in the current contract. If the public
function returns _false_, any database changes resulting from calling `contract-call!` are aborted.
If the function returns _true_, database changes have occurred.",
    example: "(contract-call! tokens transfer 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 19) => 'true"
};

const AS_CONTRACT_API: SpecialAPI = SpecialAPI {
    input_type: "A",
    output_type: "A",
    signature: "(as-contract expr)",
    description: "The `as-contract` function switches the current context's `tx-sender` value to the _contract's_ 
principal, and executes `expr` with that context. It returns the resulting value of `expr`.",
    example: "(as-contract (print tx-sender)) => 'CTcontract.name"
};

const GET_BLOCK_INFO_API: SpecialAPI = SpecialAPI {
    input_type: "BlockInfoPropertyName, BlockHeightInt",
    output_type: "buff|int",
    signature: "(get-block-info prop-name block-height-expr)",
    description: "The `get-block-info` function fetches data for a block of the given block height. The 
value and type returned is determined by the specified property name. If the provided block height integer does
not correspond to an existing block, the function is aborted. The currently available property names 
are `time`, `header-hash`, and `vrf-seed`. 

The `time` property returns an integer value of the block header time field. This is a Unix epoch timestamp in seconds 
which roughly corresponds to when the block was mined. Warning: this does not increase monotonically with each block
and block times are accurate only to within two hours. See BIP113 for more information. 

The `header-hash` property returns a 32-byte buffer. The `vrf-seed` property returns a 32-byte buffer. 
",
    example: "(get-block-info time 10) => 1557860301
(get-block-info header-hash 2) => 0x374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb
(get-block-info vrf-seed 6) => 0xf490de2920c8a35fabeb13208852aa28c76f9be9b03a4dd2b3c075f7a26923b4
"
};


fn make_for_special(api: &SpecialAPI) -> FunctionAPI {
    FunctionAPI {
        input_type: api.input_type.to_string(),
        output_type: api.output_type.to_string(),
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
        If => make_for_special(&IF_API),
        Let => make_for_special(&LET_API),
        Map => make_for_special(&MAP_API),
        Fold => make_for_special(&FOLD_API),
        ListCons => make_for_special(&LIST_API),
        FetchEntry => make_for_special(&FETCH_API),
        FetchContractEntry => make_for_special(&FETCH_CONTRACT_API),
        SetEntry => make_for_special(&SET_API),
        InsertEntry => make_for_special(&INSERT_API),
        DeleteEntry => make_for_special(&DELETE_API),
        TupleCons => make_for_special(&TUPLE_CONS_API),
        TupleGet => make_for_special(&TUPLE_GET_API),
        Begin => make_for_special(&BEGIN_API),
        Hash160 => make_for_special(&HASH160_API),
        Sha256 => make_for_special(&SHA256_API),
        Keccak256 => make_for_special(&KECCAK256_API),
        Print => make_for_special(&PRINT_API),
        ContractCall => make_for_special(&CONTRACT_CALL_API),
        AsContract => make_for_special(&AS_CONTRACT_API),
        GetBlockInfo => make_for_special(&GET_BLOCK_INFO_API),
    }
}

pub fn make_json_api_reference() -> String {
    use vm::functions::NativeFunctions::*;
    let natives = [ Add, Subtract, Multiply, Divide, CmpGeq, CmpLeq, CmpLess, CmpGreater, Modulo, Power,
                    BitwiseXOR, And, Or, Not, Equals ];
    let json_references: Vec<_> = natives.iter()
        .map(|x| make_api_reference(x))
        .collect();
    format!("{}", serde_json::to_string(&json_references)
            .expect("Failed to serialize documentation"))
}
