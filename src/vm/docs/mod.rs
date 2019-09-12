use vm::functions::{NativeFunctions};
use vm::functions::define::{DefineFunctions};
use vm::variables::{NativeVariables};
use vm::types::{FunctionType, FixedFunction};
use vm::analysis::type_checker::{TypedNativeFunction};
use vm::analysis::type_checker::natives::SimpleNativeFunction;

#[derive(Serialize)]
struct ReferenceAPIs {
    functions: Vec<FunctionAPI>,
    keywords: Vec<KeywordAPI>
}

#[derive(Serialize, Clone)]
struct KeywordAPI {
    name: &'static str,
    output_type: &'static str,
    description: &'static str,
    example: &'static str
}

#[derive(Serialize)]
struct FunctionAPI {
    name: String,
    input_type: String,
    output_type: String,
    signature: String,
    description: String,
    example: String
}

struct SimpleFunctionAPI {
    name: Option<&'static str>,
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

struct DefineAPI {
    output_type: &'static str,
    input_type: &'static str,
    signature: &'static str,
    description: &'static str,
    example: &'static str,
}

const BLOCK_HEIGHT: KeywordAPI = KeywordAPI {
    name: "block-height",
    output_type: "int",
    description: "Returns the current block height of the Stacks blockchain as an int",
    example: "(> block-height 1000) ;; returns true if the current block-height has passed 1000 blocks."
};

const CONTRACT_CALLER_KEYWORD: KeywordAPI = KeywordAPI {
    name: "contract-caller",
    output_type: "principal",
    description: "Returns the caller of the current contract context. If this contract is the first one called by a signed transaction, 
the caller will be equal to the signing principal. If `contract-call!` was used to invoke a function from a new contract, `contract-caller`
changes to the _calling_ contract's principal. If `as-contract` is used to change the `tx-sender` context, `contract-caller` _also_ changes
to the same contract principal.",
    example: "(print contract-caller) ;; Will print out a Stacks address of the transaction sender",
};

const TX_SENDER_KEYWORD: KeywordAPI = KeywordAPI {
    name: "tx-sender",
    output_type: "principal",
    description: "Returns the original sender of the current transaction, or if `as-contract` was called to modify the sending context, it returns that
contract principal.",
    example: "(print tx-sender) ;; Will print out a Stacks address of the transaction sender",
};

const NONE_KEYWORD: KeywordAPI = KeywordAPI {
    name: "none",
    output_type: "(optional ?)",
    description: "Represents the _none_ option indicating no value for a given optional (analogous to a null value).",
    example: "
(define (only-if-positive (a int))
  (if (> a 0)
      (some a)
      none))
(only-if-positive 4) ;; Returns (some 4)
(only-if-positive (- 3)) ;; Returns none
"
};

const TO_UINT_API: SimpleFunctionAPI = SimpleFunctionAPI {
    name: None,
    signature: "(to-uint i)",
    description: "Tries to convert the `int` argument to a `uint`. Will cause a runtime error and abort if the supplied argument is negative.",
    example: "(to-uint 238) ;; Returns u238"
};

const TO_INT_API: SimpleFunctionAPI = SimpleFunctionAPI {
    name: None,
    signature: "(to-int u)",
    description: "Tries to convert the `uint` argument to an `int`. Will cause a runtime error and abort if the supplied argument is >= `pow(2, 127)`",
    example: "(to-int u238) ;; Returns 238"
};

const ADD_API: SimpleFunctionAPI = SimpleFunctionAPI {
    name: Some("+ (add)"),
    signature: "(+ i1 i2...)",
    description: "Adds a variable number of integer inputs and returns the result. In the event of an _overflow_, throws a runtime error.",
    example: "(+ 1 2 3) ;; Returns 6"
};

const SUB_API: SimpleFunctionAPI = SimpleFunctionAPI {
    name: Some("- (subtract)"),
    signature: "(- i1 i2...)",
    description: "Subtracts a variable number of integer inputs and returns the result. In the event of an _underflow_, throws a runtime error.",
    example: "(- 2 1 1) ;; Returns 0
(- 0 3) ;; Returns -3
"
};

const DIV_API: SimpleFunctionAPI = SimpleFunctionAPI {
    name: Some("/ (divide)"),
    signature: "(/ i1 i2...)",
    description: "Integer divides a variable number of integer inputs and returns the result. In the event of division by zero, throws a runtime error.",
    example: "(/ 2 3) ;; Returns 0
(/ 5 2) ;; Returns 2
(/ 4 2 2) ;; Returns 1
"
};

const MUL_API: SimpleFunctionAPI = SimpleFunctionAPI {
    name: Some("* (multiply)"),
    signature: "(* i1 i2...)",
    description: "Multiplies a variable number of integer inputs and returns the result. In the event of an _overflow_, throws a runtime error.",
    example: "(* 2 3) ;; Returns 6
(* 5 2) ;; Returns 10
(* 2 2 2) ;; Returns 8
"
};

const MOD_API: SimpleFunctionAPI = SimpleFunctionAPI {
    name: None,
    signature: "(mod i1 i2)",
    description: "Returns the integer remainder from integer dividing `i1` by `i2`. In the event of a division by zero, throws a runtime error.",
    example: "(mod 2 3) ;; Returns 0
(mod 5 2) ;; Returns 1
(mod 7 1) ;; Returns 0
"
};

const POW_API: SimpleFunctionAPI = SimpleFunctionAPI {
    name: None,
    signature: "(pow i1 i2)",
    description: "Returns the result of raising `i1` to the power of `i2`. In the event of an _overflow_, throws a runtime error.",
    example: "(pow 2 3) ;; Returns 8
(pow 2 2) ;; Returns 4
(pow 7 1) ;; Returns 7
"
};

const XOR_API: SimpleFunctionAPI = SimpleFunctionAPI {
    name: None,
    signature: "(xor i1 i2)",
    description: "Returns the result of bitwise exclusive or'ing `i1` with `i2`.",
    example: "(xor 1 2) ;; Returns 3
(xor 120 280) ;; Returns 352
"
};

const AND_API: SimpleFunctionAPI = SimpleFunctionAPI {
    name: None,
    signature: "(and b1 b2 ...)",
    description: "Returns `true` if all boolean inputs are `true`. Importantly, the supplied arguments are evaluated in-order and lazily. Lazy evaluation means that if one of the arguments returns `false`, the function short-circuits, and no subsequent arguments are evaluated.",
    example: "(and 'true 'false) ;; Returns 'false
(and (eq? (+ 1 2) 1) (eq? 4 4)) ;; Returns 'false
(and (eq? (+ 1 2) 3) (eq? 4 4)) ;; Returns 'true
"
};

const OR_API: SimpleFunctionAPI = SimpleFunctionAPI {
    name: None,
    signature: "(or b1 b2 ...)",
    description: "Returns `true` if any boolean inputs are `true`. Importantly, the supplied arguments are evaluated in-order and lazily. Lazy evaluation means that if one of the arguments returns `false`, the function short-circuits, and no subsequent arguments are evaluated.",
    example: "(or 'true 'false) ;; Returns 'true
(or (eq? (+ 1 2) 1) (eq? 4 4)) ;; Returns 'true
(or (eq? (+ 1 2) 1) (eq? 3 4)) ;; Returns 'false
(or (eq? (+ 1 2) 3) (eq? 4 4)) ;; Returns 'true
"
};

const NOT_API: SimpleFunctionAPI = SimpleFunctionAPI {
    name: None,
    signature: "(not b1)",
    description: "Returns the inverse of the boolean input.",
    example: "(not 'true) ;; Returns 'false
(not (eq? 1 2)) ;; Returns 'true
"
};

const GEQ_API: SimpleFunctionAPI = SimpleFunctionAPI {
    name: Some(">= (greater than or equal)"),
    signature: "(>= i1 i2)",
    description: "Compares two integers, returning `true` if `i1` is greater than or equal to `i2` and `false` otherwise.",
    example: "(>= 1 1) ;; Returns 'true
(>= 5 2) ;; Returns 'true
"
};

const LEQ_API: SimpleFunctionAPI = SimpleFunctionAPI {
    name: Some("<= (less than or equal)"),
    signature: "(<= i1 i2)",
    description: "Compares two integers, returning true if `i1` is less than or equal to `i2` and `false` otherwise.",
    example: "(<= 1 1) ;; Returns 'true
(<= 5 2) ;; Returns 'false
"
};

const GREATER_API: SimpleFunctionAPI = SimpleFunctionAPI {
    name: Some("> (greater than)"),
    signature: "(> i1 i2)",
    description: "Compares two integers, returning `true` if `i1` is greater than `i2` and false otherwise.",
    example: "(> 1 2) ;; Returns 'false
(> 5 2) ;; Returns 'true
"
};

const LESS_API: SimpleFunctionAPI = SimpleFunctionAPI {
    name: Some("< (less than)"),
    signature: "(< i1 i2)",
    description: "Compares two integers, returning `true` if `i1` is less than `i2` and `false` otherwise.",
    example: "(< 1 2) ;; Returns 'true
(< 5 2) ;; Returns 'false
"
};

fn make_for_simple_native(api: &SimpleFunctionAPI, function: &NativeFunctions, name: String) -> FunctionAPI {
    let (input_type, output_type) = {
        if let TypedNativeFunction::Simple(SimpleNativeFunction(function_type)) = TypedNativeFunction::type_native_function(&function) {
            let input_type = match function_type {
                FunctionType::Variadic(ref in_type, _) => {
                    format!("{}, ...", in_type)
                },
                FunctionType::Fixed(FixedFunction{ ref args, .. }) => {
                    let in_types: Vec<String> = args.iter().map(|x| format!("{}", x.signature)).collect();
                    in_types.join(", ")
                },
                FunctionType::UnionArgs(ref in_types, _) => {
                    let in_types: Vec<String> = in_types.iter().map(|x| format!("{}", x)).collect();
                    in_types.join(" | ")
                },
                FunctionType::ArithmeticVariadic => "int, ... | uint, ...".to_string(),
                FunctionType::ArithmeticBinary | FunctionType::ArithmeticComparison => "int, int | uint, uint".to_string(),
            };
            let output_type = match function_type {
                FunctionType::Variadic(_, ref out_type) => format!("{}", out_type),
                FunctionType::Fixed(FixedFunction{ ref returns, .. }) => format!("{}", returns),
                FunctionType::UnionArgs(_, ref out_type) => format!("{}", out_type),
                FunctionType::ArithmeticVariadic | FunctionType::ArithmeticBinary => "int | uint".to_string(),
                FunctionType::ArithmeticComparison => "bool".to_string(),
            };
            (input_type, output_type)
        } else {
            panic!("Attempted to auto-generate docs for non-simple native function: {:?}", api.name)
        }
    };

    FunctionAPI {
        name: api.name.map_or(name, |x| x.to_string()),
        input_type: input_type,
        output_type: output_type,
        signature: api.signature.to_string(),
        description: api.description.to_string(),
        example: api.example.to_string()
    }
}

const EQUALS_API: SpecialAPI = SpecialAPI {
    input_type: "A, A, ...",
    output_type: "bool",
    signature: "(eq? v1 v2...)",
    description: "Compares the inputted values, returning `true` if they are all equal. Note that _unlike_ the `(and ...)` function, `(eq? ...)` will _not_ short-circuit.",
    example: "(eq? 1 1) ;; Returns 'true
(eq? 1 'false) ;; Returns 'false
(eq? \"abc\" 234 234) ;; Returns 'false
"
};

const IF_API: SpecialAPI = SpecialAPI {
    input_type: "bool, A, A",
    output_type: "A",
    signature: "(if bool1 expr1 expr2)",
    description: "The `if` function admits a boolean argument and two expressions 
which must return the same type. In the case that the boolean input is `true`, the
`if` function evaluates and returns `expr1`. If the boolean input is `false`, the
`if` function evaluates and returns `expr2`.",
    example: "(if true 1 2) ;; Returns 1
(if (> 1 2) 1 2) ;; Returns 2"
};

const LET_API: SpecialAPI = SpecialAPI { 
    input_type: "((name2 AnyType) (name2 AnyType) ...), AnyType, ... A",
    output_type: "A",
    signature: "(let ((name1 expr1) (name2 expr2) ...) expr-body1 expr-body2 ... expr-body-last)",
    description: "The `let` function accepts a list of `variable name` and `expression` pairs,
evaluating each expression and _binding_ it to the corresponding variable name. The _context_
created by this set of bindings is used for evaluating its body expressions. The let expression returns the value of the last such body expression.",
    example: "(let ((a 2) (b (+ 5 6 7))) (print a) (print b) (+ a b)) ;; Returns 20"
};

const FETCH_VAR_API: SpecialAPI = SpecialAPI { 
    input_type: "VarName",
    output_type: "A",
    signature: "(var-get var-name)",
    description: "The `var-get` function looks up and returns an entry from a contract's data map.
The value is looked up using `var-name`.",
    example: "(var-get cursor) ;; Returns cursor"
};

const SET_VAR_API: SpecialAPI = SpecialAPI { 
    input_type: "VarName, AnyType",
    output_type: "bool",
    signature: "(var-set! var-name expr1)",
    description: "The `var-set!` function sets the value associated with the input variable to the 
inputted value.",
    example: "(var-set! cursor (+ cursor 1)) ;; Returns 'true"
};

const MAP_API: SpecialAPI = SpecialAPI {
    input_type: "Function(A) -> B, (list A)",
    output_type: "(list B)",
    signature: "(map func list)",
    description: "The `map` function applies the input function `func` to each element of the
input list, and outputs a list containing the _outputs_ from those function applications.",
    example: "(map not (list true false true false)) ;; Returns 'false true false true"
};

const FILTER_API: SpecialAPI = SpecialAPI {
    input_type: "Function(A) -> bool, (list A)",
    output_type: "(list A)",
    signature: "(filter func list)",
    description: "The `filter` function applies the input function `func` to each element of the
input list, and returns the same list with any elements removed for which the `func` returned `false`.",
    example: "(filter not (list true false true false)) ;; Returns (list false false)"
};

const FOLD_API: SpecialAPI = SpecialAPI {
    input_type: "Function(A, B) -> B, (list A)",
    output_type: "B",
    signature: "(fold func list initial-value)",
    description: "The `fold` function applies the input function `func` to each element of the
input list _and_ the output of the previous application of the `fold` function. When invoked on
the first list element, it uses the `initial-value` as the second input. `fold` returns the last
value return by the successive applications.",
    example: "(fold * (list 2 2 2) 1) ;; Returns 8
(fold * (list 2 2 2) 0) ;; Returns 0"
};

const LIST_API: SpecialAPI = SpecialAPI {
    input_type: "A, ...",
    output_type: "(list A)",
    signature: "(list expr1 expr2 expr3 ...)",
    description: "The `list` function constructs a list composed of the inputted values. Each
supplied value must be of the same type.",
    example: "(list (+ 1 2) 4 5) ;; Returns [3 4 5]",
};

const BEGIN_API: SpecialAPI = SpecialAPI {
    input_type: "AnyType, ... A",
    output_type: "A",
    signature: "(begin expr1 expr2 expr3 ... expr-last)",
    description: "The `begin` function evaluates each of its input expressions, returning the
return value of the last such expression.",
    example: "(begin (+ 1 2) 4 5) ;; Returns 5",
};

const PRINT_API: SpecialAPI = SpecialAPI {
    input_type: "A",
    output_type: "A",
    signature: "(print expr)",
    description: "The `print` function evaluates and returns its input expression. On Blockstack Core
nodes configured for development (as opposed to production mining nodes), this function prints the resulting value to `STDOUT` (standard output).",
    example: "(print (+ 1 2 3)) ;; Returns 6",
};

const FETCH_ENTRY_API: SpecialAPI = SpecialAPI {
    input_type: "MapName, tuple",
    output_type: "(optional (tuple))",
    signature: "(map-get map-name key-tuple)",
    description: "The `map-get` function looks up and returns an entry from a contract's data map.
The value is looked up using `key-tuple`.
If there is no value associated with that key in the data map, the function returns a (none) option. Otherwise,
it returns (some value)",
    example: "(expects! (map-get names-map (tuple (name \"blockstack\"))) (err 1)) ;; Returns (tuple (id 1337))
(expects! (map-get names-map ((name \"blockstack\"))) (err 1)) ;; Same command, using a shorthand for constructing the tuple
",
};

const SET_ENTRY_API: SpecialAPI = SpecialAPI {
    input_type: "MapName, tuple_A, tuple_B",
    output_type: "bool",
    signature: "(map-set! map-name key-tuple value-tuple)",
    description: "The `map-set!` function sets the value associated with the input key to the 
inputted value. This function performs a _blind_ update; whether or not a value is already associated
with the key, the function overwrites that existing association.",
    example: "(map-set! names-map (tuple (name \"blockstack\")) (tuple (id 1337))) ;; Returns 'true
(map-set! names-map ((name \"blockstack\")) ((id 1337))) ;; Same command, using a shorthand for constructing the tuple
",
};

const INSERT_ENTRY_API: SpecialAPI = SpecialAPI {
    input_type: "MapName, tuple_A, tuple_B",
    output_type: "bool",
    signature: "(map-insert! map-name key-tuple value-tuple)",
    description: "The `map-insert!` function sets the value associated with the input key to the 
inputted value if and only if there is not already a value associated with the key in the map.
If an insert occurs, the function returns `true`. If a value already existed for
this key in the data map, the function returns `false`.",
    example: "(map-insert! names-map (tuple (name \"blockstack\")) (tuple (id 1337))) ;; Returns 'true
(map-insert! names-map (tuple (name \"blockstack\")) (tuple (id 1337))) ;; Returns 'false
(map-insert! names-map ((name \"blockstack\")) ((id 1337))) ;; Same command, using a shorthand for constructing the tuple
",
};

const DELETE_ENTRY_API: SpecialAPI = SpecialAPI {
    input_type: "MapName, tuple",
    output_type: "bool",
    signature: "(map-delete! map-name key-tuple)",
    description: "The `map-delete!` function removes the value associated with the input key for
the given map. If an item exists and is removed, the function returns `true`.
If a value did not exist for this key in the data map, the function returns `false`.",
    example: "(map-delete! names-map (tuple (name \"blockstack\"))) ;; Returns 'true
(map-delete! names-map (tuple (name \"blockstack\"))) ;; Returns 'false
(map-delete! names-map ((name \"blockstack\"))) ;; Same command, using a shorthand for constructing the tuple
",
};

const FETCH_CONTRACT_API: SpecialAPI = SpecialAPI {
    input_type: "ContractName, MapName, tuple",
    output_type: "(optional (tuple))",
    signature: "(contract-map-get contract-name map-name key-tuple)",
    description: "The `contract-map-get` function looks up and returns an entry from a
contract other than the current contract's data map. The value is looked up using `key-tuple`.
If there is no value associated with that key in the data map, the function returns a (none) option. Otherwise,
it returns (some value).",
    example: "(expects! (contract-map-get names-contract names-map (tuple (name \"blockstack\")) (err 1))) ;; Returns (tuple (id 1337))
(expects! (contract-map-get names-contract names-map ((name \"blockstack\")) (err 1)));; Same command, using a shorthand for constructing the tuple
",
};

const TUPLE_CONS_API: SpecialAPI = SpecialAPI {
    input_type: "(key-name A), (key-name-2 B), ...",
    output_type: "(tuple (key-name A) (key-name-2 B) ...)",
    signature: "(tuple ((key0 expr0) (key1 expr1) ...))",
    description: "The `tuple` function constructs a typed tuple from the supplied key and expression pairs.
A `get` function can use typed tuples as input to select specific values from a given tuple.
Key names may not appear multiple times in the same tuple definition. Supplied expressions are evaluated and
associated with the expressions' paired key name.",
    example: "(tuple (name \"blockstack\") (id 1337))"
};

const TUPLE_GET_API: SpecialAPI = SpecialAPI {
    input_type: "KeyName, (tuple) | (optional (tuple))",
    output_type: "A",
    signature: "(get key-name tuple)",
    description: "The `get` function fetches the value associated with a given key from the supplied typed tuple.
If an `Optional` value is supplied as the inputted tuple, `get` returns an `Optional` type of the specified key in
the tuple. If the supplied option is a `(none)` option, get returns `(none)`.",
    example: "(get id (tuple (name \"blockstack\") (id 1337))) ;; Returns 1337
(get id (map-get names-map (tuple (name \"blockstack\")))) ;; Returns (some 1337)
(get id (map-get names-map (tuple (name \"non-existent\")))) ;; Returns (none)
"
};

const HASH160_API: SpecialAPI = SpecialAPI {
    input_type: "buff|int",
    output_type: "(buff 20)",
    signature: "(hash160 value)",
    description: "The `hash160` function computes `RIPEMD160(SHA256(x))` of the inputted value.
If an integer (128 bit) is supplied the hash is computed over the little-endian representation of the
integer.",
    example: "(hash160 0) ;; Returns 0xe4352f72356db555721651aa612e00379167b30f"
};

const SHA256_API: SpecialAPI = SpecialAPI {
    input_type: "buff|int",
    output_type: "(buff 32)",
    signature: "(sha256 value)",
    description: "The `sha256` function computes `SHA256(x)` of the inputted value.
If an integer (128 bit) is supplied the hash is computed over the little-endian representation of the
integer.",
    example: "(sha256 0) ;; Returns 0x374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb"
};

const SHA512_API: SpecialAPI = SpecialAPI {
    input_type: "buff|int",
    output_type: "(buff 64)",
    signature: "(sha512 value)",
    description: "The `sha512` function computes `SHA512(x)` of the inputted value.
If an integer (128 bit) is supplied the hash is computed over the little-endian representation of the
integer.",
    example: "(sha512 1) ;; Returns 0x6fcee9a7b7a7b821d241c03c82377928bc6882e7a08c78a4221199bfa220cdc55212273018ee613317c8293bb8d1ce08d1e017508e94e06ab85a734c99c7cc34",
};

const SHA512T256_API: SpecialAPI = SpecialAPI {
    input_type: "buff|int",
    output_type: "(buff 32)",
    signature: "(sha512/256 value)",
    description: "The `sha512/256` function computes `SHA512/256(x)` (the SHA512 algorithm with the 512/256 initialization vector, truncated
to 256 bits) of the inputted value.
If an integer (128 bit) is supplied the hash is computed over the little-endian representation of the
integer.",
    example: "(sha512/256 1) ;; Returns 0x515a7e92e7c60522db968d81ff70b80818fc17aeabbec36baf0dda2812e94a86",
};

const KECCAK256_API: SpecialAPI = SpecialAPI {
    input_type: "buff|int",
    output_type: "(buff 32)",
    signature: "(keccak256 value)",
    description: "The `keccak256` function computes `KECCAK256(value)` of the inputted value.
Note that this differs from the `NIST SHA-3` (that is, FIPS 202) standard. If an integer (128 bit) 
is supplied the hash is computed over the little-endian representation of the integer.",
    example: "(keccak256 0) ;; Returns 0xf490de2920c8a35fabeb13208852aa28c76f9be9b03a4dd2b3c075f7a26923b4"
};

const CONTRACT_CALL_API: SpecialAPI = SpecialAPI {
    input_type: "ContractName, PublicFunctionName, Arg0, ...",
    output_type: "(response A B)",
    signature: "(contract-call! contract-name function-name arg0 arg1 ...)",
    description: "The `contract-call!` function executes the given public function of the given contract.
You _may not_ this function to call a public function defined in the current contract. If the public
function returns _err_, any database changes resulting from calling `contract-call!` are aborted.
If the function returns _ok_, database changes occurred.",
    example: "(contract-call! tokens transfer 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 19) ;; Returns (ok 1)"
};

const AT_BLOCK: SpecialAPI = SpecialAPI {
    input_type: "(buff 32), A",
    output_type: "A",
    signature: "(at-block block-hash expr)",
    description: "The `at-block` function evaluates the expression `expr` _as if_ it were evaluated at the end of the
block indicated by the _block-hash_ argument. The `expr` closure must be read-only.

The function returns the result of evaluating `expr`.
",
    example: "(at-block 0x0000000000000000000000000000000000000000000000000000000000000000 (var-get data))"
};
        

const AS_CONTRACT_API: SpecialAPI = SpecialAPI {
    input_type: "A",
    output_type: "A",
    signature: "(as-contract expr)",
    description: "The `as-contract` function switches the current context's `tx-origin` value to the _contract's_ 
principal and executes `expr` with that context. It returns the resulting value of `expr`.",
    example: "(as-contract (print tx-sender)) ;; Returns 'CTcontract.name"
};


const EXPECTS_API: SpecialAPI = SpecialAPI {
    input_type: "(optional A) | (response A B), C",
    output_type: "A",
    signature: "(expects! option-input thrown-value)",
    description: "The `expects!` function attempts to 'unpack' the first argument: if the argument is
an option type, and the argument is a `(some ...)` option, `expects!` returns the inner value of the
option. If the argument is a response type, and the argument is an `(ok ...)` response, `expects!` returns
 the inner value of the `ok`. If the supplied argument is either an `(err ...)` or a `(none)` value,
`expects!` _returns_ `thrown-value` from the current function and exits the current control-flow.",
    example: "(expects! (map-get names-map (tuple (name \"blockstack\"))) (err 1)) ;; Returns (tuple (id 1337))",
};

const EXPECTS_ERR_API: SpecialAPI = SpecialAPI {
    input_type: "(response A B), C",
    output_type: "B",
    signature: "(expects-err! response-input thrown-value)",
    description: "The `expects-err!` function attempts to 'unpack' the first argument: if the argument
is an `(err ...)` response, `expects-err!` returns the inner value of the `err`.
If the supplied argument is an `(ok ...)` value,
`expects-err!` _returns_ `thrown-value` from the current function and exits the current control-flow.",
    example: "(expects-err! (err 1) 'false) ;; Returns 1",
};

const DEFAULT_TO_API: SpecialAPI = SpecialAPI {
    input_type: "A, (optional A)",
    output_type: "A",
    signature: "(default-to default-value option-value)",
    description: "The `default-to` function attempts to 'unpack' the second argument: if the argument is
a `(some ...)` option, it returns the inner value of the option. If the second argument is a `(none)` value,
`default-to` it returns the value of `default-value`.",
    example: "(default-to 0 (get id (map-get names-map (tuple (name \"blockstack\"))))) ;; Returns 1337
(default-to 0 (get id (map-get names-map (tuple (name \"non-existant\"))))) ;; Returns 0
",
};

const CONS_OK_API: SpecialAPI = SpecialAPI {
    input_type: "A",
    output_type: "(response A B)",
    signature: "(ok value)",
    description: "The `ok` function constructs a response type from the input value. Use `ok` for
creating return values in public functions. An _ok_ value indicates that any database changes during
the processing of the function should materialize.",
    example: "(ok 1) ;; Returns (ok 1)",
};

const CONS_ERR_API: SpecialAPI = SpecialAPI {
    input_type: "A",
    output_type: "(response A B)",
    signature: "(err value)",
    description: "The `err` function constructs a response type from the input value. Use `err` for
creating return values in public functions. An _err_ value indicates that any database changes during
the processing of the function should be rolled back.",
    example: "(err 'true) ;; Returns (err 'true)",
};

const CONS_SOME_API: SpecialAPI = SpecialAPI {
    input_type: "A",
    output_type: "(optional A)",
    signature: "(some value)",
    description: "The `some` function constructs a `optional` type from the input value.",
    example: "(some 1) ;; Returns (some 1)
(is-none? (some 2)) ;; Returns 'false",
};

const IS_OK_API: SpecialAPI = SpecialAPI {
    input_type: "(response A B)",
    output_type: "bool",
    signature: "(is-ok? value)",
    description: "`is-ok?` tests a supplied response value, returning `true` if the response was `ok`,
and `false` if it was an `err`.",
    example: "(is-ok? (ok 1)) ;; Returns 'true
(is-ok? (err 1)) ;; Returns 'false",
};

const IS_NONE_API: SpecialAPI = SpecialAPI {
    input_type: "(optional A)",
    output_type: "bool",
    signature: "(is-none? value)",
    description: "`is-none?` tests a supplied option value, returning `true` if the option value is `(none)`,
and `false` if it is a `(some ...)`.",
    example: "(is-none? (get id (map-get names-map (tuple (name \"blockstack\"))))) ;; Returns 'false
(is-none? (get id (map-get names-map (tuple (name \"non-existant\"))))) ;; Returns 'true"
};

const GET_BLOCK_INFO_API: SpecialAPI = SpecialAPI {
    input_type: "BlockInfoPropertyName, BlockHeightInt",
    output_type: "buff | int",
    signature: "(get-block-info prop-name block-height-expr)",
    description: "The `get-block-info` function fetches data for a block of the given block height. The 
value and type returned are determined by the specified `BlockInfoPropertyName`. If the provided `BlockHeightInt` does
not correspond to an existing block, the function is aborted. The currently available property names 
are `time`, `header-hash`, `burnchain-header-hash`, and `vrf-seed`. 

The `time` property returns an integer value of the block header time field. This is a Unix epoch timestamp in seconds 
which roughly corresponds to when the block was mined. **Warning**: this does not increase monotonically with each block
and block times are accurate only to within two hours. See [BIP113](https://github.com/bitcoin/bips/blob/master/bip-0113.mediawiki) for more information. 

The `header-hash`, `burnchain-header-hash`, and `vrf-seed` properties return a 32-byte buffer. 
",
    example: "(get-block-info time 10) ;; Returns 1557860301
(get-block-info header-hash 2) ;; Returns 0x374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb
(get-block-info vrf-seed 6) ;; Returns 0xf490de2920c8a35fabeb13208852aa28c76f9be9b03a4dd2b3c075f7a26923b4
"
};

const DEFINE_TOKEN_API: DefineAPI = DefineAPI {
    input_type: "TokenName, <int>",
    output_type: "Not Applicable",
    signature: "(define-fungible-token token-name <total-supply>)",
    description: "`define-fungible-token` is used to define a new fungible token class for use in the current contract.

The second argument, if supplied, defines the total supply of the fungible token. This ensures that all calls to the `ft-mint!`
function will never be able to create more than `total-supply` tokens. If any such call were to increase the total supply
of tokens passed that amount, that invocation of `ft-mint!` will result in a runtime error and abort.

Like other kinds of definition statements, `define-fungible-token` may only be used at the top level of a smart contract
definition (i.e., you cannot put a define statement in the middle of a function body).

Tokens defined using `define-fungible-token` may be used in `ft-transfer!`, `ft-mint!`, and `ft-get-balance` functions",
    example: "
(define-fungible-token stacks)
"
};

const DEFINE_ASSET_API: DefineAPI = DefineAPI {
    input_type: "AssetName, TypeSignature",
    output_type: "Not Applicable",
    signature: "(define-non-fungible-token asset-name asset-identifier-type)",
    description: "`define-non-fungible-token` is used to define a new non-fungible token class for use in the current contract.
Individual assets are identified by their asset identifier, which must be of the type `asset-identifier-type`. Asset
identifiers are _unique_ identifiers.

Like other kinds of definition statements, `define-non-fungible-token` may only be used at the top level of a smart contract
definition (i.e., you cannot put a define statement in the middle of a function body).

Assets defined using `define-non-fungible-token` may be used in `nft-transfer!`, `nft-mint!`, and `nft-get-owner` functions",
    example: "
(define-non-fungible-token names (buff 50))
"
};

const DEFINE_PUBLIC_API: DefineAPI = DefineAPI {
    input_type: "MethodSignature, MethodBody",
    output_type: "Not Applicable",
    signature: "(define-public (function-name (arg-name-0 arg-type-0) (arg-name-1 arg-type-1) ...) function-body)",
    description: "`define-public` is used to define a _public_ function and transaction for a smart contract. Public
functions are callable from other smart contracts and may be invoked directly by users by submitting a transaction
to the Stacks blockchain.

Like other kinds of definition statements, `define-public` may only be used at the top level of a smart contract
definition (i.e., you cannot put a define statement in the middle of a function body).

Public functions _must_ return a ResponseType (using either `ok` or `err`). Any datamap modifications performed by
a public function is aborted if the function returns an `err` type. Public functions may be invoked by other
contracts via `contract-call!`.",
    example: "
(define-public (hello-world (input int))
  (begin (print (+ 2 input))
         (ok input)))
"
};

const DEFINE_CONSTANT_API: DefineAPI = DefineAPI {
    input_type: "MethodSignature, MethodBody",
    output_type: "Not Applicable",
    signature: "(define-constant name expression)",
    description: "`define-constant` is used to define a private constant value in a smart contract.
The expression passed into the definition is evaluated at contract launch, in the order that it is
supplied in the contract. This can lead to undefined function or undefined variable errors in the
event that a function or variable used in the expression has not been defined before the constant.

Like other kinds of definition statements, `define-constant` may only be used at the top level of a smart contract
definition (i.e., you cannot put a define statement in the middle of a function body).
",
    example: "
(define-constant four (+ 2 2))
(+ 4 four) ;; returns 8
"
};

const DEFINE_PRIVATE_API: DefineAPI = DefineAPI {
    input_type: "MethodSignature, MethodBody",
    output_type: "Not Applicable",
    signature: "(define-private (function-name (arg-name-0 arg-type-0) (arg-name-1 arg-type-1) ...) function-body)",
    description: "`define-private` is used to define _private_ functions for a smart contract. Private
functions may not be called from other smart contracts, nor may they be invoked directly by users.
Instead, these functions may only be invoked by other functions defined in the same smart contract.

Like other kinds of definition statements, `define-private` may only be used at the top level of a smart contract
definition (i.e., you cannot put a define statement in the middle of a function body).

Private functions may return any type.",
    example: "
(define-private (max-of (i1 int) (i2 int))
  (if (> i1 i2)
      i1
      i2))
(max-of 4 6) ;; returns 6
"
};

const DEFINE_READ_ONLY_API: DefineAPI = DefineAPI {
    input_type: "MethodSignature, MethodBody",
    output_type: "Not Applicable",
    signature: "(define-read-only (function-name (arg-name-0 arg-type-0) (arg-name-1 arg-type-1) ...) function-body)",
    description: "`define-read-only` is used to define a _public read-only_ function for a smart contract. Such
functions are callable from other smart contracts.

Like other kinds of definition statements, `define-read-only` may only be used at the top level of a smart contract
definition (i.e., you cannot put a define statement in the middle of a function body).

Read-only functions may return any type. However, read-only functions
may not perform any datamap modifications, or call any functions which
perform such modifications. This is enforced both during type checks and during
the execution of the function. Public read-only functions may
be invoked by other contracts via `contract-call!`.",
    example: "
(define-read-only (just-return-one-hundred) 
  (* 10 10))"
};

const DEFINE_MAP_API: DefineAPI = DefineAPI {
    input_type: "MapName, KeyTupleDefinition, MapTupleDefinition",
    output_type: "Not Applicable",
    signature: "(define-map map-name ((key-name-0 key-type-0) ...) ((val-name-0 val-type-0) ...))",
    description: "`define-map` is used to define a new datamap for use in a smart contract. Such
maps are only modifiable by the current smart contract.

Maps are defined with a key tuple type and value tuple type. These are defined using a list
of name and type pairs, e.g., a key type might be `((id int))`, which is a tuple with a single \"id\"
field of type `int`.

Like other kinds of definition statements, `define-map` may only be used at the top level of a smart contract
definition (i.e., you cannot put a define statement in the middle of a function body).",
    example: "
(define-map squares ((x int)) ((square int)))
(define (add-entry (x int))
  (map-insert! squares ((x 2)) ((square (* x x)))))
(add-entry 1)
(add-entry 2)
(add-entry 3)
(add-entry 4)
(add-entry 5)
"
};

const DEFINE_DATA_VAR_API: DefineAPI = DefineAPI {
    input_type: "VarName, TypeDefinition, Value",
    output_type: "Not Applicable",
    signature: "(define-data-var var-name type value)",
    description: "`define-data-var` is used to define a new persisted variable for use in a smart contract. Such
variable are only modifiable by the current smart contract.

Persisted variable are defined with a type and a value.

Like other kinds of definition statements, `define-data-var` may only be used at the top level of a smart contract
definition (i.e., you cannot put a define statement in the middle of a function body).",
    example: "
(define-data-var size int 0)
(define (set-size (value int))
  (var-set! size value))
(set-size 1)
(set-size 2)
"
};

const MINT_TOKEN: SpecialAPI = SpecialAPI {
    input_type: "TokenName, int, principal",
    output_type: "(response bool int)",
    signature: "(ft-mint! token-name amount recipient)",
    description: "`ft-mint!` is used to increase the token balance for the `recipient` principal for a token
type defined using `define-fungible-token`. The increased token balance is _not_ transfered from another principal, but
rather minted.

If a non-positive amount is provided to mint, this function returns `(err 1)`. Otherwise, on successfuly mint, it
returns `(ok 'true)`.
",
    example: "
(define-fungible-token stackaroo)
(ft-mint! stackaroo 100 tx-sender)
"
};

const MINT_ASSET: SpecialAPI = SpecialAPI {
    input_type: "AssetName, A, principal",
    output_type: "(response bool int)",
    signature: "(nft-mint! asset-class asset-identifier recipient)",
    description: "`nft-mint!` is used to instantiate an asset and set that asset's owner to the `recipient` principal.
The asset must have been defined using `define-non-fungible-token`, and the supplied `asset-identifier` must be of the same type specified in
that definition.

If an asset identified by `asset-identifier` _already exists_, this function will return an error with the following error code:

`(err 1)`

Otherwise, on successfuly mint, it returns `(ok 'true)`.
",
    example: "
(define-non-fungible-token stackaroo (buff 40))
(nft-mint! stackaroo \"Roo\" tx-sender)
"
};

const GET_OWNER: SpecialAPI = SpecialAPI {
    input_type: "AssetName, A",
    output_type: "(optional principal)",
    signature: "(nft-get-owner asset-class asset-identifier)",
    description: "`nft-get-owner` returns the owner of an asset, identified by `asset-identifier`, or `none` if the asset does not exist.
The asset type must have been defined using `define-non-fungible-token`, and the supplied `asset-identifier` must be of the same type specified in
that definition.",
    example: "
(define-non-fungible-token stackaroo (buff 40))
(nft-get-owner stackaroo \"Roo\")
"
};


const GET_BALANCE: SpecialAPI = SpecialAPI {
    input_type: "TokenName, principal",
    output_type: "int",
    signature: "(ft-get-balance token-name principal)",
    description: "`ft-get-balance` returns `token-name` balance of the principal `principal`.
The token type must have been defined using `define-fungible-token`.",
    example: "
(define-fungible-token stackaroos)
(ft-get-balance stackaroos tx-sender)
"
};

const TOKEN_TRANSFER: SpecialAPI = SpecialAPI {
    input_type: "TokenName, int, principal, principal",
    output_type: "(response bool int)",
    signature: "(ft-transfer! token-name amount sender recipient)",
    description: "`ft-transfer!` is used to increase the token balance for the `recipient` principal for a token
type defined using `define-fungible-token` by debiting the `sender` principal.

This function returns (ok true) if the transfer is successful. In the event of an unsuccessful transfer it returns
one of the following error codes:

`(err 1)` -- `sender` does not have enough balance to transfer
`(err 2)` -- `sender` and `recipient` are the same principal
`(err 3)` -- amount to send is non-positive
",
    example: "
(define-fungible-token stackaroo)
(ft-mint! stackaroo 100 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
(ft-transfer! stackaroo 50 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR tx-sender) ;; returns (ok true)
(ft-transfer! stackaroo 60 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR tx-sender) ;; returns (err 1)
"
};

const ASSET_TRANSFER: SpecialAPI = SpecialAPI {
    input_type: "AssetName, A, principal, principal",
    output_type: "(response bool int)",
    signature: "(nft-transfer! asset-class asset-identifier sender recipient)",
    description: "`nft-transfer!` is used to change the owner of an asset identified by `asset-identifier`
from `sender` to `recipient`. The `asset-class` must have been defined by `define-non-fungible-token` and `asset-identifier`
must be of the type specified in that definition.

This function returns (ok true) if the transfer is successful. In the event of an unsuccessful transfer it returns
one of the following error codes:

`(err 1)` -- `sender` does not own the asset
`(err 2)` -- `sender` and `recipient` are the same principal
`(err 3)` -- asset identified by asset-identifier does not exist
",
    example: "
(define-non-fungible-token stackaroo (buff 40))
(nft-mint! stackaroo \"Roo\" 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
(nft-transfer! stackaroo \"Roo\" 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR tx-sender) ;; returns (ok true)
(nft-transfer! stackaroo \"Roo\" 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR tx-sender) ;; returns (err 1)
(nft-transfer! stackaroo \"Stacka\" 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR tx-sender) ;; returns (err 3)
"
};

fn make_api_reference(function: &NativeFunctions) -> FunctionAPI {
    use vm::functions::NativeFunctions::*;
    let name = function.get_name();
    match function {
        Add => make_for_simple_native(&ADD_API, &Add, name),
        ToUInt => make_for_simple_native(&TO_UINT_API, &ToUInt, name),
        ToInt => make_for_simple_native(&TO_INT_API, &ToInt, name),
        Subtract => make_for_simple_native(&SUB_API, &Subtract, name),
        Multiply => make_for_simple_native(&MUL_API, &Multiply, name),
        Divide => make_for_simple_native(&DIV_API, &Divide, name),
        CmpGeq => make_for_simple_native(&GEQ_API, &CmpGeq, name),
        CmpLeq => make_for_simple_native(&LEQ_API, &CmpLeq, name),
        CmpLess => make_for_simple_native(&LESS_API, &CmpLess, name),
        CmpGreater => make_for_simple_native(&GREATER_API, &CmpGreater, name),
        Modulo => make_for_simple_native(&MOD_API, &Modulo, name),
        Power => make_for_simple_native(&POW_API, &Power, name),
        BitwiseXOR => make_for_simple_native(&XOR_API, &BitwiseXOR, name),
        And => make_for_simple_native(&AND_API, &And, name),
        Or => make_for_simple_native(&OR_API, &Or, name),
        Not => make_for_simple_native(&NOT_API, &Not, name),
        Equals => make_for_special(&EQUALS_API, name),
        If => make_for_special(&IF_API, name),
        Let => make_for_special(&LET_API, name),
        FetchVar => make_for_special(&FETCH_VAR_API, name),
        SetVar => make_for_special(&SET_VAR_API, name),
        Map => make_for_special(&MAP_API, name),
        Filter => make_for_special(&FILTER_API, name),
        Fold => make_for_special(&FOLD_API, name),
        ListCons => make_for_special(&LIST_API, name),
        FetchEntry => make_for_special(&FETCH_ENTRY_API, name),
        FetchContractEntry => make_for_special(&FETCH_CONTRACT_API, name),
        SetEntry => make_for_special(&SET_ENTRY_API, name),
        InsertEntry => make_for_special(&INSERT_ENTRY_API, name),
        DeleteEntry => make_for_special(&DELETE_ENTRY_API, name),
        TupleCons => make_for_special(&TUPLE_CONS_API, name),
        TupleGet => make_for_special(&TUPLE_GET_API, name),
        Begin => make_for_special(&BEGIN_API, name),
        Hash160 => make_for_special(&HASH160_API, name),
        Sha256 => make_for_special(&SHA256_API, name),
        Sha512 => make_for_special(&SHA512_API, name),
        Sha512Trunc256 => make_for_special(&SHA512T256_API, name),
        Keccak256 => make_for_special(&KECCAK256_API, name),
        Print => make_for_special(&PRINT_API, name),
        ContractCall => make_for_special(&CONTRACT_CALL_API, name),
        AsContract => make_for_special(&AS_CONTRACT_API, name),
        GetBlockInfo => make_for_special(&GET_BLOCK_INFO_API, name),
        ConsOkay => make_for_special(&CONS_OK_API, name),
        ConsError => make_for_special(&CONS_ERR_API, name),
        ConsSome =>  make_for_special(&CONS_SOME_API, name),
        DefaultTo => make_for_special(&DEFAULT_TO_API, name),
        Expects => make_for_special(&EXPECTS_API, name),
        ExpectsErr => make_for_special(&EXPECTS_ERR_API, name),
        IsOkay => make_for_special(&IS_OK_API, name),
        IsNone => make_for_special(&IS_NONE_API, name),
        MintAsset => make_for_special(&MINT_ASSET, name),
        MintToken => make_for_special(&MINT_TOKEN, name),
        GetTokenBalance => make_for_special(&GET_BALANCE, name),
        GetAssetOwner => make_for_special(&GET_OWNER, name),
        TransferToken => make_for_special(&TOKEN_TRANSFER, name),
        TransferAsset => make_for_special(&ASSET_TRANSFER, name),
        AtBlock => make_for_special(&AT_BLOCK, name),
    }
}

fn make_keyword_reference(variable: &NativeVariables) -> Option<KeywordAPI> {
    match variable {
        NativeVariables::TxSender => Some(TX_SENDER_KEYWORD.clone()),
        NativeVariables::ContractCaller => Some(CONTRACT_CALLER_KEYWORD.clone()),
        NativeVariables::NativeNone => Some(NONE_KEYWORD.clone()),
        NativeVariables::BlockHeight => Some(BLOCK_HEIGHT.clone()),
        NativeVariables::BurnBlockHeight => None,
    }
}

fn make_for_special(api: &SpecialAPI, name: String) -> FunctionAPI {
    FunctionAPI {
        name,
        input_type: api.input_type.to_string(),
        output_type: api.output_type.to_string(),
        signature: api.signature.to_string(),
        description: api.description.to_string(),
        example: api.example.to_string()
    }
}

fn make_for_define(api: &DefineAPI, name: String) -> FunctionAPI {
    FunctionAPI {
        name,
        input_type: api.input_type.to_string(),
        output_type: api.output_type.to_string(),
        signature: api.signature.to_string(),
        description: api.description.to_string(),
        example: api.example.to_string()
    }
}

fn make_define_reference(define_type: &DefineFunctions) -> FunctionAPI {
    use vm::functions::define::DefineFunctions::*;
    let name = define_type.get_name();
    match define_type {
        Constant => make_for_define(&DEFINE_CONSTANT_API, name),
        PrivateFunction => make_for_define(&DEFINE_PRIVATE_API, name),
        PublicFunction => make_for_define(&DEFINE_PUBLIC_API, name),
        Map => make_for_define(&DEFINE_MAP_API, name),
        NonFungibleToken => make_for_define(&DEFINE_ASSET_API, name),
        FungibleToken => make_for_define(&DEFINE_TOKEN_API, name),
        ReadOnlyFunction => make_for_define(&DEFINE_READ_ONLY_API, name),
        PersistedVariable => make_for_define(&DEFINE_DATA_VAR_API, name),
    }
}

pub fn make_json_api_reference() -> String {
    let mut functions: Vec<_> = NativeFunctions::ALL.iter()
        .map(|x| make_api_reference(x))
        .collect();

    for data_type in DefineFunctions::ALL.iter() {
        functions.push(make_define_reference(data_type))
    }

    let mut keywords = Vec::new();
    for variable in NativeVariables::ALL.iter() {
        let output = make_keyword_reference(variable);
        if let Some(api_ref) = output {
            keywords.push(api_ref)
        }
    }

    let api_out = ReferenceAPIs { functions, keywords };
    format!("{}", serde_json::to_string(&api_out)
            .expect("Failed to serialize documentation"))
}

#[cfg(test)]
mod test {
    use super::make_json_api_reference;

    #[test]
    fn ensure_docgen_runs() {
        // add a test to make sure that we don't inadvertently break
        //  docgen in a panic-y way.
        make_json_api_reference();
    }
}
