use std::convert::TryFrom;
use vm::types::Value;
use vm::errors::{UncheckedError, RuntimeErrorType, InterpreterResult, check_argument_count};

struct U128Ops();
struct I128Ops();

impl U128Ops {
    fn make_value(x: u128) -> InterpreterResult<Value> {
        Ok(Value::UInt(x))
    }
}

impl I128Ops {
    fn make_value(x: i128) -> InterpreterResult<Value> {
        Ok(Value::Int(x))
    }
}

// This macro checks the type of the required two arguments and then dispatches the evaluation
//   to the correct arithmetic type handler (after deconstructing the Clarity Values into
//   the corresponding Rust integer type.
macro_rules! type_force_binary_arithmetic { ($function: ident, $args: expr) => {
{
    check_argument_count(2, $args)?;
    match (&$args[0], &$args[1]) {
        (Value::Int(x), Value::Int(y)) => I128Ops::$function(*x, *y),
        (Value::UInt(x), Value::UInt(y)) => U128Ops::$function(*x, *y),
        _ => Err(UncheckedError::TypeError("int, int | uint, uint".to_string(),
                                           $args[0].clone()).into())
    }
}
}}

// This macro checks the type of the first argument and then dispatches the evaluation
//   to the correct arithmetic type handler (after deconstructing the Clarity Values into
//   the corresponding Rust integer type.
macro_rules! type_force_variadic_arithmetic { ($function: ident, $args: expr) => {
{
    let (first, rest) = $args.split_first()
        .ok_or(UncheckedError::IncorrectArgumentCount(1, $args.len()))?;
    match first {
        Value::Int(_) => {
            let typed_args: Result<Vec<_>, _> = $args.iter().map(
                |x| match x {
                    Value::Int(value) => Ok(value.clone()),
                    _ => Err(UncheckedError::TypeError("int".to_string(), x.clone()))
                })
                .collect();
            let checked_args = typed_args?;
            I128Ops::$function(&checked_args)
        },
        Value::UInt(_) => {
            let typed_args: Result<Vec<_>, _> = $args.iter().map(
                |x| match x {
                    Value::UInt(value) => Ok(value.clone()),
                    _ => Err(UncheckedError::TypeError("uint".to_string(), x.clone()))
                })
                .collect();
            let checked_args = typed_args?;
            U128Ops::$function(&checked_args)
        },
        _ => Err(UncheckedError::TypeError("int, int | uint, uint".to_string(),
                                           first.clone()).into())
    }
}
}}

// This macro creates all of the operation functions for the two arithmetic types
//  (uint128 and int128) -- this is really hard to do generically because there's no
//  "Integer" trait in rust, so macros were the most straight-forward solution to do this
//  without a bunch of code duplication
macro_rules! make_arithmetic_ops { ($struct_name: ident, $type:ty) => {
    impl $struct_name {
        fn xor(x: $type, y: $type) -> InterpreterResult<Value> {
            Self::make_value(x ^ y)
        }
        fn leq(x: $type, y: $type) -> InterpreterResult<Value> {
            Ok(Value::Bool(x <= y))
        }
        fn geq(x: $type, y: $type) -> InterpreterResult<Value> {
            Ok(Value::Bool(x >= y))
        }
        fn greater(x: $type, y: $type) -> InterpreterResult<Value> {
            Ok(Value::Bool(x > y))
        }
        fn less(x: $type, y: $type) -> InterpreterResult<Value> {
            Ok(Value::Bool(x < y))
        }
        fn add(args: &[$type]) -> InterpreterResult<Value> {
            let result = args.iter()
                .try_fold(0, |acc: $type, x: &$type| { acc.checked_add(*x) })
                .ok_or(RuntimeErrorType::ArithmeticOverflow)?;
            Self::make_value(result)
        }
        fn sub(args: &[$type]) -> InterpreterResult<Value> {
            let (first, rest) = args.split_first()
                .ok_or(UncheckedError::IncorrectArgumentCount(1, 0))?;
            if rest.len() == 0 { // return negation
                return Self::make_value(first.checked_neg()
                                        .ok_or(RuntimeErrorType::ArithmeticUnderflow)?)
                }
            
            let result = rest.iter()
                .try_fold(*first, |acc: $type, x: &$type| { acc.checked_sub(*x) })
                .ok_or(RuntimeErrorType::ArithmeticUnderflow)?;
            Self::make_value(result)
        }
        fn mul(args: &[$type]) -> InterpreterResult<Value> {
            let result = args.iter()
                .try_fold(1, |acc: $type, x: &$type| { acc.checked_mul(*x) })
                .ok_or(RuntimeErrorType::ArithmeticOverflow)?;
            Self::make_value(result)
        }
        fn div(args: &[$type]) -> InterpreterResult<Value> {
            let (first, rest) = args.split_first()
                .ok_or(UncheckedError::IncorrectArgumentCount(1, 0))?;
            let result = rest.iter()
                .try_fold(*first, |acc: $type, x: &$type| { acc.checked_div(*x) })
                .ok_or(RuntimeErrorType::DivisionByZero)?;
            Self::make_value(result)
        }
        fn modulo(numerator: $type, denominator: $type) -> InterpreterResult<Value> {
            let result = numerator.checked_rem(denominator)
                .ok_or(RuntimeErrorType::DivisionByZero)?;
                Self::make_value(result)
        }
        #[allow(unused_comparisons)]
        fn pow(base: $type, power: $type) -> InterpreterResult<Value> {
            if power < 0 || power > (u32::max_value() as $type) {
                return Err(RuntimeErrorType::Arithmetic("Power argument to (pow ...) must be a u32 integer".to_string()).into())
            }
            
            let power_u32 = power as u32;
            
            let result = base.checked_pow(power_u32)
                .ok_or(RuntimeErrorType::ArithmeticOverflow)?;
            Self::make_value(result)
        }
    }
}}

make_arithmetic_ops!(U128Ops, u128);
make_arithmetic_ops!(I128Ops, i128);

pub fn native_xor(args: &[Value]) -> InterpreterResult<Value> {
    type_force_binary_arithmetic!(xor, args)
}
pub fn native_geq(args: &[Value]) -> InterpreterResult<Value> {
    type_force_binary_arithmetic!(geq, args)
}
pub fn native_leq(args: &[Value]) -> InterpreterResult<Value> {
    type_force_binary_arithmetic!(leq, args)
}
pub fn native_ge(args: &[Value]) -> InterpreterResult<Value> {
    type_force_binary_arithmetic!(greater, args)
}
pub fn native_le(args: &[Value]) -> InterpreterResult<Value> {
    type_force_binary_arithmetic!(less, args)
}
pub fn native_add(args: &[Value]) -> InterpreterResult<Value> {
    type_force_variadic_arithmetic!(add, args)
}
pub fn native_sub(args: &[Value]) -> InterpreterResult<Value> {
    type_force_variadic_arithmetic!(sub, args)
}
pub fn native_mul(args: &[Value]) -> InterpreterResult<Value> {
    type_force_variadic_arithmetic!(mul, args)
}
pub fn native_div(args: &[Value]) -> InterpreterResult<Value> {
    type_force_variadic_arithmetic!(div, args)
}
pub fn native_pow(args: &[Value]) -> InterpreterResult<Value> {
    type_force_binary_arithmetic!(pow, args)
}
pub fn native_mod(args: &[Value]) -> InterpreterResult<Value> {
    type_force_binary_arithmetic!(modulo, args)
}

pub fn native_to_uint(args: &[Value]) -> InterpreterResult<Value> {
    check_argument_count(1, args)?;
    if let Value::Int(int_val) = args[0] {
        let uint_val = u128::try_from(int_val)
            .map_err(|_| RuntimeErrorType::ArithmeticUnderflow)?;
        Ok(Value::UInt(uint_val))
    } else {
        Err(UncheckedError::TypeError("int".to_string(), args[0].clone()).into())
    }
}

pub fn native_to_int(args: &[Value]) -> InterpreterResult<Value> {
    check_argument_count(1, args)?;
    if let Value::UInt(uint_val) = args[0] {
        let int_val = i128::try_from(uint_val)
            .map_err(|_| RuntimeErrorType::ArithmeticOverflow)?;
        Ok(Value::Int(int_val))
    } else {
        Err(UncheckedError::TypeError("uint".to_string(), args[0].clone()).into())
    }
}
