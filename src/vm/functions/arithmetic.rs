use vm::types::Value;
use vm::errors::{UncheckedError, RuntimeErrorType, InterpreterResult as Result, check_argument_count};

fn type_force_integer(value: &Value) -> Result<i128> {
    match *value {
        Value::Int(int) => Ok(int),
        _ => Err(UncheckedError::TypeError("IntType".to_string(), value.clone()).into())
    }
}

fn binary_comparison<F>(args: &[Value], function: &F) -> Result<Value>
where F: Fn(i128, i128) -> bool {
    check_argument_count(2, args)?;

    let arg1 = type_force_integer(&args[0])?;
    let arg2 = type_force_integer(&args[1])?;
    Ok(Value::Bool((*function)(arg1, arg2)))
}

pub fn native_xor(args: &[Value]) -> Result<Value> {
    check_argument_count(2, args)?;
    let x = type_force_integer(&args[0])?;
    let y = type_force_integer(&args[1])?;

    Ok(Value::Int(x ^ y))
}

pub fn native_geq(args: &[Value]) -> Result<Value> {
    binary_comparison(args, &|x, y| x >= y)
}
pub fn native_leq(args: &[Value]) -> Result<Value> {
    binary_comparison(args, &|x, y| x <= y)
}
pub fn native_ge(args: &[Value]) -> Result<Value> {
    binary_comparison(args, &|x, y| x > y)
}
pub fn native_le(args: &[Value]) -> Result<Value> {
    binary_comparison(args, &|x, y| x < y)
}

pub fn native_add(args: &[Value]) -> Result<Value> {
    let typed_args: Result<Vec<_>> = args.iter().map(|x| type_force_integer(x)).collect();
    let parsed_args = typed_args?;
    let checked_result = parsed_args.iter().fold(Some(0), |acc: Option<i128>, x| {
        match acc {
            Some(value) => value.checked_add(*x),
            None => None
        }});
    if let Some(result) = checked_result{
        Ok(Value::Int(result))
    } else {
        Err(RuntimeErrorType::ArithmeticOverflow.into())
    }
}

pub fn native_sub(args: &[Value]) -> Result<Value> {
    let typed_args: Result<Vec<_>> = args.iter().map(|x| type_force_integer(x)).collect();
    let parsed_args = typed_args?;
    let (first, rest) = parsed_args.split_first()
        .ok_or(UncheckedError::IncorrectArgumentCount(1, 0))?;
    if rest.len() == 0 { // return negation
        return Ok(Value::Int(-1 * first))
    }

    let checked_result = rest.iter().fold(Some(*first), |acc, x| {
        match acc {
            Some(value) => value.checked_sub(*x),
            None => None
        }});
    let result = checked_result
        .ok_or(RuntimeErrorType::ArithmeticUnderflow)?;
    Ok(Value::Int(result))
}

pub fn native_mul(args: &[Value]) -> Result<Value> {
    let typed_args: Result<Vec<_>> = args.iter().map(|x| type_force_integer(x)).collect();
    let parsed_args = typed_args?;
    let checked_result = parsed_args.iter().fold(Some(1), |acc: Option<i128>, x| {
        match acc {
            Some(value) => value.checked_mul(*x),
            None => None
        }});
    let result = checked_result
        .ok_or(RuntimeErrorType::ArithmeticOverflow)?;
    Ok(Value::Int(result))
}

pub fn native_div(args: &[Value]) -> Result<Value> {
    let typed_args: Result<Vec<_>> = args.iter().map(|x| type_force_integer(x)).collect();
    let parsed_args = typed_args?;

    let (first, rest) = parsed_args.split_first()
        .ok_or(UncheckedError::IncorrectArgumentCount(1, 0))?;
    let checked_result = rest.iter().fold(Some(*first), |acc, x| {
        match acc {
            Some(value) => value.checked_div(*x),
            None => None
        }});
    let result = checked_result
        .ok_or(RuntimeErrorType::DivisionByZero)?;
    Ok(Value::Int(result))
}

// AARON: Note -- this was pulled straight for rustlang's nightly @ 1.34
//             -- this _should be_ deleted once 1.34 ships.
fn checked_pow(mut base: i128, mut exp: u32) -> Option<i128> {
    let mut acc: i128 = 1;
    
    while exp > 1 {
        if (exp & 1) == 1 {
            acc = acc.checked_mul(base)?;
        }
        exp /= 2;
        base = base.checked_mul(base)?;
    }
    
    // Deal with the final bit of the exponent separately, since
    // squaring the base afterwards is not necessary and may cause a
    // needless overflow.
    if exp == 1 {
        acc = acc.checked_mul(base)?;
    }
    
    Some(acc)
}

pub fn native_pow(args: &[Value]) -> Result<Value> {
    if args.len() == 2 {
        let base = type_force_integer(&args[0])?;
        let power_i128 = type_force_integer(&args[1])?;
        if power_i128 < 0 || power_i128 > (u32::max_value() as i128) {
            return Err(RuntimeErrorType::Arithmetic("Power argument to (pow ...) must be a u32 integer".to_string()).into())
        }

        let power = power_i128 as u32;
        let checked_result = checked_pow(base, power);

        if let Some(result) = checked_result{
            Ok(Value::Int(result))
        } else {
            Err(RuntimeErrorType::ArithmeticOverflow.into())
        }
    } else {
        Err(UncheckedError::InvalidArguments("(pow ...) must be called with exactly 2 arguments".to_string()).into())
    }
}


pub fn native_mod(args: &[Value]) -> Result<Value> {
    if args.len() == 2 {
        let numerator = type_force_integer(&args[0])?;
        let denominator = type_force_integer(&args[1])?;
        let checked_result = numerator.checked_rem(denominator);
        if let Some(result) = checked_result{
            Ok(Value::Int(result))
        } else {
            Err(RuntimeErrorType::Arithmetic("Modulus by 0".to_string()).into())
        }
    } else {
        Err(UncheckedError::InvalidArguments("(mod ...) must be called with exactly 2 arguments".to_string()).into())
    }
}
