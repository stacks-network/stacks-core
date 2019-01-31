use types::Value;
use errors::{Error, InterpreterResult as Result};

fn type_force_integer(value: &Value) -> Result<i128> {
    match *value {
        Value::Int(int) => Ok(int),
        _ => Err(Error::TypeError("IntType".to_string(), value.clone()))
    }
}

fn binary_comparison<F>(args: &[Value], function: &F) -> Result<Value>
where F: Fn(i128, i128) -> bool {
    if args.len() == 2 {
        let arg1 = type_force_integer(&args[0])?;
        let arg2 = type_force_integer(&args[1])?;
        Ok(Value::Bool((*function)(arg1, arg2)))
    } else {
        Err(Error::InvalidArguments("Binary comparison must be called with exactly 2 arguments".to_string()))
    }
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
        Err(Error::Arithmetic("Overflowed in addition".to_string()))
    }
}

pub fn native_sub(args: &[Value]) -> Result<Value> {
    let typed_args: Result<Vec<_>> = args.iter().map(|x| type_force_integer(x)).collect();
    let parsed_args = typed_args?;
    if let Some((first, rest)) = parsed_args.split_first() {
        if rest.len() == 0 { // return negation
            return Ok(Value::Int(-1 * first))
        }

        let checked_result = rest.iter().fold(Some(*first), |acc, x| {
            match acc {
                Some(value) => value.checked_sub(*x),
                None => None
            }});
        if let Some(result) = checked_result{
            Ok(Value::Int(result))
        } else {
            Err(Error::Arithmetic("Underflowed in subtraction".to_string()))
        }
    } else {
        Err(Error::InvalidArguments("(- ...) must be called with at least 1 argument".to_string()))
    }
}

pub fn native_mul(args: &[Value]) -> Result<Value> {
    let typed_args: Result<Vec<_>> = args.iter().map(|x| type_force_integer(x)).collect();
    let parsed_args = typed_args?;
    let checked_result = parsed_args.iter().fold(Some(1), |acc: Option<i128>, x| {
        match acc {
            Some(value) => value.checked_mul(*x),
            None => None
        }});
    if let Some(result) = checked_result{
        Ok(Value::Int(result))
    } else {
        Err(Error::Arithmetic("Overflowed in multiplication".to_string()))
    }
}

pub fn native_div(args: &[Value]) -> Result<Value> {
    let typed_args: Result<Vec<_>> = args.iter().map(|x| type_force_integer(x)).collect();
    let parsed_args = typed_args?;
    if let Some((first, rest)) = parsed_args.split_first() {
        let checked_result = rest.iter().fold(Some(*first), |acc, x| {
            match acc {
                Some(value) => value.checked_div(*x),
                None => None
            }});
        if let Some(result) = checked_result{
            Ok(Value::Int(result))
        } else {
            Err(Error::Arithmetic("Divide by 0".to_string()))
        }
    } else {
        Err(Error::InvalidArguments("(/ ...) must be called with at least 1 argument".to_string()))
    }
}

pub fn native_pow(args: &[Value]) -> Result<Value> {
    if args.len() == 2 {
        let base = type_force_integer(&args[0])?;
        let power_i128 = type_force_integer(&args[1])?;
        if power_i128 < 0 || power_i128 > (u32::max_value() as i128) {
            return Err(Error::Arithmetic("Power argument to (pow ...) must be a u32 integer".to_string()))
        }

        let power = power_i128 as u32;
        let checked_result = base.checked_pow(power);

        if let Some(result) = checked_result{
            Ok(Value::Int(result))
        } else {
            Err(Error::Arithmetic("Overflowed in power".to_string()))
        }
    } else {
        Err(Error::InvalidArguments("(pow ...) must be called with exactly 2 arguments".to_string()))
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
            Err(Error::Arithmetic("Modulus by 0".to_string()))
        }
    } else {
        Err(Error::InvalidArguments("(mod ...) must be called with exactly 2 arguments".to_string()))
    }
}
