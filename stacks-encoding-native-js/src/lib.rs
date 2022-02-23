use std::convert::TryInto;
use clarity::vm::types::Value as ClarityValue;
use clarity::vm::types::signatures::TypeSignature as ClarityTypeSignature;
use stacks_common::codec::StacksMessageCodec;
use neon::prelude::*;


fn hello(mut cx: FunctionContext) -> JsResult<JsString> {
    Ok(cx.string("test3: hello nodejs from libclarity!"))
}

fn decode_clarity_value(mut cx: FunctionContext) -> JsResult<JsString> {
    let hex_string = cx.argument::<JsString>(0)?.value(&mut cx);
    let val_bytes = hex::decode(hex_string).or_else(|e| cx.throw_error(format!("Parsing error: {}", e)))?;
    let byte_cursor = &mut &val_bytes[..];
    let value = ClarityValue::consensus_deserialize(byte_cursor).or_else(|e| cx.throw_error(format!("{}", e)))?;
    Ok(cx.string(format!("{}", value)))
}

fn decode_clarity_value2(mut cx: FunctionContext) -> JsResult<JsString> {
    let hex_string = cx.argument::<JsString>(0)?.value(&mut cx);
    let val_bytes = hex::decode(hex_string).or_else(|e| cx.throw_error(format!("Parsing error: {}", e)))?;
    let byte_cursor = &mut &val_bytes[..];
    while !byte_cursor.is_empty() {
        let value = ClarityValue::consensus_deserialize(byte_cursor).or_else(|e| cx.throw_error(format!("{}", e)))?;
        let value_type = ClarityTypeSignature::type_of(&value).to_string();
        return Ok(cx.string(format!("{}{}", value, value_type)));
    }
    cx.throw_error("Empty input bytes")
}

fn decode_clarity_value3(mut cx: FunctionContext) -> JsResult<JsString> {
    let hex_string = cx.argument::<JsString>(0)?.value(&mut cx);
    let val_bytes = hex::decode(hex_string).or_else(|e| cx.throw_error(format!("Parsing error: {}", e)))?;
    let mut byte_cursor = val_bytes.as_slice();
    while !byte_cursor.is_empty() {
        let value = ClarityValue::consensus_deserialize(&mut byte_cursor).or_else(|e| cx.throw_error(format!("{}", e)))?;
        let value_type = ClarityTypeSignature::type_of(&value).to_string();
        return Ok(cx.string(format!("{}{}", value, value_type)));
    }
    cx.throw_error("Empty input bytes")
}

fn decode_clarity_value_array_old(mut cx: FunctionContext) -> JsResult<JsArray> {
    let hex_string = cx.argument::<JsString>(0)?.value(&mut cx);
    let val_bytes = hex::decode(hex_string).or_else(|e| cx.throw_error(format!("Parsing error: {}", e)))?;
    let array_len = u32::from_be_bytes(val_bytes[..4].try_into().unwrap());
    
    let val_slice = &val_bytes[4..];
    let mut byte_cursor = std::io::Cursor::new(val_slice);
    let val_len = val_slice.len() as u64;
    // let byte_len = byte_cursor.get_ref().len();
    let mut i: u32 = 0;
    let array_result = JsArray::new(&mut cx, array_len * 3);
    while byte_cursor.position() < val_len - 1 {
    // while !byte_cursor.is_empty() {
        let cur_start = byte_cursor.position() as usize;
        let clarity_value = ClarityValue::consensus_deserialize(&mut byte_cursor).or_else(|e| cx.throw_error(format!("{}", e)))?;
        let cur_end = byte_cursor.position() as usize;
        let value_hex = cx.string("0x".to_owned() + &hex::encode(&val_slice[cur_start..cur_end]));
        let value_type = cx.string(ClarityTypeSignature::type_of(&clarity_value).to_string());
        let value_repr = cx.string(clarity_value.to_string());
        array_result.set(&mut cx, i, value_type)?;
        array_result.set(&mut cx, i + 1, value_repr)?;
        array_result.set(&mut cx, i + 2, value_hex)?;
        i = i + 3;
    }
    Ok(array_result)
}

fn decode_clarity_value_array(mut cx: FunctionContext) -> JsResult<JsArray> {
    let input_hex = cx.argument::<JsString>(0)?.value(&mut cx);
    let input_bytes = hex::decode(input_hex).or_else(|e| cx.throw_error(format!("Parsing error: {}", e)))?;
    let result_length = u32::from_be_bytes(input_bytes[..4].try_into().unwrap());
    let array_result = JsArray::new(&mut cx, result_length);

    let val_slice = &input_bytes[4..];
    let mut byte_cursor = std::io::Cursor::new(val_slice);
    let val_len = val_slice.len() as u64;
    let mut i: u32 = 0;
    while byte_cursor.position() < val_len - 1 {
        let cur_start = byte_cursor.position() as usize;
        let clarity_value = ClarityValue::consensus_deserialize(&mut byte_cursor).or_else(|e| cx.throw_error(format!("{}", e)))?;
        let cur_end = byte_cursor.position() as usize;
        let value_hex = cx.string("0x".to_owned() + &hex::encode(&val_slice[cur_start..cur_end]));
        let value_type = cx.string(ClarityTypeSignature::type_of(&clarity_value).to_string());
        let value_repr = cx.string(clarity_value.to_string());
        let value_obj = cx.empty_object();
        value_obj.set(&mut cx, "type", value_type)?;
        value_obj.set(&mut cx, "repr", value_repr)?;
        value_obj.set(&mut cx, "hex", value_hex)?;
        array_result.set(&mut cx, i, value_obj)?;
        i = i + 1;
    }
    Ok(array_result)
}

fn inspect_clarity_value_array(mut cx: FunctionContext) -> JsResult<JsString> {
    let hex_string = cx.argument::<JsString>(0)?.value(&mut cx);
    let val_bytes = hex::decode(hex_string).or_else(|e| cx.throw_error(format!("Parsing error: {}", e)))?;
    let array_len = u32::from_be_bytes(val_bytes[0..4].try_into().unwrap());
    Ok(cx.string(array_len.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn list_decode_test() {
        let val_bytes = hex::decode("0b000000640100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d40").unwrap();
        let value = ClarityValue::consensus_deserialize(&mut &val_bytes[..]).unwrap();
        let result = format!("{}", value);
        let result2 = value.to_string();
        assert_eq!(result2, "asdf");
        assert_eq!(result, "asdf");
    }
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("hello", hello)?;
    cx.export_function("decodeClarityValue", decode_clarity_value)?;
    cx.export_function("decodeClarityValueList", decode_clarity_value_array)?;
    cx.export_function("inspectClarityValueArray", inspect_clarity_value_array)?;
    Ok(())
}
