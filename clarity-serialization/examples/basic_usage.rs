// Example demonstrating basic usage of clarity-serialization

use clarity_serialization::{
    Value, ClaritySerializable, ClarityDeserializable, 
    SerializationError, to_hex, from_hex
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Clarity Serialization Example ===\n");

    // Create some basic values
    let uint_value = Value::UInt(42);
    let bool_value = Value::Bool(true);
    let none_value = Value::none();

    println!("1. Basic Value Serialization:");
    demonstrate_serialization(&uint_value, "UInt(42)")?;
    demonstrate_serialization(&bool_value, "Bool(true)")?;
    demonstrate_serialization(&none_value, "None")?;

    // Test hex serialization
    println!("\n2. Hex Serialization:");
    let hex = uint_value.serialize_to_hex()?;
    println!("UInt(42) as hex: {}", hex);
    
    let restored = Value::deserialize_from_hex(&hex)?;
    println!("Restored from hex: {:?}", restored);
    assert_eq!(uint_value, restored);
    println!("✓ Roundtrip successful\n");

    // Test complex values
    println!("3. Complex Value Types:");
    let ok_value = Value::ok(Value::UInt(100))?;
    let error_value = Value::error(Value::Bool(false))?;
    let some_value = Value::some(Value::UInt(200))?;

    demonstrate_serialization(&ok_value, "Ok(UInt(100))")?;
    demonstrate_serialization(&error_value, "Error(Bool(false))")?;
    demonstrate_serialization(&some_value, "Some(UInt(200))")?;

    // Test custom type serialization using the macro
    println!("4. Custom Type Serialization:");
    let my_data = MyCustomData {
        value: 123,
        name: "test".to_string(),
    };
    
    let serialized = my_data.serialize();
    println!("Custom data serialized: {}", serialized);
    
    let restored = MyCustomData::deserialize(&serialized)?;
    println!("Custom data restored: {:?}", restored);
    assert_eq!(my_data.value, restored.value);
    assert_eq!(my_data.name, restored.name);
    println!("✓ Custom type roundtrip successful\n");

    println!("All examples completed successfully!");
    Ok(())
}

fn demonstrate_serialization(value: &Value, description: &str) -> Result<(), SerializationError> {
    println!("  {}: {:?}", description, value);
    
    // Serialize to bytes
    let bytes = value.serialize_to_vec()?;
    println!("    Serialized bytes: {} bytes", bytes.len());
    
    // Deserialize from bytes
    let restored = Value::deserialize_from_slice(&bytes)?;
    assert_eq!(*value, restored);
    println!("    ✓ Roundtrip successful");
    
    Ok(())
}

// Example custom type using the serialization macro
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct MyCustomData {
    value: u32,
    name: String,
}

clarity_serialization::clarity_serializable!(MyCustomData);