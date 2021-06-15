pub use vm::analysis::errors::{CheckError, CheckErrors};
use vm::execute;
use vm::types::BufferLength;
use vm::types::SequenceSubtype::{BufferType, StringType};
use vm::types::StringSubtype::ASCII;
use vm::types::TypeSignature::SequenceType;
use vm::types::{ASCIIData, BuffData, CharType, SequenceData, Value};
use vm::ClarityVersion;

#[test]
fn test_simple_principal_one() {
	// For little endian, 0001 at the beginning should be interpreted as the least significant bit.
	let good1_test = "(to-int 1)";
	let good1_expected = Value::UInt(256);
	assert_eq!(good1_expected, execute(good1_test).unwrap().unwrap());
}