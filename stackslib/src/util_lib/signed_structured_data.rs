use clarity::vm::Value;
use stacks_common::{
    codec::StacksMessageCodec,
    types::PrivateKey,
    util::{
        hash::{to_hex, Sha256Sum},
        secp256k1::{MessageSignature, Secp256k1PrivateKey},
    },
};

/// Message prefix for signed structured data. "SIP018" in ascii
pub const STRUCTURED_DATA_PREFIX: [u8; 6] = [0x53, 0x49, 0x50, 0x30, 0x31, 0x38];

pub fn structured_data_hash(value: Value) -> Sha256Sum {
    let bytes = value.serialize_to_vec();
    Sha256Sum::from_data(&bytes)
}

/// Generate a message hash for signing structured Clarity data.
/// Reference [SIP018](https://github.com/stacksgov/sips/blob/main/sips/sip-018/sip-018-signed-structured-data.md) for more information.
pub fn structured_data_message_hash(structured_data: Value, domain: Value) -> Sha256Sum {
    let message = [
        STRUCTURED_DATA_PREFIX.as_ref(),
        structured_data_hash(domain).as_bytes(),
        structured_data_hash(structured_data).as_bytes(),
    ]
    .concat();

    Sha256Sum::from_data(&message)
}

/// Sign structured Clarity data with a given private key.
/// Reference [SIP018](https://github.com/stacksgov/sips/blob/main/sips/sip-018/sip-018-signed-structured-data.md) for more information.
pub fn sign_structured_data(
    structured_data: Value,
    domain: Value,
    private_key: &Secp256k1PrivateKey,
) -> Result<MessageSignature, &str> {
    let msg_hash = structured_data_message_hash(structured_data, domain);
    private_key.sign(msg_hash.as_bytes())
}

#[cfg(test)]
mod test {
    use super::*;
    use clarity::vm::types::{TupleData, Value};
    use stacks_common::{consts::CHAIN_ID_MAINNET, util::hash::to_hex};

    /// [SIP18 test vectors](https://github.com/stacksgov/sips/blob/main/sips/sip-018/sip-018-signed-structured-data.md)
    #[test]
    fn test_sip18_ref_structured_data_hash() {
        let value = Value::string_ascii_from_bytes("Hello World".into()).unwrap();
        let msg_hash = structured_data_hash(value);
        assert_eq!(
            to_hex(msg_hash.as_bytes()),
            "5297eef9765c466d945ad1cb2c81b30b9fed6c165575dc9226e9edf78b8cd9e8"
        )
    }

    /// [SIP18 test vectors](https://github.com/stacksgov/sips/blob/main/sips/sip-018/sip-018-signed-structured-data.md)
    #[test]
    fn test_sip18_ref_message_hashing() {
        let domain = Value::Tuple(
            TupleData::from_data(vec![
                (
                    "name".into(),
                    Value::string_ascii_from_bytes("Test App".into()).unwrap(),
                ),
                (
                    "version".into(),
                    Value::string_ascii_from_bytes("1.0.0".into()).unwrap(),
                ),
                ("chain-id".into(), Value::UInt(CHAIN_ID_MAINNET.into())),
            ])
            .unwrap(),
        );
        let data = Value::string_ascii_from_bytes("Hello World".into()).unwrap();

        let msg_hash = structured_data_message_hash(data, domain);

        assert_eq!(
            to_hex(msg_hash.as_bytes()),
            "1bfdab6d4158313ce34073fbb8d6b0fc32c154d439def12247a0f44bb2225259"
        );
    }

    /// [SIP18 test vectors](https://github.com/stacksgov/sips/blob/main/sips/sip-018/sip-018-signed-structured-data.md)
    #[test]
    fn test_sip18_ref_signing() {
        let key = Secp256k1PrivateKey::from_hex(
            "753b7cc01a1a2e86221266a154af739463fce51219d97e4f856cd7200c3bd2a601",
        )
        .unwrap();
        let domain = Value::Tuple(
            TupleData::from_data(vec![
                (
                    "name".into(),
                    Value::string_ascii_from_bytes("Test App".into()).unwrap(),
                ),
                (
                    "version".into(),
                    Value::string_ascii_from_bytes("1.0.0".into()).unwrap(),
                ),
                ("chain-id".into(), Value::UInt(CHAIN_ID_MAINNET.into())),
            ])
            .unwrap(),
        );
        let data = Value::string_ascii_from_bytes("Hello World".into()).unwrap();
        let signature =
            sign_structured_data(data, domain, &key).expect("Failed to sign structured data");

        let signature_rsv = signature.to_rsv();

        assert_eq!(to_hex(signature_rsv.as_slice()), "8b94e45701d857c9f1d1d70e8b2ca076045dae4920fb0160be0642a68cd78de072ab527b5c5277a593baeb2a8b657c216b99f7abb5d14af35b4bf12ba6460ba401");
    }

    #[test]
    fn test_prefix_bytes() {
        let hex = to_hex(STRUCTURED_DATA_PREFIX.as_ref());
        assert_eq!(hex, "534950303138");
    }
}
