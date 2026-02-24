/// This module serde encodes and decodes optional byte fields in RPC
/// responses as Some(String) where the String is a `0x` prefixed
/// hex string.
pub mod prefix_opt_hex {
    pub fn serialize<S: serde::Serializer, T: std::fmt::LowerHex>(
        val: &Option<T>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match val {
            Some(ref some_val) => {
                let val_str = format!("0x{some_val:x}");
                s.serialize_some(&val_str)
            }
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>, T: crate::util::HexDeser>(
        d: D,
    ) -> Result<Option<T>, D::Error> {
        let opt_inst_str: Option<String> = serde::Deserialize::deserialize(d)?;
        let Some(inst_str) = opt_inst_str else {
            return Ok(None);
        };
        let Some(hex_str) = inst_str.get(2..) else {
            return Err(serde::de::Error::invalid_length(
                inst_str.len(),
                &"at least length 2 string",
            ));
        };
        let val = T::try_from_hex(hex_str).map_err(serde::de::Error::custom)?;
        Ok(Some(val))
    }
}

/// This module serde encodes and decodes byte fields in RPC
/// responses as a String where the String is a `0x` prefixed
/// hex string.
pub mod prefix_hex {
    pub fn serialize<S: serde::Serializer, T: std::fmt::LowerHex>(
        val: &T,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{val:x}"))
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>, T: crate::util::HexDeser>(
        d: D,
    ) -> Result<T, D::Error> {
        let inst_str: String = serde::Deserialize::deserialize(d)?;
        let Some(hex_str) = inst_str.get(2..) else {
            return Err(serde::de::Error::invalid_length(
                inst_str.len(),
                &"at least length 2 string",
            ));
        };
        T::try_from_hex(hex_str).map_err(serde::de::Error::custom)
    }
}

/// This module serde encodes and decodes byte fields in RPC
/// responses as a String where the String is a `0x` prefixed
/// hex string.
pub mod prefix_hex_byte_array {
    use crate::util::hash::{hex_bytes, to_hex};

    pub fn serialize<S: serde::Serializer>(val: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{}", to_hex(val)))
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let inst_str: String = serde::Deserialize::deserialize(d)?;
        let Some(hex_str) = inst_str.get(2..) else {
            return Err(serde::de::Error::invalid_length(
                inst_str.len(),
                &"at least length 2 string",
            ));
        };
        if inst_str.get(0..2) != Some("0x") {
            return Err(serde::de::Error::custom("must supply 0x-prefix"));
        }
        if hex_str.len() != N * 2 {
            return Err(serde::de::Error::invalid_length(
                inst_str.len(),
                &"expected length 2 * expected array length",
            ));
        }
        let bytes = hex_bytes(hex_str).map_err(serde::de::Error::custom)?;
        bytes.try_into().map_err(|b: Vec<u8>|
                                 // error should be unreachable because of the length check above 
                                 serde::de::Error::invalid_length(
                                     b.len(),
                                     &"expected exact array length",
                                 ))
    }
}

/// This module serde encode and decodes structs that
/// implement StacksMessageCodec as a 0x-prefixed hex string.
pub mod prefix_hex_codec {
    use crate::codec::StacksMessageCodec;
    use crate::util::hash::{hex_bytes, to_hex};

    pub fn serialize<S: serde::Serializer, T: StacksMessageCodec>(
        val: &T,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let mut bytes = vec![];
        val.consensus_serialize(&mut bytes)
            .map_err(serde::ser::Error::custom)?;
        s.serialize_str(&format!("0x{}", to_hex(&bytes)))
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>, T: StacksMessageCodec>(
        d: D,
    ) -> Result<T, D::Error> {
        let inst_str: String = serde::Deserialize::deserialize(d)?;
        let Some(hex_str) = inst_str.get(2..) else {
            return Err(serde::de::Error::invalid_length(
                inst_str.len(),
                &"at least length 2 string",
            ));
        };
        let bytes = hex_bytes(hex_str).map_err(serde::de::Error::custom)?;
        T::consensus_deserialize(&mut &bytes[..]).map_err(serde::de::Error::custom)
    }
}

/// This module serde encode and decodes structs that
/// implement StacksMessageCodec as a 0x-prefixed hex string.
/// This is the same as prefix_hex_codec, but for Option<T>.
pub mod prefix_opt_hex_codec {
    use crate::codec::StacksMessageCodec;
    use crate::util::hash::{hex_bytes, to_hex};

    pub fn serialize<S: serde::Serializer, T: StacksMessageCodec>(
        val: &Option<T>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match val {
            Some(ref some_val) => {
                let mut bytes = vec![];
                some_val
                    .consensus_serialize(&mut bytes)
                    .map_err(serde::ser::Error::custom)?;
                let hex_string = format!("0x{}", to_hex(&bytes));
                s.serialize_some(&hex_string)
            }
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>, T: StacksMessageCodec>(
        d: D,
    ) -> Result<Option<T>, D::Error> {
        let opt_inst_str: Option<String> = serde::Deserialize::deserialize(d)?;
        let Some(inst_string) = opt_inst_str else {
            return Ok(None);
        };
        let Some(hex_str) = inst_string.get(2..) else {
            return Err(serde::de::Error::invalid_length(
                inst_string.len(),
                &"at least length 2 string",
            ));
        };
        let bytes = hex_bytes(hex_str).map_err(serde::de::Error::custom)?;
        let val = T::consensus_deserialize(&mut &bytes[..]).map_err(serde::de::Error::custom)?;
        Ok(Some(val))
    }
}

/// Serialize strings as 0x-prefixed strings.
pub mod prefix_string_0x {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(val: &str, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{val}"))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
        let s: String = Deserialize::deserialize(d)?;
        let Some(hex_str) = s.get(2..) else {
            return Err(serde::de::Error::invalid_length(
                s.len(),
                &"at least length 2 string",
            ));
        };
        Ok(hex_str.to_string())
    }
}

#[cfg(test)]
mod tests {
    fn ser_helper<const N: usize>(bytes: &[u8; N]) -> Result<String, serde_json::Error> {
        let mut ser = serde_json::Serializer::new(vec![]);
        super::prefix_hex_byte_array::serialize(bytes, &mut ser)?;
        // read the json string (i.e., "\"0x00\"") into the hex string ("0x00")
        let out = serde_json::from_slice(&ser.into_inner()).unwrap();
        Ok(out)
    }

    fn deser_helper<const N: usize>(hex: &str) -> Result<[u8; N], serde_json::Error> {
        let json_str = format!("\"{hex}\"");
        let mut deser = serde_json::Deserializer::from_str(&json_str);
        super::prefix_hex_byte_array::deserialize(&mut deser)
    }

    #[test]
    fn prefix_hex_byte_array_errors() {
        let err = deser_helper::<1>("0").unwrap_err();
        assert!(err.to_string().contains("at least length 2 string"));
        let err = deser_helper::<1>("00aa").unwrap_err();
        assert!(err.to_string().contains("must supply 0x-prefix"));
        let err = deser_helper::<1>("0x").unwrap_err();
        assert!(err.to_string().contains("invalid length 2"));
        let err = deser_helper::<2>("0x00").unwrap_err();
        assert!(err.to_string().contains("invalid length 4"));
        let err = deser_helper::<3>("0x000").unwrap_err();
        assert!(err.to_string().contains("invalid length 5"));
        let err = deser_helper::<3>("0x00aaq1").unwrap_err();
        assert!(err.to_string().contains("bad character q for hex string"));
    }

    #[test]
    fn prefix_hex_byte_array_okay() {
        let n1_fixtures = [([0x00u8], "0x00"), ([0xff], "0xFf")];
        for (bytes, hex) in n1_fixtures.iter() {
            let out = deser_helper(hex).unwrap();
            assert_eq!(out, *bytes);
            let out = ser_helper(bytes).unwrap();
            assert_eq!(&out, &hex.to_ascii_lowercase());
        }
        let n5_fixtures = [
            ([0xff, 0xaa, 0xbc, 0x1f, 0x24], "0xffaabC1f24"),
            ([0xff, 0x00, 0xbc, 0x1f, 0x24], "0xff00Bc1f24"),
            ([0xff, 0xaa, 0xac, 0x0f, 0x24], "0xffaaac0F24"),
        ];
        for (bytes, hex) in n5_fixtures.iter() {
            let out = deser_helper(hex).unwrap();
            assert_eq!(out, *bytes);
            let out = ser_helper(bytes).unwrap();
            assert_eq!(&out, &hex.to_ascii_lowercase());
        }
        let out: [u8; 0] = deser_helper("0x").unwrap();
        let test: [u8; 0] = [];
        assert_eq!(out, test);
        let out = ser_helper(&test).unwrap();
        assert_eq!("0x", out);
    }
}
