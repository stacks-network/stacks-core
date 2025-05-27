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
        s.serialize_str(&format!("0x{}", val))
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
