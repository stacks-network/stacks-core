use clarity::vm::types::signatures::TypeSignature as ClarityTypeSignature;
use clarity::vm::types::Value as ClarityValue;
use neon::prelude::*;
use sha2::Digest;
use sha2::Sha512_256;
use stacks::{
    address::AddressHashMode,
    chainstate::stacks::{
        MultisigHashMode, MultisigSpendingCondition, SinglesigSpendingCondition, StacksPublicKey,
        StacksTransaction, TransactionAuth, TransactionAuthField, TransactionAuthFieldID,
        TransactionAuthFlags, TransactionPublicKeyEncoding, TransactionSpendingCondition,
        TransactionVersion,
    },
    types::{chainstate::StacksAddress, StacksPublicKeyBuffer},
};
use stacks_common::codec::StacksMessageCodec;
use std::convert::{TryFrom, TryInto};

fn hello(mut cx: FunctionContext) -> JsResult<JsString> {
    Ok(cx.string("test3: hello nodejs from libclarity!"))
}

fn decode_clarity_value(mut cx: FunctionContext) -> JsResult<JsString> {
    let hex_string = cx.argument::<JsString>(0)?.value(&mut cx);
    let val_bytes =
        hex::decode(hex_string).or_else(|e| cx.throw_error(format!("Parsing error: {}", e)))?;
    let byte_cursor = &mut &val_bytes[..];
    let value = ClarityValue::consensus_deserialize(byte_cursor)
        .or_else(|e| cx.throw_error(format!("{}", e)))?;
    Ok(cx.string(format!("{}", value)))
}

fn decode_clarity_value2(mut cx: FunctionContext) -> JsResult<JsString> {
    let hex_string = cx.argument::<JsString>(0)?.value(&mut cx);
    let val_bytes =
        hex::decode(hex_string).or_else(|e| cx.throw_error(format!("Parsing error: {}", e)))?;
    let byte_cursor = &mut &val_bytes[..];
    while !byte_cursor.is_empty() {
        let value = ClarityValue::consensus_deserialize(byte_cursor)
            .or_else(|e| cx.throw_error(format!("{}", e)))?;
        let value_type = ClarityTypeSignature::type_of(&value).to_string();
        return Ok(cx.string(format!("{}{}", value, value_type)));
    }
    cx.throw_error("Empty input bytes")
}

fn decode_clarity_value3(mut cx: FunctionContext) -> JsResult<JsString> {
    let hex_string = cx.argument::<JsString>(0)?.value(&mut cx);
    let val_bytes =
        hex::decode(hex_string).or_else(|e| cx.throw_error(format!("Parsing error: {}", e)))?;
    let mut byte_cursor = val_bytes.as_slice();
    while !byte_cursor.is_empty() {
        let value = ClarityValue::consensus_deserialize(&mut byte_cursor)
            .or_else(|e| cx.throw_error(format!("{}", e)))?;
        let value_type = ClarityTypeSignature::type_of(&value).to_string();
        return Ok(cx.string(format!("{}{}", value, value_type)));
    }
    cx.throw_error("Empty input bytes")
}

fn decode_clarity_value_array_old(mut cx: FunctionContext) -> JsResult<JsArray> {
    let hex_string = cx.argument::<JsString>(0)?.value(&mut cx);
    let val_bytes =
        hex::decode(hex_string).or_else(|e| cx.throw_error(format!("Parsing error: {}", e)))?;
    let array_len = u32::from_be_bytes(val_bytes[..4].try_into().unwrap());

    let val_slice = &val_bytes[4..];
    let mut byte_cursor = std::io::Cursor::new(val_slice);
    let val_len = val_slice.len() as u64;
    // let byte_len = byte_cursor.get_ref().len();
    let mut i: u32 = 0;
    let array_result = JsArray::new(&mut cx, array_len * 3);
    while byte_cursor.position() < val_len - 1 {
        let cur_start = byte_cursor.position() as usize;
        let clarity_value = ClarityValue::consensus_deserialize(&mut byte_cursor)
            .or_else(|e| cx.throw_error(format!("{}", e)))?;
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
    let input_bytes =
        hex::decode(input_hex).or_else(|e| cx.throw_error(format!("Parsing error: {}", e)))?;
    let result_length = u32::from_be_bytes(input_bytes[..4].try_into().unwrap());
    let array_result = JsArray::new(&mut cx, result_length);

    let val_slice = &input_bytes[4..];
    let mut byte_cursor = std::io::Cursor::new(val_slice);
    let val_len = val_slice.len() as u64;
    let mut i: u32 = 0;
    while byte_cursor.position() < val_len - 1 {
        let cur_start = byte_cursor.position() as usize;
        let clarity_value = ClarityValue::consensus_deserialize(&mut byte_cursor)
            .or_else(|e| cx.throw_error(format!("{}", e)))?;
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
    let val_bytes =
        hex::decode(hex_string).or_else(|e| cx.throw_error(format!("Parsing error: {}", e)))?;
    let array_len = u32::from_be_bytes(val_bytes[0..4].try_into().unwrap());
    Ok(cx.string(array_len.to_string()))
}

fn decode_transaction(mut cx: FunctionContext) -> JsResult<JsObject> {
    let hex_string = cx.argument::<JsString>(0)?.value(&mut cx);
    let val_bytes =
        hex::decode(hex_string).or_else(|e| cx.throw_error(format!("Parsing error: {}", e)))?;
    // let tx_id = Txid::from_stacks_tx(&val_bytes);
    let byte_cursor = &mut &val_bytes[..];
    let tx = StacksTransaction::consensus_deserialize(byte_cursor)
        .or_else(|e| cx.throw_error(format!("Failed to decode transaction: {:?}\n", &e)))?;
    let tx_json_obj = cx.empty_object();

    let tx_id_bytes = Sha512_256::digest(val_bytes);
    let tx_id = cx.string(format!("0x{}", hex::encode(tx_id_bytes)));
    tx_json_obj.set(&mut cx, "tx_id", tx_id)?;

    tx.neon_js_serialize(&mut cx, &tx_json_obj, &())?;
    // let tx_json = serde_json::to_string(&tx).or_else(|e| cx.throw_error(format!("Failed to serialize transaction to JSON: {}", e)))?;
    Ok(tx_json_obj)
}

/*
pub fn new<'a, C: Context<'a>>(cx: &mut C, len: u32) -> Handle<'a, JsArray> {
    JsArray::new_internal(cx.env(), len)
}
*/

/*
pub trait NeonJsSerialize {
    fn neon_js_serialize(&self, cx: &mut FunctionContext, obj: &Handle<JsObject>) -> NeonResult<()>;
}
*/

pub trait NeonJsSerialize<ExtraCtx = ()> {
    fn neon_js_serialize(
        &self,
        cx: &mut FunctionContext,
        obj: &Handle<JsObject>,
        extra_ctx: &ExtraCtx,
    ) -> NeonResult<()>;
}
pub trait NeonJsSerializeWithContext<SerializationContext> {
    fn neon_js_serialize(
        &self,
        cx: &mut FunctionContext,
        obj: &Handle<JsObject>,
        serialization_context: &SerializationContext,
    ) -> NeonResult<()>;
}

impl NeonJsSerialize for StacksTransaction {
    fn neon_js_serialize(
        &self,
        cx: &mut FunctionContext,
        obj: &Handle<JsObject>,
        _extra_ctx: &(),
    ) -> NeonResult<()> {
        let version_number = cx.number(self.version as u8);
        obj.set(cx, "version", version_number)?;

        let chain_id = cx.number(self.chain_id);
        obj.set(cx, "chain_id", chain_id)?;

        let auth_obj = cx.empty_object();
        self.auth.neon_js_serialize(
            cx,
            &auth_obj,
            &TxSerializationContext {
                transaction_version: self.version,
            },
        )?;
        obj.set(cx, "auth", auth_obj)?;

        // write_next(fd, &(self.version as u8))?;
        // write_next(fd, &self.chain_id)?;
        // write_next(fd, &self.auth)?;
        // write_next(fd, &(self.anchor_mode as u8))?;
        // write_next(fd, &(self.post_condition_mode as u8))?;
        // write_next(fd, &self.post_conditions)?;
        // write_next(fd, &self.payload)?;
        Ok(())
    }
}

struct TxSerializationContext {
    transaction_version: TransactionVersion,
}

impl NeonJsSerialize<TxSerializationContext> for TransactionAuth {
    fn neon_js_serialize(
        &self,
        cx: &mut FunctionContext,
        obj: &Handle<JsObject>,
        extra_ctx: &TxSerializationContext,
    ) -> NeonResult<()> {
        match *self {
            TransactionAuth::Standard(ref origin_condition) => {
                let type_id = cx.number(TransactionAuthFlags::AuthStandard as u8);
                obj.set(cx, "type_id", type_id)?;

                let origin_condition_obj = cx.empty_object();
                origin_condition.neon_js_serialize(cx, &origin_condition_obj, extra_ctx)?;
                obj.set(cx, "origin_condition", origin_condition_obj)?;
            }
            TransactionAuth::Sponsored(ref origin_condition, ref sponsor_condition) => {
                let type_id = cx.number(TransactionAuthFlags::AuthSponsored as u8);
                obj.set(cx, "type_id", type_id)?;

                let origin_condition_obj = cx.empty_object();
                origin_condition.neon_js_serialize(cx, &origin_condition_obj, extra_ctx)?;
                obj.set(cx, "origin_condition", origin_condition_obj)?;

                let sponsor_condition_obj = cx.empty_object();
                sponsor_condition.neon_js_serialize(cx, &sponsor_condition_obj, extra_ctx)?;
                obj.set(cx, "sponsor_condition", sponsor_condition_obj)?;
            }
        }
        Ok(())
    }
}

impl NeonJsSerialize<TxSerializationContext> for TransactionSpendingCondition {
    fn neon_js_serialize(
        &self,
        cx: &mut FunctionContext,
        obj: &Handle<JsObject>,
        extra_ctx: &TxSerializationContext,
    ) -> NeonResult<()> {
        match *self {
            TransactionSpendingCondition::Singlesig(ref data) => {
                data.neon_js_serialize(cx, obj, &extra_ctx)?;
            }
            TransactionSpendingCondition::Multisig(ref data) => {
                data.neon_js_serialize(cx, obj, &())?;
            }
        }
        Ok(())
    }
}

/*
impl StacksMessageCodec for SinglesigSpendingCondition {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &(self.hash_mode.clone() as u8))?;
        write_next(fd, &self.signer)?;
        write_next(fd, &self.nonce)?;
        write_next(fd, &self.tx_fee)?;
        write_next(fd, &(self.key_encoding.clone() as u8))?;
        write_next(fd, &self.signature)?;
        Ok(())
    }
}
*/

/*
pub struct MultisigSpendingCondition {
    pub hash_mode: MultisigHashMode,
    pub signer: Hash160,
    pub nonce: u64,  // nth authorization from this account
    pub tx_fee: u64, // microSTX/compute rate offered by this account
    pub fields: Vec<TransactionAuthField>,
    pub signatures_required: u16,
}

pub struct SinglesigSpendingCondition {
    pub hash_mode: SinglesigHashMode,
    pub signer: Hash160,
    pub nonce: u64,  // nth authorization from this account
    pub tx_fee: u64, // microSTX/compute rate offerred by this account
    pub key_encoding: TransactionPublicKeyEncoding,
    pub signature: MessageSignature,
}
*/

/*
trait SpendingConditionCommon {
    fn get_hash_mode(&self) -> u8;
    fn get_signer(&self) -> &Hash160;
    fn get_nonce(&self) -> u64;
    fn get_tx_fee(&self) -> u64;
}

impl SpendingConditionCommon for SinglesigSpendingCondition {
    fn get_hash_mode(&self) -> u8 {
        self.hash_mode.clone() as u8
    }
    fn get_signer(&self) -> &Hash160 {
        &self.signer
    }
    fn get_nonce(&self) -> u64 {
        self.nonce
    }
    fn get_tx_fee(&self) -> u64 {
        self.tx_fee
    }
}
*/

impl NeonJsSerializeWithContext<TxSerializationContext> for SinglesigSpendingCondition {
    fn neon_js_serialize(
        &self,
        cx: &mut FunctionContext,
        obj: &Handle<JsObject>,
        extra_ctx: &TxSerializationContext,
    ) -> NeonResult<()> {
        let hash_mode_int = self.hash_mode.clone() as u8;

        let hash_mode = cx.number(hash_mode_int);
        obj.set(cx, "hash_mode", hash_mode)?;

        let signer = cx.string(format!("0x{}", hex::encode(&self.signer)));
        obj.set(cx, "signer", signer)?;

        let nonce = cx.string(self.nonce.to_string());
        obj.set(cx, "nonce", nonce)?;

        let tx_fee = cx.string(self.tx_fee.to_string());
        obj.set(cx, "tx_fee", tx_fee)?;

        let key_encoding = cx.number(self.key_encoding as u8);
        obj.set(cx, "key_encoding", key_encoding)?;

        let signature = cx.string(format!("0x{}", hex::encode(&self.signature)));
        obj.set(cx, "signature", signature)?;

        let stacks_address_hash_mode = AddressHashMode::try_from(hash_mode_int).unwrap();
        let stacks_address_version = match extra_ctx.transaction_version {
            TransactionVersion::Mainnet => stacks_address_hash_mode.to_version_mainnet(),
            TransactionVersion::Testnet => stacks_address_hash_mode.to_version_testnet(),
        };
        let stacks_address =
            cx.string(StacksAddress::new(stacks_address_version, self.signer).to_string());
        obj.set(cx, "stacks_address", stacks_address)?;

        Ok(())
    }
}

impl NeonJsSerialize for MultisigSpendingCondition {
    fn neon_js_serialize(
        &self,
        cx: &mut FunctionContext,
        obj: &Handle<JsObject>,
        _extra_ctx: &(),
    ) -> NeonResult<()> {
        let hash_mode = cx.number(self.hash_mode.clone() as u8);
        obj.set(cx, "hash_mode", hash_mode)?;

        let signer = cx.string(format!("0x{}", hex::encode(&self.signer)));
        obj.set(cx, "signer", signer)?;

        let nonce = cx.string(self.nonce.to_string());
        obj.set(cx, "nonce", nonce)?;

        let tx_fee = cx.string(self.tx_fee.to_string());
        obj.set(cx, "tx_fee", tx_fee)?;

        let fields = JsArray::new(cx, self.fields.len().try_into().unwrap());
        for (i, x) in self.fields.iter().enumerate() {
            /*
            let context = TransactionAuthFieldContext {
                version: 1,
                hash_mode: &AddressHashMode::from_version(1),
                num_sigs: todo!(),
                pubkeys: todo!(),
            };
            */
            let field_obj = cx.empty_object();
            x.neon_js_serialize(cx, &field_obj, &())?;
            fields.set(cx, i as u32, field_obj)?;
        }
        obj.set(cx, "fields", fields)?;

        let signatures_required = cx.number(self.signatures_required);
        obj.set(cx, "signatures_required", signatures_required)?;

        Ok(())
    }
}

/*
export function getTxSenderAddress(tx: Transaction): string {
  const txSender = getAddressFromPublicKeyHash(
    tx.auth.originCondition.signer,
    tx.auth.originCondition.hashMode as number,
    tx.version
  );
  return txSender;
}
*/

// impl NeonJsSerializeWithContext<TransactionAuthFieldContext<'_>> for Secp256k1PublicKey {
/*
impl NeonJsSerialize for Secp256k1PublicKey {
    fn neon_js_serialize(&self, cx: &mut FunctionContext, obj: &Handle<JsObject>, _extra_ctx: &()) -> NeonResult<()> {
        let field_id = if self.compressed() {
            TransactionAuthFieldID::PublicKeyCompressed
        } else {
            TransactionAuthFieldID::PublicKeyUncompressed
        };
        let type_id = cx.number(field_id as u8);
        obj.set(cx, "type_id", type_id)?;

        let pubkey_buf = StacksPublicKeyBuffer::from_public_key(self);
        let pubkey_hex = cx.string(format!("0x{}", hex::encode(pubkey_buf)));
        obj.set(cx, "public_key", pubkey_hex)?;

        // TODO: add stacks-address encoded format
        // let stacks_address = StacksAddress::from_public_keys().unwrap();

        Ok(())
    }
}
*/

// impl NeonJsSerializeWithContext<TransactionAuthFieldContext<'_>> for TransactionAuthField {
impl NeonJsSerialize for TransactionAuthField {
    fn neon_js_serialize(
        &self,
        cx: &mut FunctionContext,
        obj: &Handle<JsObject>,
        _extra_ctx: &(),
    ) -> NeonResult<()> {
        match *self {
            TransactionAuthField::PublicKey(ref pubkey) => {
                let field_id = if pubkey.compressed() {
                    TransactionAuthFieldID::PublicKeyCompressed
                } else {
                    TransactionAuthFieldID::PublicKeyUncompressed
                };
                let type_id = cx.number(field_id as u8);
                obj.set(cx, "type_id", type_id)?;

                let pubkey_buf = StacksPublicKeyBuffer::from_public_key(pubkey);
                let pubkey_hex = cx.string(format!("0x{}", hex::encode(pubkey_buf)));
                obj.set(cx, "public_key", pubkey_hex)?;

                // TODO: add stacks-address encoded format
                // let stacks_address = StacksAddress::from_public_keys().unwrap();
            }
            TransactionAuthField::Signature(ref key_encoding, ref sig) => {
                let field_id = if *key_encoding == TransactionPublicKeyEncoding::Compressed {
                    TransactionAuthFieldID::SignatureCompressed
                } else {
                    TransactionAuthFieldID::SignatureUncompressed
                };
                let type_id = cx.number(field_id as u8);
                obj.set(cx, "type_id", type_id)?;

                let pubkey_hex = cx.string(format!("0x{}", hex::encode(sig)));
                obj.set(cx, "signature", pubkey_hex)?;
            }
        }
        Ok(())
    }
}

/*
pub trait StacksMessageCodec {
    /// serialize implementors _should never_ error unless there is an underlying
    ///   failure in writing to the `fd`
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), Error>
    where
        Self: Sized;
    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, Error>
    where
        Self: Sized;
    /// Convenience for serialization to a vec.
    ///  this function unwraps any underlying serialization error
    fn serialize_to_vec(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        let mut bytes = vec![];
        self.consensus_serialize(&mut bytes)
            .expect("BUG: serialization to buffer failed.");
        bytes
    }
}
impl StacksMessageCodec for StacksTransaction {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &(self.version as u8))?;
        write_next(fd, &self.chain_id)?;
        write_next(fd, &self.auth)?;
        write_next(fd, &(self.anchor_mode as u8))?;
        write_next(fd, &(self.post_condition_mode as u8))?;
        write_next(fd, &self.post_conditions)?;
        write_next(fd, &self.payload)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<StacksTransaction, codec_error> {
        StacksTransaction::consensus_deserialize_with_len(fd).map(|(result, _)| result)
    }
}
*/

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
    cx.export_function("decodeTransaction", decode_transaction)?;
    Ok(())
}
