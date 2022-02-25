use clarity::vm::types::signatures::TypeSignature as ClarityTypeSignature;
use clarity::vm::types::Value as ClarityValue;
use neon::prelude::*;
use sha2::Digest;
use sha2::Sha512_256;
use stacks::chainstate::stacks::AssetInfo;
use stacks::chainstate::stacks::AssetInfoID;
use stacks::chainstate::stacks::PostConditionPrincipal;
use stacks::chainstate::stacks::PostConditionPrincipalID;
use stacks::chainstate::stacks::StacksMicroblockHeader;
use stacks::chainstate::stacks::TransactionContractCall;
use stacks::chainstate::stacks::TransactionPayload;
use stacks::chainstate::stacks::TransactionPayloadID;
use stacks::chainstate::stacks::TransactionPostCondition;
use stacks::chainstate::stacks::TransactionSmartContract;
use stacks::vm::types::PrincipalData;
use stacks::{
    address::AddressHashMode,
    chainstate::stacks::{
        MultisigSpendingCondition, SinglesigSpendingCondition, StacksTransaction, TransactionAuth,
        TransactionAuthField, TransactionAuthFieldID, TransactionAuthFlags,
        TransactionPublicKeyEncoding, TransactionSpendingCondition, TransactionVersion,
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
        let value_slice = &val_slice[cur_start..cur_end];
        let value_hex = cx.string(format!("0x{}", hex::encode(value_slice)));
        let value_type = cx.string(ClarityTypeSignature::type_of(&clarity_value).to_string());
        let value_repr = cx.string(clarity_value.to_string());
        let value_obj = cx.empty_object();
        let value_buff = JsBuffer::external(&mut cx, value_slice.to_vec());
        value_obj.set(&mut cx, "type", value_type)?;
        value_obj.set(&mut cx, "repr", value_repr)?;
        value_obj.set(&mut cx, "hex", value_hex)?;
        value_obj.set(&mut cx, "buffer", value_buff)?;
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

pub trait NeonJsSerialize<ExtraCtx = (), TResult = ()> {
    fn neon_js_serialize(
        &self,
        cx: &mut FunctionContext,
        obj: &Handle<JsObject>,
        extra_ctx: &ExtraCtx,
    ) -> NeonResult<TResult>;
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

        let anchor_mode = cx.number(self.anchor_mode as u8);
        obj.set(cx, "anchor_mode", anchor_mode)?;

        let post_condition_mode = cx.number(self.post_condition_mode as u8);
        obj.set(cx, "post_condition_mode", post_condition_mode)?;

        // TODO: raw post conditions binary slice is already determined during raw tx deserialization, ideally
        // try to use that rather than re-serializing (slow)
        let mut post_conditions_raw = u32::to_be_bytes(self.post_conditions.len() as u32).to_vec();
        let post_conditions = JsArray::new(cx, self.post_conditions.len() as u32);
        for (i, x) in self.post_conditions.iter().enumerate() {
            let post_condition_obj = cx.empty_object();
            let mut val_bytes = x.neon_js_serialize(cx, &post_condition_obj, &())?;
            post_conditions_raw.append(&mut val_bytes);
            post_conditions.set(cx, i as u32, post_condition_obj)?;
        }
        obj.set(cx, "post_conditions", post_conditions)?;

        let post_conditions_buff = JsBuffer::external(cx, post_conditions_raw);
        obj.set(cx, "post_conditions_buffer", post_conditions_buff)?;

        let payload_obj = cx.empty_object();
        self.payload.neon_js_serialize(cx, &payload_obj, &())?;
        obj.set(cx, "payload", payload_obj)?;

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
                data.neon_js_serialize(cx, obj, &extra_ctx)?;
            }
        }
        Ok(())
    }
}

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

impl NeonJsSerialize<TxSerializationContext> for SinglesigSpendingCondition {
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

        let stacks_address_hash_mode = AddressHashMode::try_from(hash_mode_int).unwrap();
        let stacks_address_version = match extra_ctx.transaction_version {
            TransactionVersion::Mainnet => stacks_address_hash_mode.to_version_mainnet(),
            TransactionVersion::Testnet => stacks_address_hash_mode.to_version_testnet(),
        };
        let stacks_address =
            cx.string(StacksAddress::new(stacks_address_version, self.signer).to_string());
        obj.set(cx, "signer_stacks_address", stacks_address)?;

        let nonce = cx.string(self.nonce.to_string());
        obj.set(cx, "nonce", nonce)?;

        let tx_fee = cx.string(self.tx_fee.to_string());
        obj.set(cx, "tx_fee", tx_fee)?;

        let key_encoding = cx.number(self.key_encoding as u8);
        obj.set(cx, "key_encoding", key_encoding)?;

        let signature = cx.string(format!("0x{}", hex::encode(&self.signature)));
        obj.set(cx, "signature", signature)?;

        Ok(())
    }
}

impl NeonJsSerialize<TxSerializationContext> for MultisigSpendingCondition {
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

        let stacks_address_hash_mode = AddressHashMode::try_from(hash_mode_int).unwrap();
        let stacks_address_version = match extra_ctx.transaction_version {
            TransactionVersion::Mainnet => stacks_address_hash_mode.to_version_mainnet(),
            TransactionVersion::Testnet => stacks_address_hash_mode.to_version_testnet(),
        };
        let stacks_address =
            cx.string(StacksAddress::new(stacks_address_version, self.signer).to_string());
        obj.set(cx, "signer_stacks_address", stacks_address)?;

        let nonce = cx.string(self.nonce.to_string());
        obj.set(cx, "nonce", nonce)?;

        let tx_fee = cx.string(self.tx_fee.to_string());
        obj.set(cx, "tx_fee", tx_fee)?;

        let fields = JsArray::new(cx, self.fields.len().try_into().unwrap());
        for (i, x) in self.fields.iter().enumerate() {
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

impl NeonJsSerialize<(), Vec<u8>> for TransactionPostCondition {
    fn neon_js_serialize(
        &self,
        cx: &mut FunctionContext,
        obj: &Handle<JsObject>,
        extra_ctx: &(),
    ) -> NeonResult<Vec<u8>> {
        match *self {
            TransactionPostCondition::STX(ref principal, ref fungible_condition, ref amount) => {
                let asset_info_id = cx.number(AssetInfoID::STX as u8);
                obj.set(cx, "asset_info_id", asset_info_id)?;

                let pricipal_obj = cx.empty_object();
                principal.neon_js_serialize(cx, &pricipal_obj, extra_ctx)?;
                obj.set(cx, "principal", pricipal_obj)?;

                let condition_code = cx.number(*fungible_condition as u8);
                obj.set(cx, "condition_code", condition_code)?;

                let amount_str = cx.string(amount.to_string());
                obj.set(cx, "amount", amount_str)?;
            }
            TransactionPostCondition::Fungible(
                ref principal,
                ref asset_info,
                ref fungible_condition,
                ref amount,
            ) => {
                let asset_info_id = cx.number(AssetInfoID::FungibleAsset as u8);
                obj.set(cx, "asset_info_id", asset_info_id)?;

                let pricipal_obj = cx.empty_object();
                principal.neon_js_serialize(cx, &pricipal_obj, extra_ctx)?;
                obj.set(cx, "principal", pricipal_obj)?;

                let asset_info_obj = cx.empty_object();
                asset_info.neon_js_serialize(cx, &asset_info_obj, extra_ctx)?;
                obj.set(cx, "asset", asset_info_obj)?;

                let condition_code = cx.number(*fungible_condition as u8);
                obj.set(cx, "condition_code", condition_code)?;

                let amount_str = cx.string(amount.to_string());
                obj.set(cx, "amount", amount_str)?;
            }
            TransactionPostCondition::Nonfungible(
                ref principal,
                ref asset_info,
                ref asset_value,
                ref nonfungible_condition,
            ) => {
                let asset_info_id = cx.number(AssetInfoID::NonfungibleAsset as u8);
                obj.set(cx, "asset_info_id", asset_info_id)?;

                let pricipal_obj = cx.empty_object();
                principal.neon_js_serialize(cx, &pricipal_obj, extra_ctx)?;
                obj.set(cx, "principal", pricipal_obj)?;

                let asset_info_obj = cx.empty_object();
                asset_info.neon_js_serialize(cx, &asset_info_obj, extra_ctx)?;
                obj.set(cx, "asset", asset_info_obj)?;

                let asset_value_obj = cx.empty_object();
                asset_value.neon_js_serialize(cx, &asset_value_obj, extra_ctx)?;
                obj.set(cx, "asset_value", asset_value_obj)?;

                let condition_code = cx.number(*nonfungible_condition as u8);
                obj.set(cx, "condition_code", condition_code)?;
            }
        };
        let value_bytes = TransactionPostCondition::serialize_to_vec(&self);
        Ok(value_bytes)
    }
}

impl NeonJsSerialize for PostConditionPrincipal {
    fn neon_js_serialize(
        &self,
        cx: &mut FunctionContext,
        obj: &Handle<JsObject>,
        _extra_ctx: &(),
    ) -> NeonResult<()> {
        match *self {
            PostConditionPrincipal::Origin => {
                let type_id = cx.number(PostConditionPrincipalID::Origin as u8);
                obj.set(cx, "type_id", type_id)?;
            }
            PostConditionPrincipal::Standard(ref address) => {
                let type_id = cx.number(PostConditionPrincipalID::Standard as u8);
                obj.set(cx, "type_id", type_id)?;

                let address_str = cx.string(address.to_string());
                obj.set(cx, "address", address_str)?;
            }
            PostConditionPrincipal::Contract(ref address, ref contract_name) => {
                let type_id = cx.number(PostConditionPrincipalID::Contract as u8);
                obj.set(cx, "type_id", type_id)?;

                let address_str = cx.string(address.to_string());
                obj.set(cx, "address", address_str)?;

                let contract_str = cx.string(contract_name.to_string());
                obj.set(cx, "contract_name", contract_str)?;
            }
        }
        Ok(())
    }
}

impl NeonJsSerialize for AssetInfo {
    fn neon_js_serialize(
        &self,
        cx: &mut FunctionContext,
        obj: &Handle<JsObject>,
        _extra_ctx: &(),
    ) -> NeonResult<()> {
        let contract_address = cx.string(self.contract_address.to_string());
        obj.set(cx, "contract_address", contract_address)?;

        let contract_name = cx.string(self.contract_name.to_string());
        obj.set(cx, "contract_name", contract_name)?;

        let asset_name = cx.string(self.asset_name.to_string());
        obj.set(cx, "asset_name", asset_name)?;
        Ok(())
    }
}

impl NeonJsSerialize<(), Vec<u8>> for ClarityValue {
    fn neon_js_serialize(
        &self,
        cx: &mut FunctionContext,
        obj: &Handle<JsObject>,
        _extra_ctx: &(),
    ) -> NeonResult<Vec<u8>> {
        let value_bytes = ClarityValue::serialize_to_vec(&self);
        let value_hex = cx.string(format!("0x{}", hex::encode(&value_bytes)));
        let value_type = cx.string(ClarityTypeSignature::type_of(self).to_string());
        let value_repr = cx.string(self.to_string());
        // TODO: raw clarity value binary slice is already determined during deserialization, ideally
        // try to use that rather than re-serializing (slow)
        let value_buff = JsBuffer::external(cx, value_bytes.to_vec());
        obj.set(cx, "type", value_type)?;
        obj.set(cx, "repr", value_repr)?;
        obj.set(cx, "hex", value_hex)?;
        obj.set(cx, "buffer", value_buff)?;
        Ok(value_bytes)
    }
}

impl NeonJsSerialize for TransactionPayload {
    fn neon_js_serialize(
        &self,
        cx: &mut FunctionContext,
        obj: &Handle<JsObject>,
        extra_ctx: &(),
    ) -> NeonResult<()> {
        match *self {
            TransactionPayload::TokenTransfer(ref address, ref amount, ref memo) => {
                let type_id = cx.number(TransactionPayloadID::TokenTransfer as u8);
                obj.set(cx, "type_id", type_id)?;

                let recipient_obj = cx.empty_object();
                address.neon_js_serialize(cx, &recipient_obj, extra_ctx)?;
                obj.set(cx, "recipient", recipient_obj)?;

                let amount_str = cx.string(amount.to_string());
                obj.set(cx, "amount", amount_str)?;

                let memo_hex = cx.string(format!("0x{}", hex::encode(memo)));
                obj.set(cx, "memo", memo_hex)?;
            }
            TransactionPayload::ContractCall(ref contract_call) => {
                let type_id = cx.number(TransactionPayloadID::ContractCall as u8);
                obj.set(cx, "type_id", type_id)?;

                contract_call.neon_js_serialize(cx, obj, extra_ctx)?;
            }
            TransactionPayload::SmartContract(ref smart_contract) => {
                let type_id = cx.number(TransactionPayloadID::SmartContract as u8);
                obj.set(cx, "type_id", type_id)?;

                smart_contract.neon_js_serialize(cx, obj, extra_ctx)?;
            }
            TransactionPayload::PoisonMicroblock(ref h1, ref h2) => {
                let type_id = cx.number(TransactionPayloadID::PoisonMicroblock as u8);
                obj.set(cx, "type_id", type_id)?;

                let microblock_header_1_obj = cx.empty_object();
                h1.neon_js_serialize(cx, &microblock_header_1_obj, extra_ctx)?;
                obj.set(cx, "microblock_header_1", microblock_header_1_obj)?;

                let microblock_header_2_obj = cx.empty_object();
                h2.neon_js_serialize(cx, &microblock_header_2_obj, extra_ctx)?;
                obj.set(cx, "microblock_header_2", microblock_header_2_obj)?;
            }
            TransactionPayload::Coinbase(ref buf) => {
                let type_id = cx.number(TransactionPayloadID::Coinbase as u8);
                obj.set(cx, "type_id", type_id)?;

                let payload_buffer = JsBuffer::external(cx, buf.to_bytes());
                obj.set(cx, "payload_buffer", payload_buffer)?;
            }
        }
        Ok(())
    }
}

impl NeonJsSerialize for PrincipalData {
    fn neon_js_serialize(
        &self,
        cx: &mut FunctionContext,
        obj: &Handle<JsObject>,
        _extra_ctx: &(),
    ) -> NeonResult<()> {
        match self {
            PrincipalData::Standard(standard_principal) => {
                let type_int = 0x05; // TypePrefix::PrincipalStandard
                let type_id = cx.number(type_int);
                obj.set(cx, "type_id", type_id)?;

                let address = cx.string(standard_principal.to_address());
                obj.set(cx, "address", address)?;
            }
            PrincipalData::Contract(contract_identifier) => {
                let type_int = 0x06; // TypePrefix::PrincipalContract
                let type_id = cx.number(type_int);
                obj.set(cx, "type_id", type_id)?;

                let address = cx.string(contract_identifier.issuer.to_address());
                obj.set(cx, "address", address)?;

                let contract_name = cx.string(contract_identifier.name.to_string());
                obj.set(cx, "contract_name", contract_name)?;
            }
        };
        Ok(())
    }
}

impl NeonJsSerialize for TransactionContractCall {
    fn neon_js_serialize(
        &self,
        cx: &mut FunctionContext,
        obj: &Handle<JsObject>,
        extra_ctx: &(),
    ) -> NeonResult<()> {
        let address = cx.string(self.address.to_string());
        obj.set(cx, "address", address)?;

        let contract_name = cx.string(self.contract_name.to_string());
        obj.set(cx, "contract_name", contract_name)?;

        let function_name = cx.string(self.function_name.to_string());
        obj.set(cx, "function_name", function_name)?;

        // TODO: raw function args binary slice is already determined during raw tx deserialization, ideally
        // try to use that rather than re-serializing (slow)
        let mut function_args_raw = u32::to_be_bytes(self.function_args.len() as u32).to_vec();
        let function_args = JsArray::new(cx, self.function_args.len() as u32);
        for (i, x) in self.function_args.iter().enumerate() {
            let val_obj = cx.empty_object();
            let mut val_bytes = x.neon_js_serialize(cx, &val_obj, extra_ctx)?;
            function_args_raw.append(&mut val_bytes);
            function_args.set(cx, i as u32, val_obj)?;
        }
        obj.set(cx, "function_args", function_args)?;

        let function_args_buff = JsBuffer::external(cx, function_args_raw);
        obj.set(cx, "function_args_buffer", function_args_buff)?;

        Ok(())
    }
}

impl NeonJsSerialize for TransactionSmartContract {
    fn neon_js_serialize(
        &self,
        cx: &mut FunctionContext,
        obj: &Handle<JsObject>,
        _extra_ctx: &(),
    ) -> NeonResult<()> {
        let contract_name = cx.string(self.name.to_string());
        obj.set(cx, "contract_name", contract_name)?;

        let code_body = cx.string(self.code_body.to_string());
        obj.set(cx, "code_body", code_body)?;
        Ok(())
    }
}

impl NeonJsSerialize<(), Vec<u8>> for StacksMicroblockHeader {
    fn neon_js_serialize(
        &self,
        cx: &mut FunctionContext,
        obj: &Handle<JsObject>,
        _extra_ctx: &(),
    ) -> NeonResult<Vec<u8>> {
        let vec = self.serialize_to_vec();

        // TODO: raw microblock header binary slice is already determined during raw tx deserialization, ideally
        // try to use that rather than re-serializing (slow)
        let buffer = JsBuffer::external(cx, vec.clone());
        obj.set(cx, "buffer", buffer)?;

        let version = cx.number(self.version);
        obj.set(cx, "version", version)?;

        let sequence = cx.number(self.sequence);
        obj.set(cx, "sequence", sequence)?;

        let prev_block = JsBuffer::external(cx, self.prev_block.to_bytes());
        obj.set(cx, "prev_block", prev_block)?;

        let tx_merkle_root = JsBuffer::external(cx, self.tx_merkle_root.to_bytes());
        obj.set(cx, "tx_merkle_root", tx_merkle_root)?;

        let signature = JsBuffer::external(cx, self.signature.to_bytes());
        obj.set(cx, "signature", signature)?;

        Ok(vec)
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
