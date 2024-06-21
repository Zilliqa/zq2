use alloy_primitives::{I256, U256};
use alloy_sol_types::{abi::Decoder, SolValue};
use anyhow::{anyhow, Result};
use eth_trie::{EthTrie, Trie};
use revm::{
    precompile::PrecompileError,
    primitives::{Address, Bytes, PrecompileErrors, PrecompileOutput, PrecompileResult},
    ContextStatefulPrecompile, InnerEvmContext,
};
use scilla_parser::{
    ast::nodes::{
        NodeByteStr, NodeMetaIdentifier, NodeScillaType, NodeTypeMapKey, NodeTypeMapValue,
        NodeTypeMapValueAllowingTypeArguments, NodeTypeNameIdentifier,
    },
    parser::{lexer::Lexer, parser::ScillaTypeParser},
};

use crate::{
    db::TrieStorage,
    scilla::storage_key,
    state::{Code, State},
};

/// Internal representation of Scilla types. This is a greatly simplified version of [NodeScillaType] (which comes
/// directly from the Scilla parser) and only supports the types we currently care about. Raw parsed types can be
/// converted to a [ScillaType] with a [ToScillaType::to_scilla_type] implementation.
#[derive(Clone, Debug)]
enum ScillaType {
    Map(Box<ScillaType>, Box<ScillaType>),
    ByStr20,
    Int32,
    Int64,
    Int128,
    Int256,
    Uint32,
    Uint64,
    Uint128,
    Uint256,
    String,
}

trait ToScillaType {
    fn to_scilla_type(self) -> Option<ScillaType>;
}

impl ToScillaType for NodeScillaType {
    fn to_scilla_type(self) -> Option<ScillaType> {
        match self {
            NodeScillaType::MapType(k, v) => (k.node, v.node).to_scilla_type(),
            NodeScillaType::GenericTypeWithArgs(ident, args) if args.is_empty() => {
                ident.node.to_scilla_type()
            }
            NodeScillaType::EnclosedType(ty) => ty.node.to_scilla_type(),
            _ => None,
        }
    }
}

impl ToScillaType for (NodeTypeMapKey, NodeTypeMapValue) {
    fn to_scilla_type(self) -> Option<ScillaType> {
        let (k, v) = self;
        let k = match k {
            NodeTypeMapKey::GenericMapKey(ident) | NodeTypeMapKey::EnclosedGenericId(ident) => {
                ident.node.to_scilla_type()
            }
            NodeTypeMapKey::AddressMapKeyType(_) | NodeTypeMapKey::EnclosedAddressMapKeyType(_) => {
                None
            }
        }?;
        let v = match v {
            NodeTypeMapValue::MapValueTypeOrEnumLikeIdentifier(ident) => {
                ident.node.to_scilla_type()
            }
            NodeTypeMapValue::MapValueParenthesizedType(ident) => match ident.node {
                NodeTypeMapValueAllowingTypeArguments::TypeMapValueNoArgs(ident) => {
                    match ident.node {
                        NodeTypeMapValue::MapValueTypeOrEnumLikeIdentifier(ident) => {
                            ident.node.to_scilla_type()
                        }
                        NodeTypeMapValue::MapKeyValue(ident) => {
                            (ident.node.key.node, ident.node.value.node).to_scilla_type()
                        }
                        _ => None,
                    }
                }
                _ => None,
            },
            _ => None,
        }?;

        Some(ScillaType::Map(k.into(), v.into()))
    }
}

impl ToScillaType for NodeMetaIdentifier {
    fn to_scilla_type(self) -> Option<ScillaType> {
        match self {
            NodeMetaIdentifier::MetaName(ty) => match ty.node {
                NodeTypeNameIdentifier::ByteStringType(NodeByteStr::Type(s)) => {
                    match s.node.as_str() {
                        "ByStr20" => Some(ScillaType::ByStr20),
                        _ => None,
                    }
                }
                NodeTypeNameIdentifier::TypeOrEnumLikeIdentifier(ident) => {
                    match ident.node.as_str() {
                        "Int32" => Some(ScillaType::Int32),
                        "Int64" => Some(ScillaType::Int64),
                        "Int128" => Some(ScillaType::Int128),
                        "Int256" => Some(ScillaType::Int256),
                        "Uint32" => Some(ScillaType::Uint32),
                        "Uint64" => Some(ScillaType::Uint64),
                        "Uint128" => Some(ScillaType::Uint128),
                        "Uint256" => Some(ScillaType::Uint256),
                        "String" => Some(ScillaType::String),
                        _ => None,
                    }
                }
                _ => None,
            },
            _ => None,
        }
    }
}

/// Given a Scilla map key of type `ty`, read a Solidity value of this type from the [Decoder] and return the
/// equivalent Scilla value which could be used to look up this key in a map.
fn read_index(ty: ScillaType, d: &mut Decoder) -> Result<Vec<u8>> {
    let index = match ty {
        ScillaType::ByStr20 => serde_json::to_vec(&Address::detokenize(d.decode()?).to_string())?,
        ScillaType::Int32 => serde_json::to_vec(&i32::detokenize(d.decode()?).to_string())?,
        ScillaType::Int64 => serde_json::to_vec(&i64::detokenize(d.decode()?).to_string())?,
        ScillaType::Int128 => serde_json::to_vec(&i128::detokenize(d.decode()?).to_string())?,
        ScillaType::Int256 => serde_json::to_vec(&I256::detokenize(d.decode()?).to_string())?,
        ScillaType::Uint32 => serde_json::to_vec(&u32::detokenize(d.decode()?).to_string())?,
        ScillaType::Uint64 => serde_json::to_vec(&u64::detokenize(d.decode()?).to_string())?,
        ScillaType::Uint128 => serde_json::to_vec(&u128::detokenize(d.decode()?).to_string())?,
        ScillaType::Uint256 => serde_json::to_vec(&U256::detokenize(d.decode()?).to_string())?,
        ScillaType::String => String::detokenize(d.decode()?).into_bytes(),
        ScillaType::Map(_, _) => {
            return Err(anyhow!("a map cannot be the key of another map"));
        }
    };
    Ok(index)
}

fn get_scilla_value(
    ty: ScillaType,
    decoder: &mut Decoder,
    storage: EthTrie<TrieStorage>,
    field: &str,
    indices: &mut Vec<Vec<u8>>,
) -> Result<Vec<u8>> {
    macro_rules! decoder {
        ($ty:ty) => {{
            let value = storage
                .get(&storage_key(field, indices))?
                .ok_or_else(|| anyhow!("no such value"))?;
            Ok(serde_json::from_slice::<String>(&value)?
                .parse::<$ty>()?
                .abi_encode())
        }};
    }

    match ty {
        ScillaType::Map(k, v) => {
            let index = read_index(*k, decoder)?;
            indices.push(index);
            get_scilla_value(*v, decoder, storage, field, indices)
        }
        ScillaType::ByStr20 => decoder!(Address),
        ScillaType::Int32 => decoder!(i32),
        ScillaType::Int64 => decoder!(i64),
        ScillaType::Int128 => decoder!(i128),
        ScillaType::Int256 => decoder!(I256),
        ScillaType::Uint32 => decoder!(u32),
        ScillaType::Uint64 => decoder!(u64),
        ScillaType::Uint128 => decoder!(u128),
        ScillaType::Uint256 => decoder!(U256),
        ScillaType::String => {
            let value = storage
                .get(&storage_key(field, indices))?
                .ok_or_else(|| anyhow!("no such value"))?;
            Ok(serde_json::from_slice::<String>(&value)?.abi_encode())
        }
    }
}

pub(crate) struct ScillaRead;

fn err(message: &'static str) -> PrecompileResult {
    Err(PrecompileErrors::Fatal {
        msg: message.to_owned(),
    })
}

// ZQ1 suggests revisiting these costs in the future.
const BASE_COST: u64 = 15;
const PER_BYTE_COST: u64 = 3;

impl ContextStatefulPrecompile<&State> for ScillaRead {
    fn call(
        &self,
        input: &Bytes,
        gas_limit: u64,
        context: &mut InnerEvmContext<&State>,
    ) -> PrecompileResult {
        let Ok(input_len) = u64::try_from(input.len()) else {
            return err("input too long");
        };
        let required_gas = input_len * PER_BYTE_COST + BASE_COST;
        if gas_limit < required_gas {
            return Err(PrecompileError::OutOfGas.into());
        }

        let mut decoder = Decoder::new(input, false);

        let address = Address::detokenize(decoder.decode().unwrap());
        let field = String::detokenize(decoder.decode().unwrap());

        let Ok(account) = context.db.get_account(address) else {
            return err("state access failed");
        };
        let Code::Scilla { types, .. } = account.code else {
            return err("not a scilla contract");
        };
        let Some((ty, _)) = types.get(&field) else {
            return err("missing variable");
        };

        let storage = context.db.get_account_trie(address).unwrap();

        let mut errors = vec![];
        let Ok(parsed) = ScillaTypeParser::new().parse(&mut errors, Lexer::new(ty)) else {
            return err("failed to parse scilla type");
        };

        let Some(ty) = parsed.node.to_scilla_type() else {
            return err("unsupported scilla type");
        };

        let Ok(value) = get_scilla_value(ty, &mut decoder, storage, &field, &mut vec![]) else {
            return err("failed to get value");
        };

        Ok(PrecompileOutput::new(required_gas, value.into()))
    }
}
