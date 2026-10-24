use alloy::{
    primitives::{Address, I256, U256},
    sol_types::{SolValue, abi::Decoder},
};
use anyhow::{Result, anyhow};
use scilla_parser::ast::nodes::{
    NodeAddressType, NodeByteStr, NodeMetaIdentifier, NodeScillaType, NodeTypeMapKey,
    NodeTypeMapValue, NodeTypeMapValueAllowingTypeArguments, NodeTypeNameIdentifier,
};

use crate::cfg::Fork;

#[derive(Clone, Debug)]
pub(super) enum ScillaType {
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

impl ScillaType {
    pub(super) fn param_type(&self) -> Option<&'static str> {
        match self {
            ScillaType::ByStr20 => Some("ByStr20"),
            ScillaType::Int32 => Some("Int32"),
            ScillaType::Int64 => Some("Int64"),
            ScillaType::Int128 => Some("Int128"),
            ScillaType::Int256 => Some("Int256"),
            ScillaType::Uint32 => Some("Uint32"),
            ScillaType::Uint64 => Some("Uint64"),
            ScillaType::Uint128 => Some("Uint128"),
            ScillaType::Uint256 => Some("Uint256"),
            ScillaType::String => Some("String"),
            ScillaType::Map(_, _) => None,
        }
    }
}

pub(super) trait ToScillaType {
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
            NodeScillaType::ScillaAddresseType(ty) => ty.node.to_scilla_type(),
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
            NodeMetaIdentifier::MetaName(ty) => ty.node.to_scilla_type(),
            _ => None,
        }
    }
}

impl ToScillaType for NodeTypeNameIdentifier {
    fn to_scilla_type(self) -> Option<ScillaType> {
        match self {
            NodeTypeNameIdentifier::ByteStringType(NodeByteStr::Type(s)) => match s.node.as_str() {
                "ByStr20" => Some(ScillaType::ByStr20),
                _ => None,
            },
            NodeTypeNameIdentifier::TypeOrEnumLikeIdentifier(ident) => match ident.node.as_str() {
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
            },
            _ => None,
        }
    }
}

impl ToScillaType for NodeAddressType {
    fn to_scilla_type(self) -> Option<ScillaType> {
        self.identifier.node.to_scilla_type()
    }
}

pub(super) fn read_index(ty: ScillaType, d: &mut Decoder, fork: &Fork) -> Result<Vec<u8>> {
    let index = match ty {
        ScillaType::ByStr20 => {
            serde_json::to_vec(&format!("{:?}", Address::detokenize(d.decode()?)))?
        }
        ScillaType::Int32 => serde_json::to_vec(&i32::detokenize(d.decode()?).to_string())?,
        ScillaType::Int64 => serde_json::to_vec(&i64::detokenize(d.decode()?).to_string())?,
        ScillaType::Int128 => serde_json::to_vec(&i128::detokenize(d.decode()?).to_string())?,
        ScillaType::Int256 => serde_json::to_vec(&I256::detokenize(d.decode()?).to_string())?,
        ScillaType::Uint32 => serde_json::to_vec(&u32::detokenize(d.decode()?).to_string())?,
        ScillaType::Uint64 => serde_json::to_vec(&u64::detokenize(d.decode()?).to_string())?,
        ScillaType::Uint128 => serde_json::to_vec(&u128::detokenize(d.decode()?).to_string())?,
        ScillaType::Uint256 => serde_json::to_vec(&U256::detokenize(d.decode()?).to_string())?,
        ScillaType::String => {
            if fork.evm_to_scilla_strings_encoded_properly {
                serde_json::to_vec(&String::detokenize(d.decode()?))?
            } else {
                String::detokenize(d.decode()?).into_bytes()
            }
        }
        ScillaType::Map(_, _) => {
            return Err(anyhow!("a map cannot be the key of another map"));
        }
    };
    Ok(index)
}

pub(super) fn get_indices(
    ty: ScillaType,
    decoder: &mut Decoder,
    indices: &mut Vec<Vec<u8>>,
    fork: &Fork,
) -> Result<ScillaType> {
    match ty {
        ScillaType::Map(k, v) => {
            let index = read_index(*k, decoder, fork)?;
            indices.push(index);
            get_indices(*v, decoder, indices, fork)
        }
        _ => Ok(ty),
    }
}
