use rlp::RlpStream;
use sha3::Digest;
use sha3::Keccak256;
use std::fmt::Display;
use std::sync::Arc;
use std::{hash::Hash, str::FromStr};
use zq_trie::{Hasher, PatriciaTrie, Trie, DB};

use anyhow::{anyhow, Result};
use primitive_types::{H160, H256, U256};
use serde::{Deserialize, Serialize};

use crate::{
    contracts,
    crypto::{self, TransactionPublicKey, TransactionSignature},
};

#[derive(Debug)]
pub struct TrieHasher;

impl Hasher for TrieHasher {
    const LENGTH: usize = 32;

    fn digest(&self, data: &[u8]) -> Vec<u8> {
        Keccak256::digest(data).to_vec()
    }
}

/// Const version of `impl From<u128> for U256`
const fn u128_to_u256(value: u128) -> U256 {
    let mut ret = [0; 4];
    ret[0] = value as u64;
    ret[1] = (value >> 64) as u64;
    U256(ret)
}

const GENESIS: [(Address, U256); 2] = [
    // Address with private key 0000000000000000000000000000000000000000000000000000000000000001
    (
        Address(H160(
            *b"\x7e\x5f\x45\x52\x09\x1a\x69\x12\x5d\x5d\xfc\xb7\xb8\xc2\x65\x90\x29\x39\x5b\xdf",
        )),
        u128_to_u256(5000 * 10u128.pow(18)),
    ),
    // Address with private key 0000000000000000000000000000000000000000000000000000000000000002
    (
        Address(H160(
            *b"\x2B\x5A\xD5\xc4\x79\x5c\x02\x65\x14\xf8\x31\x7c\x7a\x21\x5E\x21\x8D\xcC\xD6\xcF",
        )),
        u128_to_u256(2000 * 10u128.pow(18)),
    ),
];

#[derive(Debug)]
pub struct State<D: DB + Send + Sync> {
    db: Arc<D>,
    accounts: PatriciaTrie<D, TrieHasher>,
}

impl<D: DB + Send + Sync> State<D> {
    pub fn new(database: Arc<D>) -> Result<State<D>> {
        let mut state = Self {
            db: database.clone(),
            accounts: PatriciaTrie::new(database, Arc::new(TrieHasher)),
        };

        state
            .deploy_fixed_contract(Address::NATIVE_TOKEN, contracts::native_token::CODE.clone())?;

        for (address, balance) in GENESIS {
            // We don't care about these logs.
            let mut logs = vec![];
            state.set_native_balance(&mut logs, address, balance)?;
        }

        Ok(state)
    }

    pub fn from_root(database: Arc<D>, root_hash: crypto::Hash) -> Result<Self> {
        Ok(Self {
            db: database.clone(),
            accounts: PatriciaTrie::from(database, Arc::new(TrieHasher), root_hash.as_bytes())?,
        })
    }

    pub fn try_clone(&mut self) -> Result<Self> {
        State::from_root(self.db.clone(), self.root_hash()?)
    }

    pub fn root_hash(&mut self) -> Result<crypto::Hash> {
        Ok(crypto::Hash(self.accounts.root()?.as_slice().try_into()?))
    }

    /// Returns an error on failures to access the state tree, or decode the account; or an empty
    /// account if one didn't exist yet
    pub fn try_get_account(&self, address: Address) -> Result<Account> {
        Ok(self
            .accounts
            .get(&Keccak256::digest(address.as_bytes()))?
            .map(|bytes| bincode::deserialize::<Account>(&bytes))
            .unwrap_or(Ok(Account::default()))?)
    }

    /// Returns a default (empty) account if an existing one cannot be fetched for any reason
    pub fn get_account(&self, address: Address) -> Account {
        self.try_get_account(address).unwrap_or(Account::default())
    }

    fn get_account_trie(&self, address: Address) -> Result<PatriciaTrie<D, TrieHasher>> {
        Ok(match self.try_get_account(address)?.storage_root {
            Some(root) => PatriciaTrie::from(self.db.clone(), Arc::new(TrieHasher), &root)?,
            None => PatriciaTrie::new(self.db.clone(), Arc::new(TrieHasher)),
        })
    }

    /// Returns an error if there are any issues fetching the account from the state trie
    pub fn try_get_account_storage(&self, address: Address, index: H256) -> Result<H256> {
        match self.get_account_trie(address)?.get(index.as_bytes()) {
            // from_slice will only panic if vec.len != H256::len_bytes, i.e. 32
            Ok(Some(vec)) if vec.len() == 32 => Ok(H256::from_slice(&vec)),
            // empty storage location
            Ok(None) => Ok(H256::zero()),
            // invalid value in storage
            Ok(Some(vec)) => Err(anyhow!(
                "Invalid storage for account {:?} at index {}: expected 32 bytes, got value {:?}",
                address,
                index,
                vec
            )),
            // any other error fetching
            Err(e) => Err(anyhow!(
                "Failed to fetch storage for account {:?} at index {}: {}",
                address,
                index,
                e
            )),
        }
    }

    /// Returns a default empty value if there are any errors accessing the storage
    pub fn get_account_storage(&self, address: Address, index: H256) -> H256 {
        self.try_get_account_storage(address, index)
            .unwrap_or(H256::default())
    }

    pub fn set_account_storage(&self, address: Address, index: H256, value: H256) -> Result<()> {
        Ok(self
            .get_account_trie(address)?
            .insert(index.as_bytes().to_vec(), value.as_bytes().to_vec())?)
    }

    pub fn remove_account_storage(&self, address: Address, index: H256) -> Result<bool> {
        Ok(self.get_account_trie(address)?.remove(index.as_bytes())?)
    }

    pub fn clear_account_storage(&mut self, address: Address) -> Result<()> {
        let account = self.get_account(address);
        self.save_account(
            address,
            Account {
                storage_root: None,
                ..account
            },
        )
    }

    /// Returns an error if there are any issues accessing the storage trie
    pub fn try_has_account(&self, address: Address) -> Result<bool> {
        Ok(self
            .accounts
            .contains(&Keccak256::digest(address.as_bytes()))?)
    }

    /// Returns false if the account cannot be accessed in the storage trie
    pub fn has_account(&self, address: Address) -> bool {
        self.try_has_account(address).unwrap_or(false)
    }

    pub fn save_account(&mut self, address: Address, account: Account) -> Result<()> {
        Ok(self.accounts.insert(
            crypto::Hash::compute(&[&address.as_bytes()])
                .as_bytes()
                .to_vec(),
            bincode::serialize(&account)?,
        )?)
    }

    pub fn delete_account(&mut self, address: Address) -> Result<bool> {
        Ok(self
            .accounts
            .remove(&Keccak256::digest(address.as_bytes()))?)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Address(pub H160);

impl Address {
    /// Address of the contract which allows you to deploy other contracts.
    pub const DEPLOY_CONTRACT: Address = Address(H160::zero());

    /// Address of the native token ERC-20 contract.
    pub const NATIVE_TOKEN: Address = Address(H160(*b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0ZIL"));

    pub fn from_bytes(bytes: [u8; 20]) -> Address {
        Address(bytes.into())
    }

    pub fn from_slice(bytes: &[u8]) -> Address {
        let mut bytes = bytes.to_owned();
        // FIXME: Awfully inefficient
        while bytes.len() < 20 {
            bytes.insert(0, 0);
        }
        Address(H160::from_slice(&bytes))
    }

    pub fn as_bytes(&self) -> [u8; 20] {
        *self.0.as_fixed_bytes()
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for Address {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Address(s.parse()?))
    }
}

#[derive(Debug, Clone, Default, Hash, Serialize, Deserialize)]
pub struct Account {
    pub nonce: u64,
    #[serde(with = "serde_bytes")]
    pub code: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub storage_root: Option<Vec<u8>>,
}

/// A transaction body, broadcast before execution and then persisted as part of a block after the transaction is executed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Transaction {
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    // TODO: rework how unsigned/partially signed transactions are handled, e.g. in tests
    pub signature: Option<TransactionSignature>,
    pub public_key: TransactionPublicKey,
    pub to_addr: Address,
    pub amount: u128,
    pub payload: Vec<u8>,
    pub chain_id: u64,
}

impl Transaction {
    pub fn hash(&self) -> crypto::Hash {
        crypto::Hash::compute(&[
            &self.nonce.to_be_bytes(),
            &self.gas_price.to_be_bytes(),
            &self.gas_limit.to_be_bytes(),
            &self.addr_from().as_bytes(),
            &self.to_addr.as_bytes(),
            &self.amount.to_be_bytes(),
            &self.payload,
        ])
    }

    /// The digest that is to be used for signing and verification.
    ///
    /// - If the `public_key` of the transaction is ECDSA, this follows Ethereum standard.
    /// The second parameter then distinguishes between EIP155 or legacy signatures.
    ///
    /// - ...presumably Zilliqa compatibility is TBA.
    pub fn signing_hash(&self) -> crypto::Hash {
        match self.public_key {
            TransactionPublicKey::Ecdsa(_, use_eip155) => {
                let mut rlp = RlpStream::new_list(match use_eip155 {
                    true => 9,
                    false => 6,
                });
                rlp.append(&self.nonce)
                    .append(&self.gas_price)
                    .append(&self.gas_limit)
                    .append(&self.to_addr.as_bytes().to_vec())
                    .append(&self.amount)
                    .append(&self.payload);
                if use_eip155 {
                    rlp.append(&self.chain_id).append(&0u8).append(&0u8);
                };
                crypto::Hash::compute(&[&rlp.out()])
            }
        }
    }

    pub fn addr_from(&self) -> Address {
        self.public_key.into_addr()
    }

    pub fn verify(&self) -> Result<()> {
        if let Some(sig) = self.signature {
            self.public_key.verify(self.signing_hash().as_bytes(), sig)
        } else {
            Err(anyhow!("Transaction is unsigned"))
        }
    }
}

/// A transaction receipt stores data about the execution of a transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReceipt {
    pub block_hash: crypto::Hash,
    pub success: bool,
    pub contract_address: Option<Address>,
    pub logs: Vec<Log>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Log {
    pub address: Address,
    pub topics: Vec<H256>,
    pub data: Vec<u8>,
}
