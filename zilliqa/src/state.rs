use cita_trie::{Hasher, PatriciaTrie, Trie, DB};
use rlp::RlpStream;
use sha3::Digest;
use sha3::Keccak256;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use primitive_types::{H160, H256};
use serde::{Deserialize, Serialize};

use crate::crypto::{self, TransactionPublicKey, TransactionSignature};

#[derive(Debug)]
pub struct TrieHasher;

impl Hasher for TrieHasher {
    const LENGTH: usize = 32;

    fn digest(&self, data: &[u8]) -> Vec<u8> {
        Keccak256::digest(data).to_vec()
    }
}

#[derive(Debug)]
pub struct State<D: DB> {
    db: Arc<D>,
    accounts: PatriciaTrie<D, TrieHasher>,
}

impl<D: DB> State<D> {
    pub fn new(database: Arc<D>) -> State<D> {
        Self {
            db: database.clone(),
            accounts: PatriciaTrie::new(database, Arc::new(TrieHasher)),
        }
    }

    pub fn from_root(database: Arc<D>, root_hash: crypto::Hash) -> Result<Self> {
        Ok(Self {
            db: database.clone(),
            accounts: PatriciaTrie::from(database, Arc::new(TrieHasher), root_hash.as_bytes())?,
        })
    }

    pub fn try_clone(&self) -> Result<Self> {
        Ok(State::from_root(self.db.clone(), self.root_hash()?)?)
    }

    pub fn root_hash(&self) -> Result<crypto::Hash> {
        Ok(crypto::Hash(self.accounts.root()?.as_slice().try_into()?))
    }

    /// Returns an error on failures to access the state tree, or decode the account; or an empty
    /// account if one didn't exist yet
    pub fn try_get_account(&self, address: Address) -> Result<Account<D>> {
        Ok(self
            .accounts
            .get(&Keccak256::digest(address.as_bytes()))?
            .map(|bytes| bincode::deserialize::<Account<D>>(&bytes))
            .unwrap_or(Ok(Account::new(self.db)))?)
    }

    /// Returns a default (empty) account if an existing one cannot be fetched for any reason
    pub fn get_account(&self, address: Address) -> Account<D> {
        self.try_get_account(address)
            .unwrap_or(Account::new(self.db))
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

    pub fn save_account(&mut self, address: Address, account: Account<D>) -> Result<()> {
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

#[derive(Debug, Clone, Hash, Serialize, Deserialize)]
pub struct Account<D: DB> {
    pub nonce: u64,
    #[serde(with = "serde_bytes")]
    pub code: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub storage_root: Vec<u8>,
    #[serde(skip)]
    #[serde(default = "Option::default")]
    trie_db: Option<Arc<D>>,
}

// Derives are dumb and can't derive Option<T>::None when T doesn't implement Default
// https://github.com/rust-lang/rust/issues/26925
impl<D: DB> Default for Account<D> {
    fn default() -> Self {
        Self {
            nonce: u64::default(),
            code: Vec::default(),
            storage_root: Vec::default(),
            trie_db: Option::default(),
        }
    }
}

impl<D: DB> Account<D> {
    pub fn new(db: Arc<D>) -> Self {
        Self {
            trie_db: Some(db),
            ..Self::default()
        }
    }

    pub fn storage(&self) -> Result<PatriciaTrie<D, TrieHasher>> {
        Ok(PatriciaTrie::from(
            self.trie_db.ok_or(anyhow!("No db available"))?,
            Arc::new(TrieHasher),
            &self.storage_root,
        )?)
    }

    pub fn get_storage(&self, index: H256) -> H256 {
        match self.storage().map(|storage| storage.get(&index.as_bytes())) {
            // from_slice will only panic if vec.len != H256::len_bytes, i.e. 32
            Ok(Ok(Some(vec))) if vec.len() == 32 => H256::from_slice(&vec),
            _ => H256::default(),
        }
    }

    pub fn set_storage(&self, index: H256, value: H256) -> Result<()> {
        Ok(self
            .storage()?
            .insert(index.as_bytes().to_vec(), value.as_bytes().to_vec())?)
    }

    pub fn remove_storage(&self, index: H256) -> Result<bool> {
        Ok(self.storage()?.remove(index.as_bytes())?)
    }

    pub fn clear_storage(&self) -> Result<()> {
        // TODO: consider caching the root hash of an empty trie somewhere instead of this
        Ok(self.storage_root = PatriciaTrie::new(
            self.trie_db
                .ok_or(anyhow!("Database not available to load or modify storage!"))?,
            Arc::new(TrieHasher),
        )
        .root().map_err(|_| anyhow!("Failed to create empty root when clearing account storage! This really shouldn't happen."))?)
    }
}

/// A transaction body, broadcast before execution and then persisted as part of a block after the transaction is executed.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
