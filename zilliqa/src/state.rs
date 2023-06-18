use eth_trie::{EthTrie as PatriciaTrie, MemoryDB, Trie};
use generic_array::{
    sequence::Split,
    typenum::{U12, U20},
    GenericArray,
};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use rlp::RlpStream;
use sha3::{Digest, Keccak256};
use std::fmt::Display;
use std::sync::Arc;
use std::{hash::Hash, str::FromStr};

use anyhow::{anyhow, Result};
use primitive_types::{H160, H256, U256};
use serde::{Deserialize, Serialize};

use crate::{contracts, crypto};

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
pub struct State {
    db: Arc<MemoryDB>,
    accounts: PatriciaTrie<MemoryDB>,
}

impl State {
    pub fn new(database: Arc<MemoryDB>) -> Result<State> {
        let mut state = Self {
            db: database.clone(),
            accounts: PatriciaTrie::new(database),
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

    pub fn at_root(&self, root_hash: H256) -> Self {
        let db = self.db.clone();
        Self {
            db,
            accounts: self.accounts.at_root(root_hash),
        }
    }

    pub fn try_clone(&mut self) -> Result<Self> {
        let root_hash = self.accounts.root_hash()?;
        Ok(self.at_root(root_hash))
    }

    pub fn root_hash(&mut self) -> Result<crypto::Hash> {
        Ok(crypto::Hash(
            self.accounts.root_hash()?.as_bytes().try_into()?,
        ))
    }

    /// Fetch an Account struct.
    /// Note: use get_account_storage to obtain a specific storage value.
    /// If modifying a raw account, ensure you call save_account afterwards.
    /// Returns an error on failures to access the state tree, or decode the account; or an empty
    /// account if one didn't exist yet
    pub fn get_account(&self, address: Address) -> Result<Account> {
        Ok(self
            .accounts
            .get(&Keccak256::digest(address.as_bytes()))?
            .map(|bytes| bincode::deserialize::<Account>(&bytes))
            .unwrap_or(Ok(Account::default()))?)
    }

    /// As get_account, but panics if account cannot be read.
    pub fn must_get_account(&self, address: Address) -> Account {
        self.get_account(address)
            .expect("Failed to read account {address:?} from state storage")
    }

    /// If using this to modify the account, ensure save_account gets called
    fn get_account_trie(&self, address: Address) -> Result<PatriciaTrie<MemoryDB>> {
        Ok(match self.get_account(address)?.storage_root {
            Some(root) => PatriciaTrie::new(self.db.clone()).at_root(root),
            None => PatriciaTrie::new(self.db.clone()),
        })
    }

    /// Returns an error if there are any issues fetching the account from the state trie
    pub fn get_account_storage(&self, address: Address, index: H256) -> Result<H256> {
        let res = match self.get_account_trie(address)?.get(index.as_bytes()) {
            // from_slice will only panic if vec.len != H256::len_bytes, i.e. 32
            Ok(Some(vec)) if vec.len() == 32 => Ok(H256::from_slice(&vec)),
            // empty storage location
            Ok(None) => Ok(H256::zero()),
            // invalid value in storage
            Ok(Some(vec)) => Err(anyhow!(
                "Invalid storage for account {address:?} at index {index}: expected 32 bytes, got value {vec:?}"
            )),
            // any other error fetching
            Err(e) => Err(anyhow!(
                "Failed to fetch storage for account {address:?} at index {index}: {e}",
            )),
        };

        println!(
            "############ get_account_storage({:?}, {:?}) -> {:?}",
            address, index, res
        );

        res
    }

    /// Panics if account or storage cannot be read.
    pub fn must_get_account_storage(&self, address: Address, index: H256) -> H256 {
        self.get_account_storage(address, index).expect(
            "Failed to read storage index {index} for account {address:?} from state storage",
        )
    }

    pub fn set_account_storage(
        &mut self,
        address: Address,
        index: H256,
        value: H256,
    ) -> Result<()> {
        println!(
            "############ set_account_storage({:?}, {:?}) -> {:?}",
            address, index, value
        );

        let mut account = self.get_account(address)?;
        let mut trie = self.get_account_trie(address)?;
        trie.insert(index.as_bytes(), value.as_bytes())?;
        account.storage_root = Some(trie.root_hash()?);
        self.save_account(address, account)?;

        Ok(())
    }

    pub fn remove_account_storage(&mut self, address: Address, index: H256) -> Result<bool> {
        let mut account = self.get_account(address)?;
        let mut trie = self.get_account_trie(address)?;
        let ret = trie.remove(index.as_bytes())?;
        account.storage_root = Some(trie.root_hash()?);
        self.save_account(address, account)?;

        Ok(ret)
    }

    pub fn clear_account_storage(&mut self, address: Address) -> Result<()> {
        let account = self.get_account(address)?;
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
            crypto::Hash::compute(&[&address.as_bytes()]).as_bytes(),
            &bincode::serialize(&account)?,
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

    pub fn is_balance_transfer(from: Address, to: Address) -> bool {
        from == Address::DEPLOY_CONTRACT && to == Address::NATIVE_TOKEN
    }

    pub fn is_contract_creation(from: Address, to: Address) -> bool {
        from != Address::DEPLOY_CONTRACT && to == Address(H160::zero())
    }

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
    pub storage_root: Option<H256>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTransaction {
    pub transaction: Transaction,
    /// The from address is inferred from the signing info.
    pub from_addr: Address,
    pub signing_info: SigningInfo,
}

impl SignedTransaction {
    pub fn new(transaction: Transaction, signing_info: SigningInfo) -> Result<Self> {
        let from_addr = verify(&transaction, &signing_info)?;
        Ok(SignedTransaction {
            transaction,
            from_addr,
            signing_info,
        })
    }

    pub fn hash(&self) -> crypto::Hash {
        let txn = &self.transaction;
        match self.signing_info {
            SigningInfo::Eth { v, r, s, chain_id } => {
                let use_eip155 = v >= (chain_id * 2) + 35;
                let mut rlp = RlpStream::new_list(if use_eip155 { 9 } else { 6 });
                rlp.append(&txn.nonce)
                    .append(&txn.gas_price)
                    .append(&txn.gas_limit)
                    .append(&txn.to_addr.as_bytes().to_vec())
                    .append(&txn.amount)
                    .append(&txn.payload);
                if use_eip155 {
                    rlp.append(&v).append(&r.as_slice()).append(&s.as_slice());
                };

                crypto::Hash(Keccak256::digest(rlp.out()).into())
            }
        }
    }

    pub fn verify(&self) -> Result<()> {
        let from_addr = verify(&self.transaction, &self.signing_info)?;
        if from_addr != self.from_addr {
            return Err(anyhow!("inconsistent from address"));
        }

        Ok(())
    }
}

fn verify(txn: &Transaction, signing_info: &SigningInfo) -> Result<Address> {
    match signing_info {
        SigningInfo::Eth { v, r, s, chain_id } => {
            let use_eip155 = *v >= (*chain_id * 2) + 35;
            let mut rlp = RlpStream::new_list(if use_eip155 { 9 } else { 6 });
            rlp.append(&txn.nonce)
                .append(&txn.gas_price)
                .append(&txn.gas_limit)
                .append(&txn.to_addr.as_bytes().to_vec())
                .append(&txn.amount)
                .append(&txn.payload);
            if use_eip155 {
                rlp.append(chain_id).append(&0u8).append(&0u8);
            };
            let prehash = Keccak256::digest(rlp.out());
            let recovery_id = if use_eip155 {
                v - ((chain_id * 2) + 35)
            } else {
                v - 27
            };
            let recovery_id = RecoveryId::from_byte(recovery_id.try_into()?)
                .ok_or_else(|| anyhow!("invalid recovery id: {recovery_id}"))?;
            let signature = Signature::from_scalars(*r, *s)?;

            let verifying_key =
                VerifyingKey::recover_from_prehash(&prehash, &signature, recovery_id)?;

            // Remove the first byte before hashing - The first byte specifies the encoding tag.
            let hashed = Keccak256::digest(&verifying_key.to_encoded_point(false).as_bytes()[1..]);
            let (_, bytes): (GenericArray<u8, U12>, GenericArray<u8, U20>) = hashed.split();
            let from_addr = Address::from_bytes(bytes.into());

            Ok(from_addr)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SigningInfo {
    Eth {
        v: u64,
        r: [u8; 32],
        s: [u8; 32],
        chain_id: u64,
    },
}

impl SigningInfo {
    pub fn hash(&self) -> crypto::Hash {
        match self {
            SigningInfo::Eth {
                v,
                r,
                s,
                chain_id: _,
            } => crypto::Hash::compute(&[&v.to_be_bytes(), r.as_slice(), s.as_slice()]),
        }
    }
}

/// A transaction body, broadcast before execution and then persisted as part of a block after the transaction is executed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Transaction {
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to_addr: Address,
    pub amount: u128,
    pub payload: Vec<u8>,
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
