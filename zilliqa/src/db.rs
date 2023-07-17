use eth_trie::DB;
use sled::Tree;

#[derive(Debug, Clone)]
pub struct SledDb {
    db: Tree,
}

impl SledDb {
    pub fn new(db: Tree) -> Self {
        Self { db }
    }
}

impl DB for SledDb {
    type Error = sled::Error;
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.db.get(key)?.map(|ivec| ivec.to_vec()))
    }

    fn insert(&self, key: &[u8], value: Vec<u8>) -> Result<(), Self::Error> {
        self.db.insert(key, value)?;
        Ok(())
    }

    fn remove(&self, key: &[u8]) -> Result<(), Self::Error> {
        self.db.remove(key)?;
        Ok(())
    }

    /// eth-trie.rs provides a way to cache reads and writes and periodically flush them.
    /// We delegate this to Sled and implement flush() as a no-op.
    fn flush(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}
