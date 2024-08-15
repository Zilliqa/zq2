use std::sync::{Arc, RwLock};

use alloy::primitives::{keccak256, B256};
use hashbrown::{HashMap, HashSet};
use log::warn;
use rlp::{Prototype, Rlp, RlpStream};

use crate::{
    db::{MemoryDB, DB},
    errors::TrieError,
    nibbles::Nibbles,
    node::{empty_children, BranchNode, Node},
};

pub type TrieResult<T> = Result<T, TrieError>;
const HASHED_LENGTH: usize = 32;

pub trait Trie<D: DB> {
    /// Returns the value for key stored in the trie.
    fn get(&self, key: &[u8]) -> TrieResult<Option<Vec<u8>>>;

    /// Checks that the key is present in the trie
    fn contains(&self, key: &[u8]) -> TrieResult<bool>;

    /// Inserts value into trie and modifies it if it exists
    fn insert(&mut self, key: &[u8], value: &[u8]) -> TrieResult<()>;

    /// Removes any existing value for key from the trie.
    fn remove(&mut self, key: &[u8]) -> TrieResult<bool>;

    /// Saves all the nodes in the db, clears the cache data, recalculates the root.
    /// Returns the root hash of the trie.
    fn root_hash(&mut self) -> TrieResult<B256>;

    /// Prove constructs a merkle proof for key. The result contains all encoded nodes
    /// on the path to the value at key. The value itself is also included in the last
    /// node and can be retrieved by verifying the proof.
    ///
    /// If the trie does not contain a value for key, the returned proof contains all
    /// nodes of the longest existing prefix of the key (at least the root node), ending
    /// with the node that proves the absence of the key.
    // TODO refactor encode_raw() so that it doesn't need a &mut self
    fn get_proof(&mut self, key: &[u8]) -> TrieResult<Vec<Vec<u8>>>;

    /// return value if key exists, None if key not exist, Error if proof is wrong
    fn verify_proof(
        &self,
        root_hash: B256,
        key: &[u8],
        proof: Vec<Vec<u8>>,
    ) -> TrieResult<Option<Vec<u8>>>;
}

#[derive(Clone, Debug)]
pub struct EthTrie<D>
where
    D: DB,
{
    root: Node,
    root_hash: B256,

    pub db: Arc<D>,

    // The batch of pending new nodes to write
    cache: HashMap<Vec<u8>, Vec<u8>>,
    passing_keys: HashSet<Vec<u8>>,
    gen_keys: HashSet<Vec<u8>>,
}

enum EncodedNode {
    Hash(B256),
    Inline(Vec<u8>),
}

#[derive(Clone, Debug)]
enum TraceStatus {
    Start,
    Doing,
    Child(u8),
    End,
}

#[derive(Clone, Debug)]
struct TraceNode {
    node: Node,
    status: TraceStatus,
}

impl TraceNode {
    fn advance(&mut self) {
        self.status = match &self.status {
            TraceStatus::Start => TraceStatus::Doing,
            TraceStatus::Doing => match self.node {
                Node::Branch(_) => TraceStatus::Child(0),
                _ => TraceStatus::End,
            },
            TraceStatus::Child(i) if *i < 15 => TraceStatus::Child(i + 1),
            _ => TraceStatus::End,
        }
    }
}

impl From<Node> for TraceNode {
    fn from(node: Node) -> TraceNode {
        TraceNode {
            node,
            status: TraceStatus::Start,
        }
    }
}

pub struct TrieIterator<'a, D>
where
    D: DB,
{
    trie: &'a EthTrie<D>,
    nibble: Nibbles,
    nodes: Vec<TraceNode>,
    advance_to: Option<Nibbles>,
}

impl<'a, D> TrieIterator<'a, D>
where
    D: DB,
{
    fn advance_to(&mut self, key: Nibbles) -> Result<(), ()> {
        loop {
            let partial = key.offset(self.nibble.len());
            let mut now = self.nodes.last().cloned();
            if let Some(ref mut now) = now {
                self.nodes.last_mut().unwrap().advance();

                match (now.status.clone(), &now.node) {
                    (TraceStatus::Doing, Node::Extension(ref ext)) => {
                        let borrow_ext = ext.read().unwrap();

                        if partial < borrow_ext.prefix {
                            self.nodes.last_mut().unwrap().status = TraceStatus::Doing;

                            break;
                        } else if partial.common_prefix(&borrow_ext.prefix)
                            == borrow_ext.prefix.len()
                        {
                            self.nibble.extend(&borrow_ext.prefix);
                            self.nodes.push(borrow_ext.node.clone().into());
                        } else {
                            self.nodes.pop();
                        }
                    }
                    (TraceStatus::Doing, Node::Leaf(ref leaf)) => {
                        use std::cmp::Ordering as O;
                        match partial.cmp(&leaf.key) {
                            O::Less => {
                                self.nodes.last_mut().unwrap().status = TraceStatus::Doing;
                                break;
                            }
                            O::Equal => {
                                self.nodes.pop();
                                break;
                            }
                            O::Greater => {
                                self.nodes.pop();
                            }
                        }
                    }
                    (TraceStatus::Doing, Node::Branch(ref branch)) => {
                        if partial.is_empty() || partial.at(0) == 16 {
                            self.nodes.last_mut().unwrap().status = TraceStatus::Doing;
                            break;
                        }

                        let borrow_branch = branch.read().unwrap();

                        let index = partial.at(0);
                        {
                            let last_node = self.nodes.last_mut().unwrap();
                            last_node.status = TraceStatus::Child(index as u8);
                            last_node.advance();
                        }

                        self.nibble.push(index as u8);
                        self.nodes
                            .push(borrow_branch.children[index].clone().into());
                    }
                    (TraceStatus::Doing, Node::Hash(ref hash_node)) => {
                        let node_hash = hash_node.hash;
                        if let Ok(n) = self.trie.recover_from_db(node_hash) {
                            self.nodes.pop();
                            match n {
                                Some(node) => self.nodes.push(node.into()),
                                None => {
                                    warn!("Trie node with hash {:?} is missing from the database. Skipping...", &node_hash);
                                    continue;
                                }
                            }
                        } else {
                            //error!();
                            return Err(());
                        }
                    }
                    (TraceStatus::Doing, Node::Empty) => {
                        self.nodes.pop();
                    }
                    (TraceStatus::Start, _) => {}
                    (TraceStatus::End | TraceStatus::Child(_), _) => {
                        unreachable!()
                    }
                }
            }
        }

        Ok(())
    }
}

impl<'a, D> Iterator for TrieIterator<'a, D>
where
    D: DB,
{
    type Item = (Vec<u8>, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(key) = self.advance_to.clone() {
            self.advance_to(key).ok()?;

            self.advance_to = None;
        }

        loop {
            let mut now = self.nodes.last().cloned();
            if let Some(ref mut now) = now {
                self.nodes.last_mut().unwrap().advance();

                match (now.status.clone(), &now.node) {
                    (TraceStatus::End, node) => {
                        match *node {
                            Node::Leaf(ref leaf) => {
                                let cur_len = self.nibble.len();
                                self.nibble.truncate(cur_len - leaf.key.len());
                            }

                            Node::Extension(ref ext) => {
                                let cur_len = self.nibble.len();
                                self.nibble
                                    .truncate(cur_len - ext.read().unwrap().prefix.len());
                            }

                            Node::Branch(_) => {
                                self.nibble.pop();
                            }
                            _ => {}
                        }
                        self.nodes.pop();
                    }

                    (TraceStatus::Doing, Node::Extension(ref ext)) => {
                        self.nibble.extend(&ext.read().unwrap().prefix);
                        self.nodes.push((ext.read().unwrap().node.clone()).into());
                    }

                    (TraceStatus::Doing, Node::Leaf(ref leaf)) => {
                        self.nibble.extend(&leaf.key);
                        return Some((self.nibble.encode_raw().0, leaf.value.clone()));
                    }

                    (TraceStatus::Doing, Node::Branch(ref branch)) => {
                        let value_option = branch.read().unwrap().value.clone();
                        if let Some(value) = value_option {
                            return Some((self.nibble.encode_raw().0, value));
                        } else {
                            continue;
                        }
                    }

                    (TraceStatus::Doing, Node::Hash(ref hash_node)) => {
                        let node_hash = hash_node.hash;
                        if let Ok(n) = self.trie.recover_from_db(node_hash) {
                            self.nodes.pop();
                            match n {
                                Some(node) => self.nodes.push(node.into()),
                                None => {
                                    warn!("Trie node with hash {:?} is missing from the database. Skipping...", &node_hash);
                                    continue;
                                }
                            }
                        } else {
                            //error!();
                            return None;
                        }
                    }

                    (TraceStatus::Child(i), Node::Branch(ref branch)) => {
                        if i == 0 {
                            self.nibble.push(0);
                        } else {
                            self.nibble.pop();
                            self.nibble.push(i);
                        }
                        self.nodes
                            .push((branch.read().unwrap().children[i as usize].clone()).into());
                    }

                    (_, Node::Empty) => {
                        self.nodes.pop();
                    }
                    _ => {}
                }
            } else {
                return None;
            }
        }
    }
}

impl<D> EthTrie<D>
where
    D: DB,
{
    fn construct_iter(&self, node: Node, prefix: &[u8], after: Option<&[u8]>) -> TrieIterator<D> {
        let advance_to = after.map(|v| Nibbles::from_raw(v, true));
        let nibble = Nibbles::from_raw(prefix, false);
        let nodes = vec![node.into()];

        TrieIterator {
            trie: self,
            nibble,
            nodes,
            advance_to,
        }
    }

    pub fn iter(&self) -> TrieIterator<D> {
        self.construct_iter(self.root.clone(), &[], None)
    }

    pub fn iter_after(&self, after: &[u8]) -> TrieIterator<D> {
        self.construct_iter(self.root.clone(), &[], Some(after))
    }

    /// Return an iterator of key-value pairs in the trie that start with the given prefix. The keys are returned in
    /// order.
    pub fn iter_by_prefix(&self, prefix: &[u8]) -> TrieResult<TrieIterator<D>> {
        let nibble = Nibbles::from_raw(prefix, false);
        let node = self.node_with_prefix(&self.root, &nibble)?;

        Ok(self.construct_iter(node, prefix, None))
    }

    pub fn iter_after_by_prefix(&self, after: &[u8], prefix: &[u8]) -> TrieResult<TrieIterator<D>> {
        let nibble = Nibbles::from_raw(prefix, false);
        let node = self.node_with_prefix(&self.root, &nibble)?;

        Ok(self.construct_iter(node, prefix, Some(after)))
    }

    pub fn remove_by_prefix(&mut self, prefix: &[u8]) -> TrieResult<()> {
        // TODO(#1025): Optimise this
        let keys: Vec<_> = self.iter_by_prefix(prefix)?.map(|(k, _)| k).collect();

        for key in keys {
            assert!(self.remove(&key)?);
        }

        Ok(())
    }

    pub fn new(db: Arc<D>) -> Self {
        Self {
            root: Node::Empty,
            root_hash: keccak256(rlp::NULL_RLP),

            cache: HashMap::new(),
            passing_keys: HashSet::new(),
            gen_keys: HashSet::new(),

            db,
        }
    }

    pub fn at_root(&self, root_hash: B256) -> Self {
        Self {
            root: Node::from_hash(root_hash),
            root_hash,

            cache: HashMap::new(),
            passing_keys: HashSet::new(),
            gen_keys: HashSet::new(),

            db: self.db.clone(),
        }
    }
}

impl<D> Trie<D> for EthTrie<D>
where
    D: DB,
{
    /// Returns the value for key stored in the trie.
    fn get(&self, key: &[u8]) -> TrieResult<Option<Vec<u8>>> {
        let path = &Nibbles::from_raw(key, true);
        let result = self.get_at(&self.root, path, 0);
        if let Err(TrieError::MissingTrieNode {
            node_hash,
            traversed,
            root_hash,
            err_key: _,
        }) = result
        {
            Err(TrieError::MissingTrieNode {
                node_hash,
                traversed,
                root_hash,
                err_key: Some(key.to_vec()),
            })
        } else {
            result
        }
    }

    /// Checks that the key is present in the trie
    fn contains(&self, key: &[u8]) -> TrieResult<bool> {
        let path = &Nibbles::from_raw(key, true);
        Ok(self.get_at(&self.root, path, 0)?.map_or(false, |_| true))
    }

    /// Inserts value into trie and modifies it if it exists
    fn insert(&mut self, key: &[u8], value: &[u8]) -> TrieResult<()> {
        if value.is_empty() {
            self.remove(key)?;
            return Ok(());
        }
        let root = self.root.clone();
        let path = &Nibbles::from_raw(key, true);
        let result = self.insert_at(root, path, 0, value.to_vec());

        if let Err(TrieError::MissingTrieNode {
            node_hash,
            traversed,
            root_hash,
            err_key: _,
        }) = result
        {
            Err(TrieError::MissingTrieNode {
                node_hash,
                traversed,
                root_hash,
                err_key: Some(key.to_vec()),
            })
        } else {
            self.root = result?;
            Ok(())
        }
    }

    /// Removes any existing value for key from the trie.
    fn remove(&mut self, key: &[u8]) -> TrieResult<bool> {
        let path = &Nibbles::from_raw(key, true);
        let result = self.delete_at(&self.root.clone(), path, 0);

        if let Err(TrieError::MissingTrieNode {
            node_hash,
            traversed,
            root_hash,
            err_key: _,
        }) = result
        {
            Err(TrieError::MissingTrieNode {
                node_hash,
                traversed,
                root_hash,
                err_key: Some(key.to_vec()),
            })
        } else {
            let (n, removed) = result?;
            self.root = n;
            Ok(removed)
        }
    }

    /// Saves all the nodes in the db, clears the cache data, recalculates the root.
    /// Returns the root hash of the trie.
    fn root_hash(&mut self) -> TrieResult<B256> {
        self.commit()
    }

    /// Prove constructs a merkle proof for key. The result contains all encoded nodes
    /// on the path to the value at key. The value itself is also included in the last
    /// node and can be retrieved by verifying the proof.
    ///
    /// If the trie does not contain a value for key, the returned proof contains all
    /// nodes of the longest existing prefix of the key (at least the root node), ending
    /// with the node that proves the absence of the key.
    fn get_proof(&mut self, key: &[u8]) -> TrieResult<Vec<Vec<u8>>> {
        let key_path = &Nibbles::from_raw(key, true);
        let result = self.get_path_at(&self.root, key_path, 0);

        if let Err(TrieError::MissingTrieNode {
            node_hash,
            traversed,
            root_hash,
            err_key: _,
        }) = result
        {
            Err(TrieError::MissingTrieNode {
                node_hash,
                traversed,
                root_hash,
                err_key: Some(key.to_vec()),
            })
        } else {
            let mut path = result?;
            match self.root {
                Node::Empty => {}
                _ => path.push(self.root.clone()),
            }
            Ok(path
                .into_iter()
                .rev()
                .map(|n| self.encode_raw(&n))
                .collect())
        }
    }

    /// return value if key exists, None if key not exist, Error if proof is wrong
    fn verify_proof(
        &self,
        root_hash: B256,
        key: &[u8],
        proof: Vec<Vec<u8>>,
    ) -> TrieResult<Option<Vec<u8>>> {
        let proof_db = Arc::new(MemoryDB::new(true));
        for node_encoded in proof.into_iter() {
            let hash = keccak256(&node_encoded);

            if root_hash.eq(&hash) || node_encoded.len() >= HASHED_LENGTH {
                proof_db.insert(hash.as_slice(), node_encoded).unwrap();
            }
        }
        let trie = EthTrie::new(proof_db).at_root(root_hash);
        trie.get(key).or(Err(TrieError::InvalidProof))
    }
}

impl<D> EthTrie<D>
where
    D: DB,
{
    /// Returns the highest level node in the trie which is prefixed by `prefix`. If the returned node is a leaf or
    /// extension whose key does contain the required prefix, we strip the prefix from the key before returning the
    /// node.
    fn node_with_prefix(&self, source_node: &Node, prefix: &Nibbles) -> TrieResult<Node> {
        match source_node {
            Node::Empty => Ok(Node::Empty),
            Node::Hash(hash_node) => {
                let node_hash = hash_node.hash;
                let node = self
                    .recover_from_db(node_hash)?
                    .ok_or(TrieError::MissingTrieNode {
                        node_hash,
                        traversed: None,
                        root_hash: Some(self.root_hash),
                        err_key: None,
                    })?;
                self.node_with_prefix(&node, prefix)
            }
            Node::Leaf(leaf) => {
                // We require the precondition (and assert) that the provided path is never a leaf itself. This means
                // when we return a leaf, the final `16` byte from the leaf's key is only included once.
                assert!(prefix.is_empty() || !prefix.is_leaf());

                // If our path is a prefix of the leaf's key, strip the prefix before returning the leaf.
                if let Some(rest) = leaf.key.strip_prefix(prefix) {
                    Ok(Node::from_leaf(rest, leaf.value.clone()))
                } else {
                    Ok(Node::Empty)
                }
            }
            Node::Branch(branch) => {
                let borrow_branch = branch.read().unwrap();

                if prefix.is_empty() || prefix.at(0) == 16 {
                    Ok(source_node.clone())
                } else {
                    let index = prefix.at(0);
                    self.node_with_prefix(&borrow_branch.children[index], &prefix.offset(1))
                }
            }
            Node::Extension(extension) => {
                let extension = extension.read().unwrap();

                // An extension node means all nodes under this point in the trie (under `extension.node`) have a
                // common prefix of `extension.prefix`. If `prefix` is a prefix of `extension.prefix`, we make a
                // recursive call with the inner `extension.node`. There is an edge case to consider here, where
                // `prefix` is longer than `extension.prefix` - In this case, we truncate `prefix` to be the same
                // length and use the remainder in our recursive call.

                // Truncate `prefix` to the length of the extension prefix.
                let split_point = prefix.len().min(extension.prefix.len());
                // `candidate_prefix` is what we will try to strip from the start of this `extension.prefix`.
                // `rest_of_prefix` is anything left from the original `prefix`. Note that this can be empty.
                let (candidate_prefix, rest_of_prefix) = prefix.split_at(split_point);

                if let Some(rest) = extension.prefix.strip_prefix(&candidate_prefix) {
                    let inner = self.node_with_prefix(&extension.node, &rest_of_prefix)?;
                    if rest.is_empty() {
                        // If there is no prefix left for this extension, it doesn't need to exist and we can just
                        // return the inner node.
                        Ok(inner)
                    } else {
                        // As mentioned in the documentation for this method, we return the extension node with the
                        // matching prefix removed.
                        Ok(Node::from_extension(rest, inner))
                    }
                } else {
                    Ok(Node::Empty)
                }
            }
        }
    }

    fn get_at(
        &self,
        source_node: &Node,
        path: &Nibbles,
        path_index: usize,
    ) -> TrieResult<Option<Vec<u8>>> {
        let partial = &path.offset(path_index);
        match source_node {
            Node::Empty => Ok(None),
            Node::Hash(hash_node) if hash_node.hash == keccak256(rlp::NULL_RLP) => Ok(None),
            Node::Leaf(leaf) => {
                if &leaf.key == partial {
                    Ok(Some(leaf.value.clone()))
                } else {
                    Ok(None)
                }
            }
            Node::Branch(branch) => {
                let borrow_branch = branch.read().unwrap();

                if partial.is_empty() || partial.at(0) == 16 {
                    Ok(borrow_branch.value.clone())
                } else {
                    let index = partial.at(0);
                    self.get_at(&borrow_branch.children[index], path, path_index + 1)
                }
            }
            Node::Extension(extension) => {
                let extension = extension.read().unwrap();

                let prefix = &extension.prefix;
                let match_len = partial.common_prefix(prefix);
                if match_len == prefix.len() {
                    self.get_at(&extension.node, path, path_index + match_len)
                } else {
                    Ok(None)
                }
            }
            Node::Hash(hash_node) => {
                let node_hash = hash_node.hash;
                let node =
                    self.recover_from_db(node_hash)?
                        .ok_or_else(|| TrieError::MissingTrieNode {
                            node_hash,
                            traversed: Some(path.slice(0, path_index)),
                            root_hash: Some(self.root_hash),
                            err_key: None,
                        })?;
                self.get_at(&node, path, path_index)
            }
        }
    }

    fn insert_at(
        &mut self,
        n: Node,
        path: &Nibbles,
        path_index: usize,
        value: Vec<u8>,
    ) -> TrieResult<Node> {
        let partial = path.offset(path_index);
        match n {
            Node::Empty => Ok(Node::from_leaf(partial, value)),
            Node::Leaf(leaf) => {
                let old_partial = &leaf.key;
                let match_index = partial.common_prefix(old_partial);
                if match_index == old_partial.len() {
                    return Ok(Node::from_leaf(leaf.key.clone(), value));
                }

                let mut branch = BranchNode {
                    children: empty_children(),
                    value: None,
                };

                let n = Node::from_leaf(old_partial.offset(match_index + 1), leaf.value.clone());
                branch.insert(old_partial.at(match_index), n);

                let n = Node::from_leaf(partial.offset(match_index + 1), value);
                branch.insert(partial.at(match_index), n);

                if match_index == 0 {
                    return Ok(Node::Branch(Arc::new(RwLock::new(branch))));
                }

                // if include a common prefix
                Ok(Node::from_extension(
                    partial.slice(0, match_index),
                    Node::Branch(Arc::new(RwLock::new(branch))),
                ))
            }
            Node::Branch(branch) => {
                let mut borrow_branch = branch.write().unwrap();

                if partial.at(0) == 0x10 {
                    borrow_branch.value = Some(value);
                    return Ok(Node::Branch(branch.clone()));
                }

                let child = borrow_branch.children[partial.at(0)].clone();
                let new_child = self.insert_at(child, path, path_index + 1, value)?;
                borrow_branch.children[partial.at(0)] = new_child;
                Ok(Node::Branch(branch.clone()))
            }
            Node::Extension(ext) => {
                let mut borrow_ext = ext.write().unwrap();

                let prefix = &borrow_ext.prefix;
                let sub_node = borrow_ext.node.clone();
                let match_index = partial.common_prefix(prefix);

                if match_index == 0 {
                    let mut branch = BranchNode {
                        children: empty_children(),
                        value: None,
                    };
                    branch.insert(
                        prefix.at(0),
                        if prefix.len() == 1 {
                            sub_node
                        } else {
                            Node::from_extension(prefix.offset(1), sub_node)
                        },
                    );
                    let node = Node::Branch(Arc::new(RwLock::new(branch)));

                    return self.insert_at(node, path, path_index, value);
                }

                if match_index == prefix.len() {
                    let new_node =
                        self.insert_at(sub_node, path, path_index + match_index, value)?;
                    return Ok(Node::from_extension(prefix.clone(), new_node));
                }

                let new_ext = Node::from_extension(prefix.offset(match_index), sub_node);
                let new_node = self.insert_at(new_ext, path, path_index + match_index, value)?;
                borrow_ext.prefix = prefix.slice(0, match_index);
                borrow_ext.node = new_node;
                Ok(Node::Extension(ext.clone()))
            }
            Node::Hash(hash_node) => {
                let node_hash = hash_node.hash;
                self.passing_keys.insert(node_hash.to_vec());
                let node =
                    self.recover_from_db(node_hash)?
                        .ok_or_else(|| TrieError::MissingTrieNode {
                            node_hash,
                            traversed: Some(path.slice(0, path_index)),
                            root_hash: Some(self.root_hash),
                            err_key: None,
                        })?;
                self.insert_at(node, path, path_index, value)
            }
        }
    }

    fn delete_at(
        &mut self,
        old_node: &Node,
        path: &Nibbles,
        path_index: usize,
    ) -> TrieResult<(Node, bool)> {
        let partial = &path.offset(path_index);
        let (new_node, deleted) = match old_node {
            Node::Empty => Ok((Node::Empty, false)),
            Node::Leaf(leaf) => {
                if &leaf.key == partial {
                    return Ok((Node::Empty, true));
                }
                Ok((Node::Leaf(leaf.clone()), false))
            }
            Node::Branch(branch) => {
                let mut borrow_branch = branch.write().unwrap();

                if partial.at(0) == 0x10 {
                    borrow_branch.value = None;
                    return Ok((Node::Branch(branch.clone()), true));
                }

                let index = partial.at(0);
                let child = &borrow_branch.children[index];

                let (new_child, deleted) = self.delete_at(child, path, path_index + 1)?;
                if deleted {
                    borrow_branch.children[index] = new_child;
                }

                Ok((Node::Branch(branch.clone()), deleted))
            }
            Node::Extension(ext) => {
                let mut borrow_ext = ext.write().unwrap();

                let prefix = &borrow_ext.prefix;
                let match_len = partial.common_prefix(prefix);

                if match_len == prefix.len() {
                    let (new_node, deleted) =
                        self.delete_at(&borrow_ext.node, path, path_index + match_len)?;

                    if deleted {
                        borrow_ext.node = new_node;
                    }

                    Ok((Node::Extension(ext.clone()), deleted))
                } else {
                    Ok((Node::Extension(ext.clone()), false))
                }
            }
            Node::Hash(hash_node) => {
                let hash = hash_node.hash;
                self.passing_keys.insert(hash.to_vec());

                let node =
                    self.recover_from_db(hash)?
                        .ok_or_else(|| TrieError::MissingTrieNode {
                            node_hash: hash,
                            traversed: Some(path.slice(0, path_index)),
                            root_hash: Some(self.root_hash),
                            err_key: None,
                        })?;
                self.delete_at(&node, path, path_index)
            }
        }?;

        if deleted {
            Ok((self.degenerate(new_node)?, deleted))
        } else {
            Ok((new_node, deleted))
        }
    }

    // This refactors the trie after a node deletion, as necessary.
    // For example, if a deletion removes a child of a branch node, leaving only one child left, it
    // needs to be modified into an extension and maybe combined with its parent and/or child node.
    fn degenerate(&mut self, n: Node) -> TrieResult<Node> {
        match n {
            Node::Branch(branch) => {
                let borrow_branch = branch.read().unwrap();

                let mut used_indexs = vec![];
                for (index, node) in borrow_branch.children.iter().enumerate() {
                    match node {
                        Node::Empty => continue,
                        _ => used_indexs.push(index),
                    }
                }

                // if only a value node, transmute to leaf.
                if used_indexs.is_empty() && borrow_branch.value.is_some() {
                    let key = Nibbles::from_raw(&[], true);
                    let value = borrow_branch.value.clone().unwrap();
                    Ok(Node::from_leaf(key, value))
                // if only one node. make an extension.
                } else if used_indexs.len() == 1 && borrow_branch.value.is_none() {
                    let used_index = used_indexs[0];
                    let n = borrow_branch.children[used_index].clone();

                    let new_node = Node::from_extension(Nibbles::from_hex(&[used_index as u8]), n);
                    self.degenerate(new_node)
                } else {
                    Ok(Node::Branch(branch.clone()))
                }
            }
            Node::Extension(ext) => {
                let borrow_ext = ext.read().unwrap();

                let prefix = &borrow_ext.prefix;
                match borrow_ext.node.clone() {
                    Node::Extension(sub_ext) => {
                        let borrow_sub_ext = sub_ext.read().unwrap();

                        let new_prefix = prefix.join(&borrow_sub_ext.prefix);
                        let new_n = Node::from_extension(new_prefix, borrow_sub_ext.node.clone());
                        self.degenerate(new_n)
                    }
                    Node::Leaf(leaf) => {
                        let new_prefix = prefix.join(&leaf.key);
                        Ok(Node::from_leaf(new_prefix, leaf.value.clone()))
                    }
                    // try again after recovering node from the db.
                    Node::Hash(hash_node) => {
                        let node_hash = hash_node.hash;
                        self.passing_keys.insert(node_hash.to_vec());

                        let new_node =
                            self.recover_from_db(node_hash)?
                                .ok_or(TrieError::MissingTrieNode {
                                    node_hash,
                                    traversed: None,
                                    root_hash: Some(self.root_hash),
                                    err_key: None,
                                })?;

                        let n = Node::from_extension(borrow_ext.prefix.clone(), new_node);
                        self.degenerate(n)
                    }
                    _ => Ok(Node::Extension(ext.clone())),
                }
            }
            _ => Ok(n),
        }
    }

    // Get nodes path along the key, only the nodes whose encode length is greater than
    // hash length are added.
    // For embedded nodes whose data are already contained in their parent node, we don't need to
    // add them in the path.
    // In the code below, we only add the nodes get by `get_node_from_hash`, because they contains
    // all data stored in db, including nodes whose encoded data is less than hash length.
    fn get_path_at(
        &self,
        source_node: &Node,
        path: &Nibbles,
        path_index: usize,
    ) -> TrieResult<Vec<Node>> {
        let partial = &path.offset(path_index);
        match source_node {
            Node::Empty | Node::Leaf(_) => Ok(vec![]),
            Node::Branch(branch) => {
                let borrow_branch = branch.read().unwrap();

                if partial.is_empty() || partial.at(0) == 16 {
                    Ok(vec![])
                } else {
                    let node = &borrow_branch.children[partial.at(0)];
                    self.get_path_at(node, path, path_index + 1)
                }
            }
            Node::Extension(ext) => {
                let borrow_ext = ext.read().unwrap();

                let prefix = &borrow_ext.prefix;
                let match_len = partial.common_prefix(prefix);

                if match_len == prefix.len() {
                    self.get_path_at(&borrow_ext.node, path, path_index + match_len)
                } else {
                    Ok(vec![])
                }
            }
            Node::Hash(hash_node) => {
                let node_hash = hash_node.hash;
                let n = self
                    .recover_from_db(node_hash)?
                    .ok_or(TrieError::MissingTrieNode {
                        node_hash,
                        traversed: None,
                        root_hash: Some(self.root_hash),
                        err_key: None,
                    })?;
                let mut rest = self.get_path_at(&n, path, path_index)?;
                rest.push(n);
                Ok(rest)
            }
        }
    }

    fn commit(&mut self) -> TrieResult<B256> {
        let root_hash = match self.write_node(&self.root.clone()) {
            EncodedNode::Hash(hash) => hash,
            EncodedNode::Inline(encoded) => {
                let hash = keccak256(&encoded);
                self.cache.insert(hash.to_vec(), encoded);
                hash
            }
        };

        let mut keys = Vec::with_capacity(self.cache.len());
        let mut values = Vec::with_capacity(self.cache.len());
        for (k, v) in self.cache.drain() {
            keys.push(k.to_vec());
            values.push(v);
        }

        self.db
            .insert_batch(keys, values)
            .map_err(|e| TrieError::DB(e.to_string()))?;

        let removed_keys: Vec<Vec<u8>> = self
            .passing_keys
            .iter()
            .filter(|h| !self.gen_keys.contains(&h.to_vec()))
            .map(|h| h.to_vec())
            .collect();

        self.db
            .remove_batch(&removed_keys)
            .map_err(|e| TrieError::DB(e.to_string()))?;

        self.root_hash = root_hash;
        self.gen_keys.clear();
        self.passing_keys.clear();
        self.root = self
            .recover_from_db(root_hash)?
            .expect("The root that was just created is missing");
        Ok(root_hash)
    }

    fn write_node(&mut self, to_encode: &Node) -> EncodedNode {
        // Returns the hash value directly to avoid double counting.
        if let Node::Hash(hash_node) = to_encode {
            return EncodedNode::Hash(hash_node.hash);
        }

        let data = self.encode_raw(to_encode);
        // Nodes smaller than 32 bytes are stored inside their parent,
        // Nodes equal to 32 bytes are returned directly
        if data.len() < HASHED_LENGTH {
            EncodedNode::Inline(data)
        } else {
            let hash = keccak256(&data);
            self.cache.insert(hash.to_vec(), data);

            self.gen_keys.insert(hash.to_vec());
            EncodedNode::Hash(hash)
        }
    }

    fn encode_raw(&mut self, node: &Node) -> Vec<u8> {
        match node {
            Node::Empty => rlp::NULL_RLP.to_vec(),
            Node::Leaf(leaf) => {
                let mut stream = RlpStream::new_list(2);
                stream.append(&leaf.key.encode_compact());
                stream.append(&leaf.value);
                stream.out().to_vec()
            }
            Node::Branch(branch) => {
                let borrow_branch = branch.read().unwrap();

                let mut stream = RlpStream::new_list(17);
                for i in 0..16 {
                    let n = &borrow_branch.children[i];
                    match self.write_node(n) {
                        EncodedNode::Hash(hash) => stream.append(&hash.as_slice()),
                        EncodedNode::Inline(data) => stream.append_raw(&data, 1),
                    };
                }

                match &borrow_branch.value {
                    Some(v) => stream.append(v),
                    None => stream.append_empty_data(),
                };
                stream.out().to_vec()
            }
            Node::Extension(ext) => {
                let borrow_ext = ext.read().unwrap();

                let mut stream = RlpStream::new_list(2);
                stream.append(&borrow_ext.prefix.encode_compact());
                match self.write_node(&borrow_ext.node) {
                    EncodedNode::Hash(hash) => stream.append(&hash.as_slice()),
                    EncodedNode::Inline(data) => stream.append_raw(&data, 1),
                };
                stream.out().to_vec()
            }
            Node::Hash(_hash) => unreachable!(),
        }
    }

    fn decode_node(data: &[u8]) -> TrieResult<Node> {
        let r = Rlp::new(data);

        match r.prototype()? {
            Prototype::Data(0) => Ok(Node::Empty),
            Prototype::List(2) => {
                let key = r.at(0)?.data()?;
                let key = Nibbles::from_compact(key);

                if key.is_leaf() {
                    Ok(Node::from_leaf(key, r.at(1)?.data()?.to_vec()))
                } else {
                    let n = Self::decode_node(r.at(1)?.as_raw())?;

                    Ok(Node::from_extension(key, n))
                }
            }
            Prototype::List(17) => {
                let mut nodes = empty_children();
                #[allow(clippy::needless_range_loop)]
                for i in 0..nodes.len() {
                    let rlp_data = r.at(i)?;
                    let n = Self::decode_node(rlp_data.as_raw())?;
                    nodes[i] = n;
                }

                // The last element is a value node.
                let value_rlp = r.at(16)?;
                let value = if value_rlp.is_empty() {
                    None
                } else {
                    Some(value_rlp.data()?.to_vec())
                };

                Ok(Node::from_branch(nodes, value))
            }
            _ => {
                if r.is_data() && r.size() == HASHED_LENGTH {
                    let hash = B256::from_slice(r.data()?);
                    Ok(Node::from_hash(hash))
                } else {
                    Err(TrieError::InvalidData)
                }
            }
        }
    }

    fn recover_from_db(&self, key: B256) -> TrieResult<Option<Node>> {
        if key == keccak256(rlp::NULL_RLP) {
            return Ok(Some(Node::Empty));
        }
        let node = match self
            .db
            .get(key.as_slice())
            .map_err(|e| TrieError::DB(e.to_string()))?
        {
            Some(value) => Some(Self::decode_node(&value)?),
            None => None,
        };
        Ok(node)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        sync::Arc,
    };

    use alloy::primitives::{keccak256, B256};
    use rand::{distributions::Alphanumeric, seq::SliceRandom, thread_rng, Rng};

    use super::{EthTrie, Trie};
    use crate::{
        db::{MemoryDB, DB},
        errors::TrieError,
        nibbles::Nibbles,
    };

    #[test]
    fn test_trie_insert() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb);
        trie.insert(b"test", b"test").unwrap();
    }

    #[test]
    fn test_trie_get() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb);
        trie.insert(b"test", b"test").unwrap();
        let v = trie.get(b"test").unwrap();

        assert_eq!(Some(b"test".to_vec()), v)
    }

    #[test]
    fn test_trie_get_missing() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb);
        trie.insert(b"test", b"test").unwrap();
        let v = trie.get(b"no-val").unwrap();

        assert_eq!(None, v)
    }

    fn corrupt_trie() -> (EthTrie<MemoryDB>, B256, B256) {
        let memdb = Arc::new(MemoryDB::new(true));
        let corruptor_db = memdb.clone();
        let mut trie = EthTrie::new(memdb);
        trie.insert(b"test1-key", b"really-long-value1-to-prevent-inlining")
            .unwrap();
        trie.insert(b"test2-key", b"really-long-value2-to-prevent-inlining")
            .unwrap();
        let actual_root_hash = trie.root_hash().unwrap();

        // Manually corrupt the database by removing a trie node
        // This is the hash for the leaf node for test2-key
        let node_hash_to_delete = b"\xcb\x15v%j\r\x1e\te_TvQ\x8d\x93\x80\xd1\xa2\xd1\xde\xfb\xa5\xc3hJ\x8c\x9d\xb93I-\xbd";
        assert_ne!(corruptor_db.get(node_hash_to_delete).unwrap(), None);
        corruptor_db.remove(node_hash_to_delete).unwrap();
        assert_eq!(corruptor_db.get(node_hash_to_delete).unwrap(), None);

        (
            trie,
            actual_root_hash,
            B256::from_slice(node_hash_to_delete),
        )
    }

    #[test]
    /// When a database entry is missing, get returns a MissingTrieNode error
    fn test_trie_get_corrupt() {
        let (trie, actual_root_hash, deleted_node_hash) = corrupt_trie();

        let result = trie.get(b"test2-key");

        if let Err(missing_trie_node) = result {
            let expected_error = TrieError::MissingTrieNode {
                node_hash: deleted_node_hash,
                traversed: Some(Nibbles::from_hex(&[7, 4, 6, 5, 7, 3, 7, 4, 3, 2])),
                root_hash: Some(actual_root_hash),
                err_key: Some(b"test2-key".to_vec()),
            };
            assert_eq!(missing_trie_node, expected_error);
        } else {
            // The only acceptable result here was a MissingTrieNode
            panic!(
                "Must get a MissingTrieNode when database entry is missing, but got {:?}",
                result
            );
        }
    }

    #[test]
    /// When a database entry is missing, delete returns a MissingTrieNode error
    fn test_trie_delete_corrupt() {
        let (mut trie, actual_root_hash, deleted_node_hash) = corrupt_trie();

        let result = trie.remove(b"test2-key");

        if let Err(missing_trie_node) = result {
            let expected_error = TrieError::MissingTrieNode {
                node_hash: deleted_node_hash,
                traversed: Some(Nibbles::from_hex(&[7, 4, 6, 5, 7, 3, 7, 4, 3, 2])),
                root_hash: Some(actual_root_hash),
                err_key: Some(b"test2-key".to_vec()),
            };
            assert_eq!(missing_trie_node, expected_error);
        } else {
            // The only acceptable result here was a MissingTrieNode
            panic!(
                "Must get a MissingTrieNode when database entry is missing, but got {:?}",
                result
            );
        }
    }

    #[test]
    /// When a database entry is missing, delete returns a MissingTrieNode error
    fn test_trie_delete_refactor_corrupt() {
        let (mut trie, actual_root_hash, deleted_node_hash) = corrupt_trie();

        let result = trie.remove(b"test1-key");

        if let Err(missing_trie_node) = result {
            let expected_error = TrieError::MissingTrieNode {
                node_hash: deleted_node_hash,
                traversed: None,
                root_hash: Some(actual_root_hash),
                err_key: Some(b"test1-key".to_vec()),
            };
            assert_eq!(missing_trie_node, expected_error);
        } else {
            // The only acceptable result here was a MissingTrieNode
            panic!(
                "Must get a MissingTrieNode when database entry is missing, but got {:?}",
                result
            );
        }
    }

    #[test]
    /// When a database entry is missing, get_proof returns a MissingTrieNode error
    fn test_trie_get_proof_corrupt() {
        let (mut trie, actual_root_hash, deleted_node_hash) = corrupt_trie();

        let result = trie.get_proof(b"test2-key");

        if let Err(missing_trie_node) = result {
            let expected_error = TrieError::MissingTrieNode {
                node_hash: deleted_node_hash,
                traversed: None,
                root_hash: Some(actual_root_hash),
                err_key: Some(b"test2-key".to_vec()),
            };
            assert_eq!(missing_trie_node, expected_error);
        } else {
            // The only acceptable result here was a MissingTrieNode
            panic!(
                "Must get a MissingTrieNode when database entry is missing, but got {:?}",
                result
            );
        }
    }

    #[test]
    /// When a database entry is missing, insert returns a MissingTrieNode error
    fn test_trie_insert_corrupt() {
        let (mut trie, actual_root_hash, deleted_node_hash) = corrupt_trie();

        let result = trie.insert(b"test2-neighbor", b"any");

        if let Err(missing_trie_node) = result {
            let expected_error = TrieError::MissingTrieNode {
                node_hash: deleted_node_hash,
                traversed: Some(Nibbles::from_hex(&[7, 4, 6, 5, 7, 3, 7, 4, 3, 2])),
                root_hash: Some(actual_root_hash),
                err_key: Some(b"test2-neighbor".to_vec()),
            };
            assert_eq!(missing_trie_node, expected_error);
        } else {
            // The only acceptable result here was a MissingTrieNode
            panic!(
                "Must get a MissingTrieNode when database entry is missing, but got {:?}",
                result
            );
        }
    }

    #[test]
    fn test_trie_random_insert() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb);

        for _ in 0..1000 {
            let rand_str: String = thread_rng()
                .sample_iter(&Alphanumeric)
                .take(30)
                .map(char::from)
                .collect();
            let val = rand_str.as_bytes();
            trie.insert(val, val).unwrap();

            let v = trie.get(val).unwrap();
            assert_eq!(v.map(|v| v.to_vec()), Some(val.to_vec()));
        }
    }

    #[test]
    fn test_trie_contains() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb);
        trie.insert(b"test", b"test").unwrap();
        assert!(trie.contains(b"test").unwrap());
        assert!(!trie.contains(b"test2").unwrap());
    }

    #[test]
    fn test_trie_remove() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb);
        trie.insert(b"test", b"test").unwrap();
        let removed = trie.remove(b"test").unwrap();
        assert!(removed)
    }

    #[test]
    fn test_trie_random_remove() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb);

        for _ in 0..1000 {
            let rand_str: String = thread_rng()
                .sample_iter(&Alphanumeric)
                .take(30)
                .map(char::from)
                .collect();
            let val = rand_str.as_bytes();
            trie.insert(val, val).unwrap();

            let removed = trie.remove(val).unwrap();
            assert!(removed);
        }
    }

    #[test]
    fn test_trie_at_root_six_keys() {
        let memdb = Arc::new(MemoryDB::new(true));
        let root = {
            let mut trie = EthTrie::new(memdb.clone());
            trie.insert(b"test", b"test").unwrap();
            trie.insert(b"test1", b"test").unwrap();
            trie.insert(b"test2", b"test").unwrap();
            trie.insert(b"test23", b"test").unwrap();
            trie.insert(b"test33", b"test").unwrap();
            trie.insert(b"test44", b"test").unwrap();
            trie.root_hash().unwrap()
        };

        let mut trie = EthTrie::new(memdb).at_root(root);
        let v1 = trie.get(b"test33").unwrap();
        assert_eq!(Some(b"test".to_vec()), v1);
        let v2 = trie.get(b"test44").unwrap();
        assert_eq!(Some(b"test".to_vec()), v2);
        let root2 = trie.root_hash().unwrap();
        assert_eq!(hex::encode(root), hex::encode(root2));
    }

    #[test]
    fn test_trie_at_root_and_insert() {
        let memdb = Arc::new(MemoryDB::new(true));
        let root = {
            let mut trie = EthTrie::new(Arc::clone(&memdb));
            trie.insert(b"test", b"test").unwrap();
            trie.insert(b"test1", b"test").unwrap();
            trie.insert(b"test2", b"test").unwrap();
            trie.insert(b"test23", b"test").unwrap();
            trie.insert(b"test33", b"test").unwrap();
            trie.insert(b"test44", b"test").unwrap();
            trie.root_hash().unwrap()
        };

        let mut trie = EthTrie::new(memdb).at_root(root);
        trie.insert(b"test55", b"test55").unwrap();
        trie.root_hash().unwrap();
        let v = trie.get(b"test55").unwrap();
        assert_eq!(Some(b"test55".to_vec()), v);
    }

    #[test]
    fn test_trie_at_root_and_delete() {
        let memdb = Arc::new(MemoryDB::new(true));
        let root = {
            let mut trie = EthTrie::new(Arc::clone(&memdb));
            trie.insert(b"test", b"test").unwrap();
            trie.insert(b"test1", b"test").unwrap();
            trie.insert(b"test2", b"test").unwrap();
            trie.insert(b"test23", b"test").unwrap();
            trie.insert(b"test33", b"test").unwrap();
            trie.insert(b"test44", b"test").unwrap();
            trie.root_hash().unwrap()
        };

        let mut trie = EthTrie::new(memdb).at_root(root);
        let removed = trie.remove(b"test44").unwrap();
        assert!(removed);
        let removed = trie.remove(b"test33").unwrap();
        assert!(removed);
        let removed = trie.remove(b"test23").unwrap();
        assert!(removed);
    }

    #[test]
    fn test_multiple_trie_roots() {
        let k0 = B256::ZERO;
        let k1 = B256::random();
        let v = B256::random();

        let root1 = {
            let memdb = Arc::new(MemoryDB::new(true));
            let mut trie = EthTrie::new(memdb);
            trie.insert(k0.as_slice(), v.as_slice()).unwrap();
            trie.root_hash().unwrap()
        };

        let root2 = {
            let memdb = Arc::new(MemoryDB::new(true));
            let mut trie = EthTrie::new(memdb);
            trie.insert(k0.as_slice(), v.as_slice()).unwrap();
            trie.insert(k1.as_slice(), v.as_slice()).unwrap();
            trie.root_hash().unwrap();
            trie.remove(k1.as_ref()).unwrap();
            trie.root_hash().unwrap()
        };

        let root3 = {
            let memdb = Arc::new(MemoryDB::new(true));
            let mut trie1 = EthTrie::new(Arc::clone(&memdb));
            trie1.insert(k0.as_slice(), v.as_slice()).unwrap();
            trie1.insert(k1.as_slice(), v.as_slice()).unwrap();
            trie1.root_hash().unwrap();
            let root = trie1.root_hash().unwrap();
            let mut trie2 = trie1.at_root(root);
            trie2.remove(k1.as_slice()).unwrap();
            trie2.root_hash().unwrap()
        };

        assert_eq!(root1, root2);
        assert_eq!(root2, root3);
    }

    #[test]
    fn test_delete_stale_keys_with_random_insert_and_delete() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb);

        let mut rng = rand::thread_rng();
        let mut keys = vec![];
        for _ in 0..100 {
            let random_bytes: Vec<u8> = (0..rng.gen_range(2..30))
                .map(|_| rand::random::<u8>())
                .collect();
            trie.insert(&random_bytes, &random_bytes).unwrap();
            keys.push(random_bytes.clone());
        }
        trie.root_hash().unwrap();
        let slice = &mut keys;
        slice.shuffle(&mut rng);

        for key in slice.iter() {
            trie.remove(key).unwrap();
        }
        trie.root_hash().unwrap();

        let empty_node_key = keccak256(rlp::NULL_RLP);
        let value = trie.db.get(empty_node_key.as_slice()).unwrap().unwrap();
        assert_eq!(value, &rlp::NULL_RLP)
    }

    #[test]
    fn insert_full_branch() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb);

        trie.insert(b"test", b"test").unwrap();
        trie.insert(b"test1", b"test").unwrap();
        trie.insert(b"test2", b"test").unwrap();
        trie.insert(b"test23", b"test").unwrap();
        trie.insert(b"test33", b"test").unwrap();
        trie.insert(b"test44", b"test").unwrap();
        trie.root_hash().unwrap();

        let v = trie.get(b"test").unwrap();
        assert_eq!(Some(b"test".to_vec()), v);
    }

    #[test]
    fn iterator_trie() {
        let memdb = Arc::new(MemoryDB::new(true));
        let root1: B256;
        let mut kv = HashMap::new();
        kv.insert(b"test".to_vec(), b"test".to_vec());
        kv.insert(b"test1".to_vec(), b"test1".to_vec());
        kv.insert(b"test11".to_vec(), b"test2".to_vec());
        kv.insert(b"test14".to_vec(), b"test3".to_vec());
        kv.insert(b"test16".to_vec(), b"test4".to_vec());
        kv.insert(b"test18".to_vec(), b"test5".to_vec());
        kv.insert(b"test2".to_vec(), b"test6".to_vec());
        kv.insert(b"test23".to_vec(), b"test7".to_vec());
        kv.insert(b"test9".to_vec(), b"test8".to_vec());
        {
            let mut trie = EthTrie::new(memdb.clone());
            let mut kv = kv.clone();
            let mut kv2 = kv.clone();
            kv.iter().for_each(|(k, v)| {
                trie.insert(k, v).unwrap();
            });
            root1 = trie.root_hash().unwrap();

            kv2.remove(&b"test".to_vec());
            kv2.remove(&b"test1".to_vec());
            kv2.remove(&b"test11".to_vec());
            kv2.remove(&b"test14".to_vec());

            trie.iter()
                .for_each(|(k, v)| assert_eq!(kv.remove(&k).unwrap(), v));
            assert!(kv.is_empty());

            trie.iter_after(b"test14")
                .for_each(|(k, v)| assert_eq!(kv2.remove(&k).unwrap(), v));
            assert!(kv2.is_empty());
        }

        {
            let mut trie = EthTrie::new(memdb.clone());
            let mut kv2 = HashMap::new();
            kv2.insert(b"test".to_vec(), b"test11".to_vec());
            kv2.insert(b"test1".to_vec(), b"test12".to_vec());
            kv2.insert(b"test14".to_vec(), b"test13".to_vec());
            kv2.insert(b"test22".to_vec(), b"test14".to_vec());
            kv2.insert(b"test9".to_vec(), b"test15".to_vec());
            kv2.insert(b"test16".to_vec(), b"test16".to_vec());
            kv2.insert(b"test2".to_vec(), b"test17".to_vec());
            kv2.iter().for_each(|(k, v)| {
                trie.insert(k, v).unwrap();
            });

            trie.root_hash().unwrap();

            let mut kv_delete = HashSet::new();
            kv_delete.insert(b"test".to_vec());
            kv_delete.insert(b"test1".to_vec());
            kv_delete.insert(b"test14".to_vec());

            kv_delete.iter().for_each(|k| {
                trie.remove(k).unwrap();
            });

            kv2.retain(|k, _| !kv_delete.contains(k));

            trie.root_hash().unwrap();
            trie.iter()
                .for_each(|(k, v)| assert_eq!(kv2.remove(&k).unwrap(), v));
            assert!(kv2.is_empty());
        }

        let trie = EthTrie::new(memdb).at_root(root1);
        trie.iter()
            .for_each(|(k, v)| assert_eq!(kv.remove(&k).unwrap(), v));
        assert!(kv.is_empty());
    }

    #[test]
    fn iterator_clone_trie() {
        let root: B256;
        let mut contents = HashMap::new();
        {
            let mut test_values = HashMap::new();
            test_values.insert(b"test".to_vec(), b"test".to_vec());
            test_values.insert(b"test1".to_vec(), b"test1".to_vec());
            test_values.insert(b"test11".to_vec(), b"test2".to_vec());
            test_values.insert(b"test14".to_vec(), b"test3".to_vec());
            test_values.insert(b"test16".to_vec(), b"test4".to_vec());
            test_values.insert(b"test18".to_vec(), b"test5".to_vec());
            test_values.insert(b"test2".to_vec(), b"test6".to_vec());
            test_values.insert(b"test23".to_vec(), b"test7".to_vec());
            test_values.insert(b"test9".to_vec(), b"test8".to_vec());
            let mut trie = EthTrie::new(Arc::new(MemoryDB::new(true)));
            for (k, v) in &test_values {
                trie.insert(k, v).unwrap();
            }
            root = trie.root_hash().unwrap();
            for (k, v) in trie.iter() {
                contents.insert(k, v);
            }
        }

        {
            let mut trie = EthTrie::new(Arc::new(MemoryDB::new(true)));
            for (k, v) in &contents {
                trie.insert(k, v).unwrap();
            }
            assert_eq!(trie.root_hash().unwrap(), root);
        }
    }

    #[test]
    fn prefix_iterator_trie() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut kv = HashMap::new();
        kv.insert(b"test".to_vec(), b"test".to_vec());
        kv.insert(b"test1".to_vec(), b"test1".to_vec());
        kv.insert(b"test11".to_vec(), b"test2".to_vec());
        kv.insert(b"test14".to_vec(), b"test3".to_vec());
        kv.insert(b"test16".to_vec(), b"test4".to_vec());
        kv.insert(b"test18".to_vec(), b"test5".to_vec());
        kv.insert(b"test2".to_vec(), b"test6".to_vec());
        kv.insert(b"test23".to_vec(), b"test7".to_vec());
        kv.insert(b"test9".to_vec(), b"test8".to_vec());
        kv.insert(b"TTTest9".to_vec(), b"test9".to_vec());

        let mut trie = EthTrie::new(memdb.clone());
        kv.iter().for_each(|(k, v)| {
            trie.insert(k, v).unwrap();
        });
        trie.root_hash().unwrap();

        let cases: &[&[u8]] = &[
            b"", b"t", b"te", b"tes", b"test", b"test1", b"test11", b"test14", b"test15", b"test2",
            b"test23", b"test24", b"test9", b"T", b"TT", b"s",
        ];

        for prefix in cases {
            println!("prefix: {:?}", Nibbles::from_raw(prefix, false).get_data());
            let mut kv: HashMap<_, _> = kv
                .clone()
                .into_iter()
                .filter(|(k, _)| k.starts_with(prefix))
                .collect();
            let iter = trie.iter_by_prefix(prefix).unwrap();
            for (k, v) in iter {
                println!("key: {:?}", Nibbles::from_raw(prefix, false).get_data());
                assert_eq!(kv.remove(&k).unwrap(), v);
            }
            println!(
                "remaining keys: {:?}",
                kv.keys()
                    .map(|k| String::from_utf8_lossy(k))
                    .collect::<Vec<_>>()
            );
            assert!(kv.is_empty());
        }
    }

    #[test]
    fn test_small_trie_at_root() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb.clone());
        trie.insert(b"key", b"val").unwrap();
        let new_root_hash = trie.commit().unwrap();

        let empty_trie = EthTrie::new(memdb);
        // Can't find key in new trie at empty root
        assert_eq!(empty_trie.get(b"key").unwrap(), None);

        let trie_view = empty_trie.at_root(new_root_hash);
        assert_eq!(&trie_view.get(b"key").unwrap().unwrap(), b"val");

        // Previous trie was not modified
        assert_eq!(empty_trie.get(b"key").unwrap(), None);
    }

    #[test]
    fn test_large_trie_at_root() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb.clone());
        trie.insert(
            b"pretty-long-key",
            b"even-longer-val-to-go-more-than-32-bytes",
        )
        .unwrap();
        let new_root_hash = trie.commit().unwrap();

        let empty_trie = EthTrie::new(memdb);
        // Can't find key in new trie at empty root
        assert_eq!(empty_trie.get(b"pretty-long-key").unwrap(), None);

        let trie_view = empty_trie.at_root(new_root_hash);
        assert_eq!(
            &trie_view.get(b"pretty-long-key").unwrap().unwrap(),
            b"even-longer-val-to-go-more-than-32-bytes"
        );

        // Previous trie was not modified
        assert_eq!(empty_trie.get(b"pretty-long-key").unwrap(), None);
    }
}
