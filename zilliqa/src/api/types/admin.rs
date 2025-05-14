use std::collections::BTreeMap;

use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct VotesReceivedReturnee {
    pub votes: BTreeMap<crate::crypto::Hash, crate::consensus::BlockVotes>,
    pub buffered_votes: BTreeMap<crate::crypto::Hash, Vec<crate::message::Vote>>,
    pub new_views: BTreeMap<u64, crate::consensus::NewViewVote>,
}
