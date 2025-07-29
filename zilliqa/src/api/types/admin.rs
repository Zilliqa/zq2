use libp2p::PeerId;
use serde::Serialize;

use crate::crypto::NodePublicKey;

#[derive(Clone, Debug, Serialize)]
pub struct VotesReceivedReturnee {
    pub votes: Vec<(crate::crypto::Hash, crate::consensus::BlockVotes, VoteCount)>,
    pub buffered_votes: Vec<(crate::crypto::Hash, Vec<(PeerId, crate::message::Vote)>)>,
    pub new_views: Vec<(u64, crate::consensus::NewViewVote, VoteCount)>,
}

#[derive(Clone, Debug, Serialize)]
pub struct VoteCount {
    pub voted: Vec<NodePublicKey>,
    pub not_voted: Vec<NodePublicKey>,
}
