use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct VotesReceivedReturnee {
    pub votes: Vec<(crate::crypto::Hash, crate::consensus::BlockVotes)>,
    pub buffered_votes: Vec<(crate::crypto::Hash, Vec<crate::message::Vote>)>,
    pub new_views: Vec<(u64, crate::consensus::NewViewVote)>,
}
