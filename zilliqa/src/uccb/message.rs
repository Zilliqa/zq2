//! Message types for UCCB

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UCCBExternalMessage {
    Hello,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UCCBInternalMessage {
    HelloInternal,
}
