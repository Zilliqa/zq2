use revm::{
    context_interface::block::BlobExcessGasAndPrice,
    primitives::{eip4844::MIN_BLOB_GASPRICE, hardfork::SpecId},
};

use crate::{
    cfg::Fork,
    evm::{SPEC_ID_CANCUN, SPEC_ID_PRAGUE, SPEC_ID_SHANGHAI},
};

pub fn select_spec_and_blob_params(fork: &Fork) -> (SpecId, Option<BlobExcessGasAndPrice>) {
    if fork.pectra_active {
        (
            SPEC_ID_PRAGUE,
            Some(BlobExcessGasAndPrice::new(0, MIN_BLOB_GASPRICE)),
        )
    } else if fork.cancun_active {
        (
            SPEC_ID_CANCUN,
            Some(BlobExcessGasAndPrice::new(0, MIN_BLOB_GASPRICE)),
        )
    } else {
        (SPEC_ID_SHANGHAI, None)
    }
}
