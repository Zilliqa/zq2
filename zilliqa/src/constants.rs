use crate::transaction::{EvmGas, ScillaGas};

pub const MINIMUM_ETH_GAS: EvmGas = EvmGas(21_000);

pub const MINIMUM_ZIL_GAS: ScillaGas = ScillaGas(10);
