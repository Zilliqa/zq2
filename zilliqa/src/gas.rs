#![allow(dead_code)]
#![allow(unused_variables)]

/// Minimum gas required to do simple transfer (eth)
const MIN_ETH_GAS: u64 = 21000;
/// Gas required to transfer using zilliqa API
const NORMAL_TRAN_GAS: u64 = 50;

/// Multiplier used for converting gas units between eth and zilliqa
const SCALING_FACTOR: u64 = MIN_ETH_GAS / NORMAL_TRAN_GAS;

pub(crate) fn calc_deploy_eth_gas(code: &[u8], data: &[u8]) -> u64 {
    const GAS_COST_FOR_ZERO_DATA: u64 = 4;
    const GAS_COST_FOR_NON_ZERO_DATA: u64 = 16;
    const CONTRACT_DEPLOYMENT_BASE_FEE: u64 = 32000;

    fn calculate(input: &[u8]) -> u64 {
        input.into_iter().fold(0u64, |acc, byte| {
            if *byte == 0 {
                acc + GAS_COST_FOR_ZERO_DATA
            } else {
                acc + GAS_COST_FOR_NON_ZERO_DATA
            }
        })
    }

    MIN_ETH_GAS + CONTRACT_DEPLOYMENT_BASE_FEE + calculate(code) + calculate(data)
}

pub struct GasTracker {
    /// Provided gas by estimate/transaction
    given_core_gas: u64,
    given_eth_remainder: u64,
    /// Calculated as execution runs
    used_gas_core: u64,
    eth_gas_remainder: u64,
}

impl GasTracker {
    pub fn create_from_eth(start_gas: u64) -> Self {
        Self {
            given_core_gas: start_gas / SCALING_FACTOR,
            given_eth_remainder: start_gas % SCALING_FACTOR,
            used_gas_core: 0,
            eth_gas_remainder: 0,
        }
    }

    pub fn create_from_zil(start_gas: u64) -> Self {
        Self {
            given_core_gas: start_gas,
            given_eth_remainder: 0,
            used_gas_core: 0,
            eth_gas_remainder: 0,
        }
    }

    pub fn account_eth_gas(&mut self, used_gas: u64) {
        // Calculate total used so far and add newly used
        let absolute_eth = self.used_gas_core * SCALING_FACTOR + self.eth_gas_remainder + used_gas;
        self.used_gas_core = absolute_eth / SCALING_FACTOR;
        self.eth_gas_remainder = absolute_eth % SCALING_FACTOR;
    }

    pub fn account_zil_gas(&mut self, used_gas: u64) {
        self.used_gas_core += used_gas;
    }

    pub fn get_left_eth(&self) -> u64 {
        let used_absolute = self.used_gas_core * SCALING_FACTOR + self.eth_gas_remainder;
        let given_absolute = self.given_core_gas * SCALING_FACTOR + self.given_eth_remainder;

        // Either some gas left or 0
        given_absolute.saturating_sub(used_absolute)
    }

    pub fn get_left_zil(&self) -> u64 {
        // There might be some gas in `left self.given_eth_remainder` but that's not enough for a single zil unit
        self.given_core_gas.saturating_sub(self.used_gas_core)
    }
}

#[cfg(test)]
mod tests {
    use crate::gas::{GasTracker, SCALING_FACTOR};

    #[test]
    fn eth_init() {
        const INIT_ETH_GAS: u64 = 100000;
        let tracker = GasTracker::create_from_eth(INIT_ETH_GAS);
        assert_eq!(tracker.given_core_gas, INIT_ETH_GAS / SCALING_FACTOR);
        assert_eq!(tracker.given_eth_remainder, INIT_ETH_GAS % SCALING_FACTOR);
        assert_eq!(tracker.used_gas_core, 0);
        assert_eq!(tracker.eth_gas_remainder, 0);

        assert_eq!(tracker.get_left_eth(), INIT_ETH_GAS);
        assert_eq!(tracker.get_left_zil(), INIT_ETH_GAS / SCALING_FACTOR);
    }

    #[test]
    fn zil_init() {
        const INIT_ZIL_GAS: u64 = 100;
        let tracker = GasTracker::create_from_zil(INIT_ZIL_GAS);
        assert_eq!(tracker.given_core_gas, INIT_ZIL_GAS);
        assert_eq!(tracker.given_eth_remainder, 0);
        assert_eq!(tracker.eth_gas_remainder, 0);
        assert_eq!(tracker.used_gas_core, 0);

        assert_eq!(tracker.get_left_eth(), INIT_ZIL_GAS * SCALING_FACTOR);
        assert_eq!(tracker.get_left_zil(), INIT_ZIL_GAS);
    }

    #[test]
    fn eth_init_and_eth_use() {
        const INIT_ETH_GAS: u64 = 100000;
        let mut tracker = GasTracker::create_from_eth(INIT_ETH_GAS);
        let mut expected = INIT_ETH_GAS - 350;
        tracker.account_eth_gas(350);
        assert_eq!(tracker.get_left_eth(), expected);

        tracker.account_eth_gas(350);
        expected -= 350;
        assert_eq!(tracker.get_left_eth(), expected);

        tracker.account_eth_gas(3150);
        expected -= 3150;
        assert_eq!(tracker.get_left_eth(), expected);

        tracker.account_eth_gas(1999);
        expected -= 1999;
        assert_eq!(tracker.get_left_eth(), expected);

        tracker.account_eth_gas(expected);
        assert_eq!(tracker.get_left_eth(), 0);
        assert_eq!(tracker.get_left_zil(), 0);
    }

    #[test]
    fn eth_init_and_mixed_use() {
        const INIT_ETH_GAS: u64 = 100000;
        let mut tracker = GasTracker::create_from_eth(INIT_ETH_GAS);
        let mut expected = INIT_ETH_GAS - 350;
        tracker.account_eth_gas(350);
        assert_eq!(tracker.get_left_eth(), expected);

        tracker.account_zil_gas(50);
        expected -= 50 * SCALING_FACTOR;
        assert_eq!(tracker.get_left_eth(), expected);
        assert_eq!(tracker.get_left_zil(), 188);

        tracker.account_zil_gas(49);
        expected -= 49 * SCALING_FACTOR;
        assert_eq!(tracker.get_left_eth(), expected);
        assert_eq!(tracker.get_left_zil(), 139);

        tracker.account_zil_gas(139);
        assert_eq!(tracker.get_left_zil(), 0);
        assert_eq!(tracker.get_left_eth(), 0);
    }

    #[test]
    fn eth_init_and_core_use() {
        const INIT_ETH_GAS: u64 = 100000;
        let mut tracker = GasTracker::create_from_eth(INIT_ETH_GAS);

        tracker.account_zil_gas(238);
        assert_eq!(tracker.get_left_zil(), 0);
        assert_eq!(true, tracker.get_left_eth() > 0);
    }

    #[test]
    fn zil_init_and_zil_use() {
        const INIT_ZIL_GAS: u64 = 300;
        let mut tracker = GasTracker::create_from_zil(INIT_ZIL_GAS);

        tracker.account_zil_gas(238);
        assert_eq!(tracker.get_left_zil(), 62);

        tracker.account_zil_gas(61);
        assert_eq!(tracker.get_left_zil(), 1);

        tracker.account_zil_gas(1);
        assert_eq!(tracker.get_left_zil(), 0);
        assert_eq!(tracker.get_left_eth(), 0);
    }
}
