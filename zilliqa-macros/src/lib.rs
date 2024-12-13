mod test;

use proc_macro::TokenStream;

/// Attributes:
/// * restrict_concurrency: spawns fewer threads than normal (currently used in scilla tests)
/// * do_checkpoints: enables saving of weak subjectivity checkpoint snapshot files
/// * deposit_v3_upgrade_block_height: creates a ContractUpgradesBlockHeights consensus configuration with deposit_v3 upgrade block height
#[proc_macro_attribute]
pub fn test(args: TokenStream, item: TokenStream) -> TokenStream {
    test::test_macro(args.into(), item.into()).into()
}
