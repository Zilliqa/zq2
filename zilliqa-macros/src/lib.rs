mod test;

use proc_macro::TokenStream;

/// Attributes:
/// * restrict_concurrency: spawns fewer threads than normal (currently used in scilla tests)
/// * do_snapshots: enables saving of weak subjectivity checkpoint snapshot files
#[proc_macro_attribute]
pub fn test(args: TokenStream, item: TokenStream) -> TokenStream {
    test::test_macro(args.into(), item.into()).into()
}
