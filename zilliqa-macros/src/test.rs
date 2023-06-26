use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;
use syn::ItemFn;

// Much of this code is adapted from https://github.com/tokio-rs/tokio/blob/910a1e2fcf8ebafd41c2841144c3a1037af7dc40/tokio-macros/src/lib.rs.

pub(crate) fn test_macro(_args: TokenStream, item: TokenStream) -> TokenStream {
    let mut input: ItemFn = match syn::parse2(item.clone()) {
        Ok(it) => it,
        Err(e) => return token_stream_with_error(item, e),
    };

    // Take the name of the test function as written.
    let test_name = input.sig.ident;
    // Rename the test function to "inner". We will add it as an inner function of our actual test and call it.
    let inner_name = Ident::new("inner", Span::call_site());
    input.sig.ident = inner_name.clone();

    quote! {
        #[tokio::test(flavor = "multi_thread")]
        async fn #test_name() {
            // The original test function
            #input

            // Set up a tracing subscriber, so we can see logs from failed test cases if needed.
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env());
            tracing_subscriber::util::SubscriberInitExt::set_default(subscriber);

            // Work out what RNG seeds to run the test with.
            let seeds: Vec<u64> = if let Some(seed) = std::env::var_os("ZQ_TEST_RNG_SEED") {
                vec![seed.to_str().unwrap().parse().unwrap()]
            } else {
                let samples: usize = std::env::var_os("ZQ_TEST_SAMPLES")
                    .map(|s| s.to_str().unwrap().parse().unwrap())
                    .unwrap_or(1);
                // Generate random seeds using the thread-local RNG.
                rand::Rng::sample_iter(rand::thread_rng(), rand::distributions::Standard).take(samples).collect()
            };

            let mut set = tokio::task::JoinSet::new();

            for seed in seeds {
                set.spawn(async move {
                    println!("Reproduce this test run by setting ZQ_TEST_RNG_SEED={seed}");
                    let mut rng = <rand_chacha::ChaCha8Rng as rand_core::SeedableRng>::seed_from_u64(seed);
                    let network = crate::Network::new(&mut rng, 4);
                    // Call the original test function
                    #inner_name(network).await;
                });
            }

            while let Some(result) = set.join_next().await {
                let () = result.unwrap();
            }
        }
    }
}

// If any of the steps for this macro fail, we still want to expand to an item that is as close to the expected output
// as possible. This helps out IDEs such that completions and other related features keep working.
fn token_stream_with_error(mut tokens: TokenStream, error: syn::Error) -> TokenStream {
    tokens.extend(error.into_compile_error());
    tokens
}
