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

            // Work out what RNG seeds to run the test with.
            let seeds: Vec<u64> = if let Some(seed) = std::env::var_os("ZQ_TEST_RNG_SEED") {
                vec![seed.to_str().unwrap().parse().unwrap()]
            } else {
                let samples: usize = std::env::var_os("ZQ_TEST_SAMPLES")
                    .map(|s| s.to_str().unwrap().parse().expect(&format!("Failed to parse ZQ_TEST_SAMPLES env var: {:?}", s)))
                    .unwrap_or(1);
                // Generate random seeds using the thread-local RNG.
                //rand::Rng::sample_iter(rand::thread_rng(), rand::distributions::Standard).take(samples).collect()
                // Populate from a range
                let ret = (0..samples).map(|x| x as u64).collect();
                ret
                //(0..samples).collect().iter().map(|x| *x as u64).collect()
            };
            let style = indicatif::ProgressStyle::with_template("[{elapsed_precise}/{duration_precise}] {wide_bar:.cyan/blue} {pos:>}/{len}").unwrap().progress_chars("##-");
            let pb = indicatif::ProgressBar::new(seeds.len() as u64);
            pb.set_style(style);

            pb.tick();

            let mut set = tokio::task::JoinSet::new();

            // Keep a map of task IDs to test seeds, so we can print the seed of tasks that fail. We can't print the
            // seed as soon as the test has failed, because other cases will be running in parallel and we don't want
            // to interlace different cases' seeds and error messages. Instead, we wait until we resolve tasks from the
            // `JoinSet` (via `.join_next_with_id()`), where we can guarantee to only process one case at a time.
            let mut id_to_seed = std::collections::HashMap::new();

            // time this whole test to make sure its not taking too long
            use std::time::{Duration, Instant};
            let start = Instant::now();
            let seeds_number = seeds.len();

            // Silence the default panic hook.
            std::panic::set_hook(Box::new(|_| {}));

            for seed in seeds {
                let handle = set.spawn(async move {
                    // Set up a tracing subscriber, so we can see logs from failed test cases.
                    let subscriber = tracing_subscriber::fmt()
                        .with_ansi(false)
                        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env());
                    let _guard = tracing_subscriber::util::SubscriberInitExt::set_default(subscriber);

                    let mut rng = <rand_chacha::ChaCha8Rng as rand_core::SeedableRng>::seed_from_u64(seed);
                    let network = crate::Network::new(std::sync::Arc::new(std::sync::Mutex::new(rng)), 4, seed);

                    // Call the original test function, wrapped in `catch_unwind` so we can detect the panic.
                    let result = futures::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(
                        zilliqa::time::with_fake_time(#inner_name(network))
                    )).await;

                    match result {
                        Ok(()) => {},
                        Err(e) => {
                            std::panic::resume_unwind(e);
                        }
                    }
                });
                id_to_seed.insert(handle.id(), seed);
            }
            if std::env::var_os("ZQ_TEST_SEED_SUMMARY").is_some() {
                let mut success = 0;
                let mut failure = 0;
                let mut failure_examples = Vec::new();
                while let Some(result) = set.join_next_with_id().await {
                    pb.inc(1);
                    match result {
                        Ok((_, ())) => { success += 1; },
                        Err(e) => {
                            failure += 1;
                            if failure_examples.len() < 16 {
                                let seed = id_to_seed.get(&e.id()).unwrap();
                                failure_examples.push(seed);
                            }
                        },
                    }
                }

                let total = success + failure;
                println!("Total seeds tested: {total}");
                println!("\x1b[0;32mSuccess: {success}\x1b[0m");
                let examples = if failure == 0 {
                    String::new()
                } else {
                    let more = if failure > 16 { "..." } else { "" };
                    let e = failure_examples.iter().map(|s| s.to_string()).collect::<Vec<_>>();
                    format!(" (seeds: {}{more})", e.join(", "))
                };
                println!("\x1b[0;31mFailure: {failure}{examples}\x1b[0m");
                println!("Pass rate: {}%", (success as f32 / total as f32) * 100.0);

                if failure != 0 {
                    panic!();
                }
            } else {
                // Restore the default panic hook, so the panic we actually care about gets printed.
                let _ = std::panic::take_hook();

                while let Some(result) = set.join_next_with_id().await {
                    pb.inc(1);
                    match result {
                        Ok((_, ())) => {},
                        Err(e) => {
                            let id = e.id();
                            if let Ok(p) = e.try_into_panic() {
                                // Silence the panic hook again. When we break from this loop and the `JoinSet` is
                                // dropped, the remaining tasks will be aborted. If any of them have also failed, we
                                // don't want their logs to be printed.
                                std::panic::set_hook(Box::new(|_| {}));

                                let seed = id_to_seed.get(&id).unwrap();
                                println!("Reproduce this test run by setting ZQ_TEST_RNG_SEED={seed}");
                                std::panic::resume_unwind(p);
                            } else {
                                panic!("task cancelled")
                            }
                        },
                    }
                }
            }

            let duration = start.elapsed();
            let mut time_allowed_ms = Duration::from_secs(10).as_millis() * (seeds_number as u128);

            if cfg!(debug_assertions) {
                time_allowed_ms *= 10;
            }

            if duration.as_millis() > time_allowed_ms {
                panic!("Test took too long: {}ms. Allowed: {}", duration.as_millis(), time_allowed_ms);
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
