use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;
use syn::{ItemFn, parse::Parser};

// Much of this code is adapted from https://github.com/tokio-rs/tokio/blob/910a1e2fcf8ebafd41c2841144c3a1037af7dc40/tokio-macros/src/lib.rs.

pub(crate) fn test_macro(args: TokenStream, item: TokenStream) -> TokenStream {
    let mut restrict_concurrency = false;
    let mut do_checkpoints = false;
    let mut blocks_per_epoch = 10;
    // Code below reads 0 to be "do not deploy deposit_v3"
    let mut deposit_v3_upgrade_block_height = 0;

    let parsed_args =
        match syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
            .parse2(args.clone())
        {
            Ok(it) => it,
            Err(e) => return token_stream_with_error(args, e),
        };
    for arg in parsed_args {
        match arg {
            syn::Meta::Path(p) => {
                let Some(name) = p.get_ident() else {
                    return token_stream_with_error(
                        args,
                        syn::Error::new_spanned(p, "Attribute parameter must be ident"),
                    );
                };
                match name.to_string().as_str() {
                    "restrict_concurrency" => restrict_concurrency = true,
                    "do_checkpoints" => do_checkpoints = true,
                    _ => {
                        return token_stream_with_error(
                            args,
                            syn::Error::new_spanned(p, "Unknown attribute"),
                        );
                    }
                }
            }
            syn::Meta::NameValue(a) => {
                let Some(name) = a.path.get_ident() else {
                    return token_stream_with_error(
                        args,
                        syn::Error::new_spanned(a.path, "Attribute parameter must be ident"),
                    );
                };
                match name.to_string().as_str() {
                    "blocks_per_epoch" => {
                        let syn::Expr::Lit(syn::ExprLit {
                            lit: syn::Lit::Int(val),
                            ..
                        }) = a.value
                        else {
                            return token_stream_with_error(
                                args,
                                syn::Error::new_spanned(
                                    a.value,
                                    "Attribute parameter value must be an int",
                                ),
                            );
                        };
                        match val.base10_parse::<u64>() {
                            Ok(val) => blocks_per_epoch = val,
                            Err(e) => return token_stream_with_error(args, e),
                        };
                    }
                    "deposit_v3_upgrade_block_height" => {
                        let syn::Expr::Lit(syn::ExprLit {
                            lit: syn::Lit::Int(val),
                            ..
                        }) = a.value
                        else {
                            return token_stream_with_error(
                                args,
                                syn::Error::new_spanned(
                                    a.value,
                                    "Attribute parameter value must be an int",
                                ),
                            );
                        };
                        match val.base10_parse::<u64>() {
                            Ok(val) => deposit_v3_upgrade_block_height = val,
                            Err(e) => return token_stream_with_error(args, e),
                        };
                    }
                    _ => {
                        return token_stream_with_error(
                            args,
                            syn::Error::new_spanned(a, "Unknown attribute"),
                        );
                    }
                }
            }
            // Can match syn::Meta::Namevalue(a) here for args with params, e.g. to set node_count
            // in the future
            other => {
                return token_stream_with_error(
                    args,
                    syn::Error::new_spanned(other, "Unknown attribute"),
                );
            }
        }
    }

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
                rand::Rng::sample_iter(rand::thread_rng(), rand::distributions::Standard).take(samples).collect()
            };
            let style = indicatif::ProgressStyle::with_template("[{elapsed_precise}/{duration_precise}] {wide_bar:.cyan/blue} {pos:>}/{len}").unwrap().progress_chars("##-");
            let pb = indicatif::ProgressBar::new(seeds.len() as u64);
            pb.set_style(style);

            pb.tick();

            let mut sem = std::sync::Arc::new(tokio::sync::Semaphore::new(if #restrict_concurrency { 8 } else { 256 }));
            let mut set = tokio::task::JoinSet::new();

            // Keep a map of task IDs to test seeds, so we can print the seed of tasks that fail. We can't print the
            // seed as soon as the test has failed, because other cases will be running in parallel and we don't want
            // to interlace different cases' seeds and error messages. Instead, we wait until we resolve tasks from the
            // `JoinSet` (via `.join_next_with_id()`), where we can guarantee to only process one case at a time.
            let mut id_to_seed = std::collections::HashMap::new();

            // time this whole test to make sure its not taking too long
            use std::time::{Duration, Instant};
            let seeds_number = seeds.len();

            // Spawn a Scilla container for this group of tests.
            let scilla = zilliqa::test_util::ScillaServer::default();
            let addr = scilla.addr.clone();
            let temp_dir = scilla.temp_dir.clone();

            // Silence the default panic hook.
            std::panic::set_hook(Box::new(|_| {}));

            for seed in seeds {
                let sem = sem.clone();
                let addr = addr.clone();
                let temp_dir = temp_dir.clone();
                let handle = set.spawn(async move {
                    let _permit = sem.acquire_owned().await.unwrap();

                    // Set up a tracing subscriber, so we can see logs from failed test cases.
                    let subscriber = tracing_subscriber::fmt()
                        .with_ansi(false)
                        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env());

                    let _guard = tracing_subscriber::util::SubscriberInitExt::set_default(subscriber);

                    // Optionally print the seed in each tests logging so it can be filtered out later.
                    use tracing::Instrument;
                    let span = if std::env::var_os("ZQ_TEST_SEED_SPANS").is_some() {
                        tracing::span!(tracing::Level::INFO, "", seed)
                    } else {
                        tracing::span!(tracing::Level::INFO, "")
                    };

                    async move {
                        let mut rng = <rand_chacha::ChaCha8Rng as rand::SeedableRng>::seed_from_u64(seed);
                        let mut deposit_v3_upgrade_block_height_option = Option::None;
                        if #deposit_v3_upgrade_block_height != 0 {
                            deposit_v3_upgrade_block_height_option = Option::Some(#deposit_v3_upgrade_block_height);
                        };
                        let result = zilliqa::time::with_fake_time(async {
                            let network = crate::Network::new(
                                std::sync::Arc::new(std::sync::Mutex::new(rng)),
                                4,
                                seed,
                                addr,
                                "/scilla/0/_build/default/src/stdlib/".to_owned(),
                                #do_checkpoints,
                                #blocks_per_epoch,
                                deposit_v3_upgrade_block_height_option,
                                format!("{temp_dir}/scilla-sockets"),
                            );

                            // Call the original test function, wrapped in `catch_unwind` so we can detect the panic.
                            futures::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(#inner_name(network))).await
                        }).await;

                        match result {
                            Ok(()) => {},
                            Err(e) => {
                                std::panic::resume_unwind(e);
                            }
                        }
                    }.instrument(span).await
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
                                let seed = id_to_seed.get(&e.id()).expect("task ID not found");
                                failure_examples.push(seed);
                            }
                        },
                    }
                }

                failure_examples.sort();
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

                                let seed = id_to_seed.get(&id).expect("task ID not found");
                                println!("Reproduce this test run by setting ZQ_TEST_RNG_SEED={seed}");
                                std::panic::resume_unwind(p);
                            } else {
                                panic!("task cancelled")
                            }
                        },
                    }
                }
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
