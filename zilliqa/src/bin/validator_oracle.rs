use alloy_provider::{Provider, ProviderBuilder, WsConnect};
use alloy_rpc_types::{BlockNumberOrTag, Filter};
use anyhow::Result;
use clap::Parser;
use futures_util::stream::StreamExt;
use std::path::PathBuf;
use zilliqa::{crypto::SecretKey, state::contract_addr, uccb::cfg::ZQ2Config};

#[derive(Parser, Debug)]
struct Args {
    #[arg(value_parser = SecretKey::from_hex)]
    secret_key: SecretKey,
    #[clap(long, short, default_value = "config.toml")]
    config_file: PathBuf,
}

impl zilliqa::uccb::Args for Args {
    fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    fn config_file(&self) -> &PathBuf {
        &self.config_file
    }
}

async fn listen_to_staker_updates(zq2_config: &ZQ2Config) -> Result<()> {
    let filter = Filter::new()
        .address(contract_addr::DEPOSIT)
        // Must be the same signature as the event in deposit.sol
        .event("StakerAdded(bytes)")
        .from_block(BlockNumberOrTag::Latest);

    let ws = WsConnect::new(&zq2_config.rpc_url);
    let provider = ProviderBuilder::new().on_ws(ws).await?;

    let subscription = provider.subscribe_logs(&filter).await?;
    let mut stream = subscription.into_stream();
    while let Some(log) = stream.next().await {
        // TODO: update validator manager(s) only if leader
        println!("Subscription log: {log:?}");
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config = zilliqa::uccb::read_config(&args)?;
    let zq2_config = &config.zq2;

    listen_to_staker_updates(&config.zq2).await
}
