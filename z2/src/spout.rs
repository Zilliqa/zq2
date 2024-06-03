use anyhow::Result;
use futures::future::JoinAll;
use tokio::{process::Command, sync::mpsc, task::JoinHandle};

use crate::{
    collector,
    components::{self, Component},
    utils,
};

/// Run the eth spout from a sibling directory
pub struct Runner {
    pub join_handlers: Option<JoinAll<JoinHandle<()>>>,
}

impl collector::Runner for Runner {
    fn take_join_handles(&mut self) -> Result<Option<JoinAll<tokio::task::JoinHandle<()>>>> {
        Ok(self.join_handlers.take())
    }
}

pub fn get_spout_directory(base_dir: &str) -> String {
    format!("{base_dir}/zilliqa-developer/products/eth-spout")
}

pub async fn exists(base_dir: &str) -> Result<bool> {
    utils::file_exists(&get_spout_directory(base_dir)).await
}

impl Runner {
    pub async fn requirements() -> Result<components::Requirements> {
        Ok(components::Requirements {
            software: vec![],
            repos: vec!["zilliqa-developer".to_string()],
        })
    }

    pub async fn spawn_spout(
        base_dir: &str,
        chain_url: &str,
        explorer_url: &str,
        spout_private_key: &str,
        port: u16,
        channel: &mpsc::Sender<collector::Message>,
    ) -> Result<Runner> {
        println!("Spawning eth spout on port {port} .. ");
        let dir = get_spout_directory(base_dir);
        let mut cmd = Command::new("cargo");
        cmd.arg("run");
        cmd.current_dir(&dir);
        cmd.env("HTTP_PORT", format!("{port}"));
        cmd.env("RPC_URL", chain_url);
        cmd.env("NATIVE_TOKEN_SYMBOL", "ZIL");
        cmd.env("PRIVATE_KEY", spout_private_key);
        cmd.env("ETH_AMOUNT", "1000");
        cmd.env("EXPLORER_URL", explorer_url);
        cmd.env("MINIMUM_SECONDS_BETWEEN_REQUESTS", "0");
        cmd.env("BECH32_HRP", "zil");
        let join_handlers = collector::spawn(
            &mut cmd,
            &dir,
            &collector::Legend::new(Component::Spout, 0)?,
            channel.clone(),
        )
        .await?;
        Ok(Runner {
            join_handlers: Some(join_handlers),
        })
    }
}
