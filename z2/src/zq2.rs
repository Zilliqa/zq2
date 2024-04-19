use crate::collector;
use anyhow::Result;
use futures::future::JoinAll;
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub struct Runner {
    pub index: usize,
    pub join_handles: Option<JoinAll<JoinHandle<()>>>,
}

impl collector::Runner for Runner {
    fn take_join_handles(&mut self) -> Result<Option<JoinAll<tokio::task::JoinHandle<()>>>> {
        Ok(self.join_handles.take())
    }
}

impl Runner {
    pub async fn spawn(
        index: usize,
        key: &str,
        config_file: &str,
        debug_spec: &Option<String>,
        channel: &mpsc::Sender<collector::Message>,
    ) -> Result<Runner> {
        let mut cmd = Command::new("target/debug/zilliqa");
        cmd.arg(key);
        cmd.arg("--config-file");
        cmd.arg(config_file);
        if let Some(val) = debug_spec {
            cmd.env("RUST_LOG", val);
        }
        let join_handles = collector::spawn(
            &mut cmd,
            "zq2",
            &collector::Legend::new(collector::Program::Zq2, index)?,
            channel.clone(),
        )
        .await?;
        Ok(Runner {
            index,
            join_handles: Some(join_handles),
        })
    }
}
