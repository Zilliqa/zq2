use crate::collector;
use crate::utils;
use anyhow::Result;
use futures::future::JoinAll;
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub struct Runner {
    pub join_handles: Option<JoinAll<JoinHandle<()>>>,
}

impl collector::Runner for Runner {
    fn take_join_handles(&mut self) -> Result<Option<JoinAll<tokio::task::JoinHandle<()>>>> {
        Ok(self.join_handles.take())
    }
}

pub fn get_otter_directory(base_dir: &str) -> String {
    format!("{base_dir}/otterscan")
}

pub async fn exists(base_dir: &str) -> Result<bool> {
    utils::file_exists(&get_otter_directory(base_dir)).await
}

impl Runner {
    pub async fn spawn_otter(
        base_dir: &str,
        chain_url: &str,
        port: u16,
        channel: &mpsc::Sender<collector::Message>,
    ) -> Result<Runner> {
        let otter_dir = get_otter_directory(base_dir);
        let startup = format!("{base_dir}/zq2/z2/runtime/start_otterscan.sh");
        let mut cmd = Command::new(&startup);
        cmd.current_dir(otter_dir);
        cmd.env("VITE_ERIGON_URL", chain_url);
        cmd.env("PORT", &format!("{}", port));
        let join_handles = collector::spawn(
            &mut cmd,
            &startup,
            &collector::Legend::new(collector::Program::Otterscan, 0)?,
            channel.clone(),
        )
        .await?;
        Ok(Runner {
            join_handles: Some(join_handles),
        })
    }
}
