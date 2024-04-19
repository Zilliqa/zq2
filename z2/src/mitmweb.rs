use crate::collector;
use anyhow::Result;
use futures::future::JoinAll;
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Run the eth spout from a sibling directory
pub struct Runner {
    pub join_handlers: Option<JoinAll<JoinHandle<()>>>,
}

impl collector::Runner for Runner {
    fn take_join_handles(&mut self) -> Result<Option<JoinAll<tokio::task::JoinHandle<()>>>> {
        Ok(self.join_handlers.take())
    }
}

impl Runner {
    pub async fn spawn_mitmproxy(
        _base_dir: &str,
        index: usize,
        from_port: u16,
        to_port: u16,
        mgmt_port: u16,
        channel: &mpsc::Sender<collector::Message>,
    ) -> Result<Self> {
        println!("Starting mitmproxy FROM {from_port} (send requests here <---) TO {to_port} (where they go) MGMT {mgmt_port}");
        let mut cmd = Command::new("mitmweb");
        cmd.arg("--mode");
        cmd.arg(&format!("reverse:http://localhost:{}", to_port));
        cmd.arg("--no-web-open-browser");
        cmd.arg("--listen-port");
        cmd.arg(format!("{}", from_port));
        cmd.arg("--web-port");
        cmd.arg(format!("{}", mgmt_port));
        let join_handlers = collector::spawn(
            &mut cmd,
            "mitmweb",
            &collector::Legend::new(collector::Program::Mitmweb, index)?,
            channel.clone(),
        )
        .await?;
        Ok(Runner {
            join_handlers: Some(join_handlers),
        })
    }
}
