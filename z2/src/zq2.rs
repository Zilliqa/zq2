use anyhow::Result;
use futures::future::JoinAll;
use tokio::{process::Command, sync::mpsc, task::JoinHandle};

use crate::{
    collector,
    components::{self, Component},
};

pub struct Runner {
    pub index: usize,
    pub join_handles: Option<JoinAll<JoinHandle<()>>>,
}

impl collector::Runner for Runner {
    fn take_join_handles(&mut self) -> Result<Option<JoinAll<tokio::task::JoinHandle<()>>>> {
        Ok(self.join_handles.take())
    }
}

pub fn get_zq2_dir(base_dir: &str) -> String {
    format!("{base_dir}/zq2")
}

impl Runner {
    pub async fn requirements() -> Result<components::Requirements> {
        Ok(components::Requirements {
            software: vec![],
            repos: vec!["zq2".to_string()],
        })
    }

    pub async fn spawn(
        base_dir: &str,
        index: usize,
        key: &str,
        config_file: &str,
        debug_spec: &Option<String>,
        channel: &mpsc::Sender<collector::Message>,
    ) -> Result<Runner> {
        let exe_name = format!("{base_dir}/zq2/target/debug/zilliqa");
        let mut cmd = Command::new(&exe_name);
        cmd.arg(key);
        cmd.arg("--config-file");
        cmd.arg(config_file);
        if let Some(val) = debug_spec {
            cmd.env("RUST_LOG", val);
        }
        let join_handles = collector::spawn(
            &mut cmd,
            &exe_name,
            &collector::Legend::new(Component::ZQ2, index)?,
            channel.clone(),
        )
        .await?;
        Ok(Runner {
            index,
            join_handles: Some(join_handles),
        })
    }
}
