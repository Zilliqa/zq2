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

impl Runner {
    pub fn get_scilla_stdlib_dir(base_dir: &str) -> String {
        format!("{base_dir}/scilla/_build/default/src/stdlib/")
    }

    pub async fn requirements() -> Result<components::Requirements> {
        Ok(components::Requirements {
            software: vec![],
            repos: vec!["scilla:main-zq2".to_string()],
        })
    }

    pub async fn spawn_scilla(
        base_dir: &str,
        index: usize,
        port: u16,
        channel: &mpsc::Sender<collector::Message>,
    ) -> Result<Runner> {
        let exe_name = format!("{base_dir}/scilla/bin/scilla-server-http");
        let mut cmd = Command::new(&exe_name);
        let port = format!("{}", port);
        cmd.args(vec!["-p", &port]);
        let join_handles = collector::spawn(
            &mut cmd,
            &exe_name,
            &collector::Legend::new(Component::Scilla, index)?,
            channel.clone(),
        )
        .await?;
        Ok(Runner {
            index,
            join_handles: Some(join_handles),
        })
    }
}
