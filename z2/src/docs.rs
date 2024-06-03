use anyhow::Result;
use futures::future::JoinAll;
use tokio::{process::Command, sync::mpsc, task::JoinHandle};

use crate::{
    collector,
    components::{self, Component},
    zq2,
};

pub struct Runner {
    pub join_handlers: Option<JoinAll<JoinHandle<()>>>,
}

impl collector::Runner for Runner {
    fn take_join_handles(&mut self) -> Result<Option<JoinAll<tokio::task::JoinHandle<()>>>> {
        Ok(self.join_handlers.take())
    }
}

pub fn get_docs_dir(base_dir: &str) -> String {
    format!("{base_dir}/dev-portal")
}

impl Runner {
    pub async fn requirements() -> Result<components::Requirements> {
        Ok(components::Requirements {
            software: vec![],
            repos: vec!["dev-portal".to_string()],
        })
    }

    pub async fn spawn_docs(
        base_dir: &str,
        listen_hostport: &str,
        channel: &mpsc::Sender<collector::Message>,
    ) -> Result<Runner> {
        println!("Spawning docs on {listen_hostport} .. ");
        let dir = get_docs_dir(base_dir);
        let zq2_dir = zq2::get_zq2_dir(base_dir);
        let mut cmd = Command::new("make");
        cmd.arg("dev2");
        cmd.current_dir(&dir);
        cmd.env("NO_CHECKOUT", "1");
        cmd.env("USE_ZQ2_FROM", &zq2_dir);
        cmd.env("SERVEOPTS", &format!("-a {listen_hostport}"));
        let join_handlers = collector::spawn(
            &mut cmd,
            &dir,
            &collector::Legend::new(Component::Docs, 0)?,
            channel.clone(),
        )
        .await?;
        Ok(Runner {
            join_handlers: Some(join_handlers),
        })
    }
}
