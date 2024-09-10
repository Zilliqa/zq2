use anyhow::{Context as _, Result};
use futures::future::JoinAll;
use tokio::{fs, process::Command, sync::mpsc, task::JoinHandle};

use crate::{
    collector,
    components::{self, Component},
};

/// Tracks otel - this is just a container we run with docker-compose up (because that's the only practical way)
/// so that you can see API traces.
pub struct Runner {
    pub config_dir: String,
    pub join_handles: Option<JoinAll<JoinHandle<()>>>,
}

impl collector::Runner for Runner {
    fn take_join_handles(&mut self) -> Result<Option<JoinAll<tokio::task::JoinHandle<()>>>> {
        Ok(self.join_handles.take())
    }
}

impl Runner {
    pub async fn spawn_otel(
        _base_dir: &str,
        config_dir: &str,
        channel: &mpsc::Sender<collector::Message>,
    ) -> Result<Runner> {
        Runner::write_config_files(config_dir).await?;
        let join_handles = Runner::start_otel(config_dir, channel).await?;
        Ok(Self {
            config_dir: config_dir.to_string(),
            join_handles: Some(join_handles),
        })
    }

    pub async fn requirements() -> Result<components::Requirements> {
        Ok(components::Requirements::default())
    }

    pub async fn write_config_files(config_dir: &str) -> Result<()> {
        // Just writes a couple of files.
        let docker_compose = include_str!("../resources/otel-compose.yaml");
        fs::write(
            format!("{0}/otel-compose.yaml", &config_dir),
            docker_compose,
        )
        .await
        .context(format!("Cannot write {0}/otel-compose.yaml", &config_dir))?;
        let otel_config = include_str!("../resources/otel-collector-config.yaml");
        fs::write(format!("{0}/otel-config.yaml", &config_dir), otel_config)
            .await
            .context(format!("Cannot write {0}/otel-config.yaml", &config_dir))?;
        let mimir_config = include_str!("../resources/mimir-config.yaml");
        fs::write(format!("{0}/mimir-config.yaml", &config_dir), mimir_config)
            .await
            .context(format!("Cannot write {0}/minir-config.yaml", &config_dir))?;
        Ok(())
    }

    pub async fn start_otel(
        config_dir: &str,
        channel: &mpsc::Sender<collector::Message>,
    ) -> Result<JoinAll<tokio::task::JoinHandle<()>>> {
        let mut cmd = Command::new("docker");
        cmd.args(vec!["compose", "-f", "otel-compose.yaml", "up"]);
        cmd.current_dir(config_dir);
        println!("> {cmd:?}");
        collector::spawn(
            &mut cmd,
            "docker",
            &collector::Legend::new(Component::Otel, 0)?,
            channel.clone(),
        )
        .await
    }
}
