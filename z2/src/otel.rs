use anyhow::{anyhow, Context as _, Result};
use tokio::{fs, process::Command};

use crate::components;

/// Tracks otel - this is just a container we run with docker-compose up (because that's the only practical way)
/// so that you can see API traces.
pub struct Otel {
    pub config_dir: String,
}

impl Otel {
    pub fn new(config_dir: &str) -> Result<Self> {
        Ok(Self {
            config_dir: config_dir.to_string(),
        })
    }

    pub async fn requirements() -> Result<components::Requirements> {
        Ok(components::Requirements::default())
    }

    pub async fn write_files(&self) -> Result<()> {
        // Just writes a couple of files.
        let docker_compose = include_str!("../resources/otel-compose.yaml");
        fs::write(
            format!("{0}/otel-compose.yaml", &self.config_dir),
            docker_compose,
        )
        .await
        .context(format!(
            "Cannot write {0}/otel-compose.yaml",
            &self.config_dir
        ))?;
        let otel_config = include_str!("../resources/otel-collector-config.yaml");
        fs::write(
            format!("{0}/otel-config.yaml", &self.config_dir),
            otel_config,
        )
        .await
        .context(format!(
            "Cannot write {0}/otel-config.yaml",
            &self.config_dir
        ))?;
        let mimir_config = include_str!("../resources/mimir-config.yaml");
        fs::write(
            format!("{0}/mimir-config.yaml", &self.config_dir),
            mimir_config,
        )
        .await
        .context(format!(
            "Cannot write {0}/minir-config.yaml",
            &self.config_dir
        ))?;
        Ok(())
    }

    pub async fn ensure_otel(&self) -> Result<()> {
        let mut cmd = Command::new("docker-compose");
        cmd.arg("-f");
        cmd.arg("otel-compose.yaml");
        cmd.arg("up");
        cmd.arg("-d"); // @todo may want to reconsider thus, but easy for now.
        cmd.current_dir(&self.config_dir);
        let result = cmd.spawn()?.wait().await?;
        if result.success() {
            println!("OTEL metrics should be available at port 9009 (mimir), 9010 (grafana)");
        } else {
            return Err(anyhow!("Could not bring otel up"));
        }
        Ok(())
    }
}
