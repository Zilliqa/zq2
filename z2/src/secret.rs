use std::{collections::BTreeMap, process::Command};

use anyhow::{Context, Ok, Result, anyhow};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Secret {
    #[serde(skip_serializing_if = "Option::is_none")]
    project_id: Option<String>,
    name: String,
    labels: BTreeMap<String, String>,
}

impl Secret {
    pub fn value(&self) -> Result<String> {
        let project_id = &self.project_id.clone().context(format!(
            "Error retrieving the project ID of the secret {}",
            self.name
        ))?;

        let output = Command::new("gcloud")
            .args([
                "--project",
                project_id,
                "secrets",
                "versions",
                "access",
                "latest",
                "--secret",
                &self.name,
            ])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!(
                "Error retrieving the latest version of the secret '{}' in the project {}",
                self.name,
                project_id
            ));
        }

        Ok(std::str::from_utf8(&output.stdout)?.trim().to_string())
    }

    pub fn get_secrets(project_id: &str, filter: &str) -> Result<Vec<Secret>> {
        let output = Command::new("gcloud")
            .args([
                "secrets",
                "list",
                "--project",
                project_id,
                "--format=json",
                "--filter",
                filter,
            ])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("listing secrets failed"));
        }

        // Parse the JSON output
        let mut secrets: Vec<Secret> = serde_json::from_slice(&output.stdout)?;

        // Add project_id field to each item and normalize the secret name
        for secret in &mut secrets {
            secret.project_id = Some(project_id.to_owned());
            if let Some(last_slash_pos) = secret.name.rfind('/') {
                secret.name = secret.name[last_slash_pos + 1..].to_string();
            }
        }

        Ok(secrets)
    }
}
