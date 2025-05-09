use std::{collections::BTreeMap, io::Write, process::Command};

use anyhow::{Context, Ok, Result, anyhow};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::kms::KmsService;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Secret {
    #[serde(skip_serializing_if = "Option::is_none")]
    project_id: Option<String>,
    name: String,
    labels: BTreeMap<String, String>,
}

impl Secret {
    pub fn add_version(&self, value: Option<String>, encrypted: bool) -> Result<String> {
        let value = value.unwrap_or(Self::generate_random_secret());
        let project_id = &self.project_id.clone().context(format!(
            "Error retrieving the project ID of the secret {}",
            self.name
        ))?;

        // Create a new named temporary file with the secret
        let mut temp_file = NamedTempFile::new()?;

        if encrypted {
            // Check if we have the required labels to generate the KMS keyring and key
            let chain_name = self.labels.get("zq2-network").ok_or_else(|| {
                anyhow!("Cannot encrypt: missing 'zq2-network' label for KMS keyring")
            })?;
            let key_name = if let Some(node_name) = self.labels.get("node-name") {
                node_name.to_string()
            } else if let Some(role) = self.labels.get("role") {
                format!("{}-{}", chain_name, role)
            } else {
                return Err(anyhow!(
                    "Cannot encrypt: missing both 'node-name' and 'role' labels for KMS key"
                ));
            };

            // Encrypt using KmsService
            let ciphertext_base64 = KmsService::encrypt(
                project_id,
                &value,
                &format!("kms-{}", chain_name),
                &key_name,
            )?;

            // Write base64 encrypted content to file
            writeln!(temp_file, "{}", ciphertext_base64)?;
        } else {
            // Write plaintext directly if not encrypted
            writeln!(temp_file, "{}", value)?;
        }

        let output = Command::new("gcloud")
            .args([
                "--project",
                project_id,
                "secrets",
                "versions",
                "add",
                &self.name,
                &format!("--data-file={}", temp_file.path().to_str().unwrap()),
            ])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!(
                "Error adding a new version to the secret '{}' in the project {}",
                self.name,
                project_id
            ));
        }

        Ok(value)
    }

    pub fn create(project_id: &str, name: &str, labels: BTreeMap<String, String>) -> Result<Self> {
        let mut labels_to_add = Vec::<String>::new();

        for (k, v) in labels.clone() {
            labels_to_add.push(format!("{}={}", k, v));
        }

        let output = Command::new("gcloud")
            .args([
                "--project",
                project_id,
                "secrets",
                "create",
                name,
                "--replication-policy",
                "automatic",
                "--labels",
                &labels_to_add.join(","),
            ])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!(
                "Error creating the secret '{}' in the project {}",
                name,
                project_id
            ));
        }

        Ok(Self {
            project_id: Some(project_id.to_owned()),
            name: name.to_owned(),
            labels,
        })
    }

    fn generate_random_secret() -> String {
        let mut data = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut data);
        hex::encode(data)
    }

    pub fn delete(&self) -> Result<()> {
        let project_id = &self.project_id.clone().context(format!(
            "Error retrieving the project ID of the secret {}",
            self.name
        ))?;

        let output = Command::new("gcloud")
            .args([
                "--project",
                project_id,
                "secrets",
                "delete",
                &self.name,
                "--quiet",
            ])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("listing secrets failed"));
        }

        Ok(())
    }

    pub fn grant_service_account(
        secret_name: &str,
        project_id: &str,
        service_account_name: &str,
    ) -> Result<String> {
        let output = Command::new("gcloud")
            .args([
                "secrets",
                "add-iam-policy-binding",
                secret_name,
                "--project",
                project_id,
                "--member",
                &format!("serviceAccount:{}", service_account_name),
                "--role",
                "roles/secretmanager.secretAccessor",
            ])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!(
                "Error granting the service account '{}' access to the secret '{}' in the project {}: {}",
                service_account_name,
                secret_name,
                project_id,
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(std::str::from_utf8(&output.stdout)?.trim().to_owned())
    }

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

    pub fn get_secrets_by_role(
        chain_name: &str,
        project_id: &str,
        role_name: &str,
    ) -> Result<Vec<Secret>> {
        Self::get_secrets(
            project_id,
            format!(
                "labels.zq2-network={} AND labels.role={}",
                chain_name, role_name
            )
            .as_str(),
        )
    }
}
