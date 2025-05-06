use std::{collections::BTreeMap, io::Write, process::Command};

use anyhow::{Context, Ok, Result, anyhow};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use base64::{engine::general_purpose, Engine as _};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Secret {
    #[serde(skip_serializing_if = "Option::is_none")]
    project_id: Option<String>,
    name: String,
    labels: BTreeMap<String, String>,
}

impl Secret {
    pub fn add_version(&self, value: Option<String>, kms_keyring: Option<String>, kms_key: Option<String>) -> Result<String> {
        let value = value.unwrap_or(Self::generate_random_secret());
        let project_id = &self.project_id.clone().context(format!(
            "Error retrieving the project ID of the secret {}",
            self.name
        ))?;

        // Create a new named temporary file with the secret
        let mut temp_file = NamedTempFile::new()?;

        // Encrypt if both KMS key and keyring are provided
        if let (Some(kms_keyring), Some(kms_key)) = (kms_keyring, kms_key) {
            let mut plaintext_file = NamedTempFile::new()?;
            writeln!(plaintext_file, "{}", value)?;

            // Determine KMS project ID based on prefix
            let kms_project_id = if project_id.starts_with("prj-d") {
                "prj-d-kms-tw1xyxbh"
            } else if project_id.starts_with("prj-p") {
                "prj-p-kms-2vduab0g"
            } else {
                project_id
            };

            let ciphertext_tempfile = NamedTempFile::new()?;
            let status = Command::new("gcloud")
                .args([
                    "kms", "encrypt",
                    "--plaintext-file", plaintext_file.path().to_str().unwrap(),
                    "--ciphertext-file", ciphertext_tempfile.path().to_str().unwrap(),
                    "--keyring", &kms_keyring,
                    "--key", &kms_key,
                    "--location", "global",
                    "--project", kms_project_id,
                ])
                .status()?;
            if !status.success() {
                return Err(anyhow::anyhow!("KMS encryption failed"));
            }

            // Read binary ciphertext and encode as base64
            let ciphertext_bytes = std::fs::read(ciphertext_tempfile.path())?;
            let ciphertext_base64 = general_purpose::STANDARD.encode(&ciphertext_bytes);
            
            // Write base64 to final output file
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
