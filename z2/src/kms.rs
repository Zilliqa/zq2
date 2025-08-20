use std::{io::Write, process::Command};

use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose};
use tempfile::NamedTempFile;

use crate::chain::node::Machine;

pub const NON_PROD_PREFIX: &str = "prj-d";
pub const PROD_PREFIX: &str = "prj-p";
pub const NON_PROD_KMS_PROJECT: &str = "prj-d-kms-tw1xyxbh";
pub const PROD_KMS_PROJECT: &str = "prj-p-kms-2vduab0g";

pub struct KmsService;

impl KmsService {
    pub fn get_kms_project_id(project_id: &str) -> &str {
        if project_id.starts_with(NON_PROD_PREFIX) {
            NON_PROD_KMS_PROJECT
        } else if project_id.starts_with(PROD_PREFIX) {
            PROD_KMS_PROJECT
        } else {
            project_id
        }
    }

    pub fn decrypt(
        project_id: &str,
        base64_ciphertext: &str,
        kms_keyring: &str,
        kms_key: &str,
        machine: Option<Machine>,
    ) -> Result<String> {
        // Determine KMS project ID based on prefix
        let kms_project_id = Self::get_kms_project_id(project_id);

        // Execute command in a machine if provided, otherwise run locally
        let plaintext = if let Some(machine) = machine {
            let cmd = format!(
                "echo '{base64_ciphertext}' | base64 -d | gcloud kms decrypt --project {kms_project_id} --location global --keyring {kms_keyring} --key {kms_key} --ciphertext-file - --plaintext-file -"
            );
            let output = machine.run(&cmd, false)?;
            if !output.status.success() {
                return Err(anyhow!(
                    "KMS decryption failed in {}: {}",
                    machine.name,
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            std::str::from_utf8(&output.stdout)?.trim().to_owned()
        } else {
            let mut ciphertext_file = NamedTempFile::new()?;
            let plaintext_file = NamedTempFile::new()?;
            let ciphertext_bytes = general_purpose::STANDARD.decode(base64_ciphertext)?;
            ciphertext_file.write_all(&ciphertext_bytes)?;
            let output = Command::new("gcloud")
                .args([
                    "kms",
                    "decrypt",
                    "--ciphertext-file",
                    ciphertext_file.path().to_str().unwrap(),
                    "--plaintext-file",
                    plaintext_file.path().to_str().unwrap(),
                    "--keyring",
                    kms_keyring,
                    "--key",
                    kms_key,
                    "--location",
                    "global",
                    "--project",
                    kms_project_id,
                ])
                .output()?;
            if !output.status.success() {
                return Err(anyhow!(
                    "KMS decryption failed in local: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            std::fs::read_to_string(plaintext_file.path())?
                .trim()
                .to_owned()
        };

        Ok(plaintext)
    }
}
