use std::{io::Write, process::Command};

use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose};
use tempfile::NamedTempFile;

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

    pub fn encrypt(
        project_id: &str,
        plaintext: &str,
        kms_keyring: &str,
        kms_key: &str,
    ) -> Result<String> {
        // Create a temporary file for the plaintext
        let mut plaintext_file = NamedTempFile::new()?;
        writeln!(plaintext_file, "{}", plaintext)?;

        // Determine KMS project ID based on prefix
        let kms_project_id = Self::get_kms_project_id(project_id);

        // Create a temporary file for the ciphertext
        let ciphertext_tempfile = NamedTempFile::new()?;

        // Run the KMS encryption command
        let status = Command::new("gcloud")
            .args([
                "kms",
                "encrypt",
                "--plaintext-file",
                plaintext_file.path().to_str().unwrap(),
                "--ciphertext-file",
                ciphertext_tempfile.path().to_str().unwrap(),
                "--keyring",
                kms_keyring,
                "--key",
                kms_key,
                "--location",
                "global",
                "--project",
                kms_project_id,
            ])
            .status()?;

        if !status.success() {
            return Err(anyhow!("KMS encryption failed"));
        }

        // Read binary ciphertext and encode as base64
        let ciphertext_bytes = std::fs::read(ciphertext_tempfile.path())?;
        let ciphertext_base64 = general_purpose::STANDARD.encode(&ciphertext_bytes);

        Ok(ciphertext_base64)
    }

    pub fn decrypt(
        project_id: &str,
        base64_ciphertext: &str,
        kms_keyring: &str,
        kms_key: &str,
    ) -> Result<String> {
        // Determine KMS project ID based on prefix
        let kms_project_id = Self::get_kms_project_id(project_id);

        // Create temporary files for the encrypted data
        let mut ciphertext_file = NamedTempFile::new()?;
        let plaintext_file = NamedTempFile::new()?;

        // Decode base64 to binary
        let ciphertext_bytes = general_purpose::STANDARD.decode(base64_ciphertext)?;

        // Write decoded binary data to the file
        ciphertext_file.write_all(&ciphertext_bytes)?;

        // Run the KMS decryption command
        let status = Command::new("gcloud")
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
            .status()?;

        if !status.success() {
            return Err(anyhow!("KMS decryption failed"));
        }

        // Read the plaintext result
        let plaintext = std::fs::read_to_string(plaintext_file.path())?;

        Ok(plaintext.trim().to_owned())
    }
}
