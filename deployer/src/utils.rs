use anyhow::{anyhow, Result};
use base64::prelude::*;
use home;
use log::error;
use std::env;
use std::path::Path;
use std::path::PathBuf;

/// Get a string from a u8
pub fn string_or_empty_from_u8(in_val: &[u8]) -> String {
    let result: &str = if let Ok(val) = std::str::from_utf8(in_val) {
        val
    } else {
        "<not_representable>"
    };
    result.to_string()
}

/// Get string from path
pub fn string_from_path(in_path: &Path) -> Result<String> {
    Ok(in_path
        .as_os_str()
        .to_str()
        .ok_or(anyhow!("Cannot convert path to string"))?
        .to_string())
}

/// Get an environment variable and returns None whether not set
pub fn get_env_variable(var_name: &str) -> Option<String> {
    match env::var(var_name) {
        Ok(value) => Some(value),
        Err(_) => None,
    }
}

/// Remove a suffix from a string, or return the original
pub fn remove_suffix<'a>(in_string: &'a str, suffix: &str) -> &'a str {
    if let Some(result) = in_string.strip_suffix(suffix) {
        result
    } else {
        in_string
    }
}

pub fn relative_home_path_str(val: &str) -> Result<String> {
    let path = relative_home_path(val)?;
    string_from_path(&path)
}

pub fn relative_home_path(val: &str) -> Result<PathBuf> {
    let mut home_path = home::home_dir().ok_or(anyhow!("Can't get your home directory"))?;
    home_path.push(val);
    Ok(home_path)
}

/// Log an error and re-propagate
pub fn with_error_logged<T>(result: Result<T>) -> Result<T> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => {
            let error_message = &error;
            error!("{error_message}");
            Err(error)
        }
    }
}

pub fn decode_base64(value: &str) -> Option<String> {
    BASE64_STANDARD
        .decode(value)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

pub fn encode_base64(value: &str) -> String {
    BASE64_STANDARD.encode(value)
}
