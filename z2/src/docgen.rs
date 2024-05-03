// Code to generate documentation from .tera.md files.
#![allow(unused_imports)]

use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};
use tokio::fs;

pub struct Docs {
    // Where do we render to?
    pub target_dir: String,
    // Where do we render from?
    pub source_dir: String,
}

impl Docs {
    pub fn new(source_dir: &str, target_dir: &str) -> Result<Self> {
        Ok(Self {
            target_dir: target_dir.to_string(),
            source_dir: source_dir.to_string(),
        })
    }

    pub async fn generate_all(&self) -> Result<()> {
        self.generate_dir(&PathBuf::from(&self.source_dir)).await?;
        Ok(())
    }

    // Recursively generate documentation.
    // Because of the weird rules around recursive async, this is done iteratively.
    pub async fn generate_dir(&self, dir: &Path) -> Result<()> {
        let mut stack = Vec::new();
        stack.push(PathBuf::from(dir));
        while let Some(ref path) = stack.pop() {
            let md = fs::metadata(path).await?;
            if md.is_dir() {
                let mut entries = fs::read_dir(path).await?;
                loop {
                    let Some(entry) = entries.next_entry().await? else {
                        break;
                    };
                    stack.push(entry.path())
                }
            } else if md.is_file() {
                println!("File: {:?}", path);
            }
        }
        Ok(())
    }
}
