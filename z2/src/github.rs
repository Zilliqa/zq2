use anyhow::{Result, anyhow};
use reqwest::{Client, StatusCode};
use serde::Deserialize;

static ORGANIZATION: &str = "Zilliqa";

async fn get_release(
    organization: &str,
    repository: &str,
    pre_release: bool,
) -> Result<Option<String>> {
    let response = Client::builder()
        .user_agent("zilliqa")
        .build()?
        .get(format!(
            "https://api.github.com/repos/{organization}/{repository}/releases"
        ))
        .send()
        .await?;

    if response.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }

    #[derive(Deserialize)]
    struct ReleaseItem {
        tag_name: String,
        prerelease: bool,
    }
    let releases: Vec<ReleaseItem> = response.error_for_status()?.json().await?;

    let tag = releases
        .into_iter()
        .find(|r| r.prerelease == pre_release)
        .map(|r| r.tag_name);
    Ok(tag)
}

async fn get_commit(organization: &str, repository: &str) -> Result<Option<String>> {
    let response = Client::builder()
        .user_agent("zilliqa")
        .build()?
        .get(format!(
            "https://api.github.com/repos/{organization}/{repository}/commits"
        ))
        .send()
        .await?;

    if response.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }

    #[derive(Deserialize)]
    struct Commit {
        sha: String,
    }
    let response: Vec<Commit> = response.error_for_status()?.json().await?;

    Ok(response.first().map(|c| c.sha.chars().take(8).collect()))
}

pub async fn get_release_or_commit(repository: &str, pre_release: bool) -> Result<String> {
    if let Some(r) = get_release(ORGANIZATION, repository, pre_release).await? {
        return Ok(r);
    };

    if let Some(r) = get_commit(ORGANIZATION, repository).await? {
        return Ok(r);
    }

    Err(anyhow!(
        "No release or version found {}",
        repository.to_string()
    ))
}
