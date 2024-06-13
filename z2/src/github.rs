use anyhow::{anyhow, Result};
use octocrab::{
    models::repos::{Release, RepoCommit},
    Octocrab,
};

static ORGANIZATION: &str = "Zilliqa";

async fn get_release(organization: &str, repository: &str) -> Result<Option<String>> {
    let client = octocrab::initialise(Octocrab::builder().build()?);

    let page = client
        .repos(organization, repository)
        .releases()
        .list()
        // Optional Parameters
        .per_page(100)
        .page(1u32)
        // Send the request
        .send()
        .await?;

    let rel: Vec<Release> = page.items.to_vec();
    if let Some(r) = rel.first() {
        Ok(Some(r.tag_name.clone()))
    } else {
        Ok(None)
    }
}

async fn get_commit(organization: &str, repository: &str) -> Result<Option<String>> {
    let client = octocrab::initialise(Octocrab::builder().build()?);

    let commit = client
        .repos(organization, repository)
        .list_commits()
        // Optional Parameters
        .per_page(100)
        .page(1u32)
        // Send the request
        .send()
        .await?;

    let rel: Vec<RepoCommit> = commit.items.to_vec();
    if let Some(r) = rel.first() {
        Ok(Some(r.sha.chars().take(8).collect()))
    } else {
        Ok(None)
    }
}

pub async fn get_release_or_commit(repository: &str) -> Result<String> {
    if let Some(r) = get_release(ORGANIZATION, repository).await? {
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
