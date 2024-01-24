use std::{num::NonZeroU64, fs, path::PathBuf};

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use google_compute1::{
    api::{AttachedDisk, AttachedDiskInitializeParams, Instance, NetworkInterface},
    hyper, hyper_rustls, oauth2, Compute,
};
use google_storage1::{Storage, api::Bucket};
use primitive_types::H160;
use serde::{Deserialize, Serialize};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    New {
        name: String,
        gcp_project: String,
        gcp_zone: String,
    },
    Deploy {
        config_file: PathBuf,
    },
}

macro_rules! paginated {
    ($request:expr) => {{
        let mut page_token: Option<String> = None;
        let mut result = vec![];
        loop {
            let mut request = $request;
            if let Some(page_token) = page_token {
                request = request.page_token(&page_token);
            }
            let (_, response) = request.doit().await?;
            if let Some(items) = response.items {
                result.extend(items);
            }
            page_token = response.next_page_token;
            if page_token.is_none() {
                break;
            }
        }

        result
    }};
}

#[derive(Deserialize, Serialize)]
struct NetworkConfig {
    name: String,
    nodes: NonZeroU64,
    secret_keys: Vec<String>,
    genesis_accounts: Vec<(H160, String)>,
    gcp_project: String,
    gcp_zone: String,
}

impl NetworkConfig {
    fn new(name: String, gcp_project: String, gcp_zone: String) -> Self {
        Self {
            name,
            nodes: NonZeroU64::new(1).unwrap(),
            secret_keys: vec![], // TODO
            genesis_accounts: vec![], // TODO
            gcp_project,
            gcp_zone,
        }
    }

    fn region(&self) -> &str {
        let (region, _) = self.gcp_zone.rsplit_once('-').unwrap();
        region
    }
}

type Client = hyper::Client<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>;
type Auth = oauth2::authenticator::Authenticator<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>;

fn is_not_found(error: &google_storage1::Error) -> Result<bool> {
    if let google_storage1::Error::BadRequest(e) = error {
        let code = e.get("error").ok_or_else(|| anyhow!("no error"))?.get("code").ok_or_else(|| anyhow!("no code"))?.as_u64().ok_or_else(|| anyhow!("code is not a number"))?;
        Ok(code == 404)
    } else {
        Ok(false)
    }
}

async fn create_bin_bucket(client: &Client, auth: &Auth, config: &NetworkConfig) -> Result<String> {
    let storage = Storage::new(client.clone(), auth.clone());

    let name = format!("{}-{}-binaries", config.gcp_project, config.name);

    match storage.buckets().get(&name).doit().await {
        Ok((_, bucket)) => {
            Ok(bucket.name.ok_or_else(|| anyhow!("no name"))?)
        },
        Err(e) if is_not_found(&e)? => {
            let bucket = Bucket {
                name: Some(name),
                location: Some(config.region().to_owned()),
                ..Default::default()
            };
            let (_, bucket) = storage.buckets().insert(bucket, &config.gcp_project).doit().await?;
            Ok(bucket.name.ok_or_else(|| anyhow!("no name"))?)
        },
        Err(e) => {
            Err(e.into())
        }
    }
}

async fn create_network(client: &Client, auth: &Auth, config: &NetworkConfig) -> Result<()> {
    let compute = Compute::new(client.clone(), auth.clone());

    compute.networks().insert(request, project)

    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let secret = oauth2::read_authorized_user_secret(
        "/home/james/.config/gcloud/application_default_credentials.json",
    )
    .await?;

    let auth = oauth2::AuthorizedUserAuthenticator::builder(secret)
        .build()
        .await?;

    let client = hyper::Client::builder().build(
        hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .https_or_http()
            .enable_http1()
            .build(),
    );

    let compute = Compute::new(client.clone(), auth.clone());

    match cli.command {
        Command::New { name, gcp_project, gcp_zone } => {
            let config = NetworkConfig::new(name.clone(), gcp_project.clone(), gcp_zone.clone());
            let config = toml::to_string_pretty(&config)?;
            fs::write(format!("{name}.toml"), config)?;
        },
        Command::Deploy { config_file } => {
            let config = fs::read_to_string(config_file)?;
            let config: NetworkConfig = toml::from_str(&config)?;

            let bin_bucket = create_bin_bucket(&client, &auth, &config).await?;

            //let instance = Instance {
            //    name: Some("test".to_owned()),
            //    machine_type: Some(format!("zones/{zone}/machineTypes/n1-standard-1")),
            //    disks: Some(vec![AttachedDisk {
            //        initialize_params: Some(AttachedDiskInitializeParams {
            //            source_image: Some(
            //                "projects/debian-cloud/global/images/debian-11-bullseye-v20240110"
            //                    .to_owned(),
            //            ),
            //            ..Default::default()
            //        }),
            //        boot: Some(true),
            //        disk_size_gb: Some(16),
            //        ..Default::default()
            //    }]),
            //    network_interfaces: Some(vec![NetworkInterface {
            //        subnetwork: Some(format!("projects/{project}/regions/europe-west2/subnetworks/zq2")),
            //        ..Default::default()
            //    }]),
            //    ..Default::default()
            //};
            //let (_, mut op) = dbg!(
            //    compute
            //        .instances()
            //        .insert(instance, &project, &zone)
            //        .doit()
            //        .await
            //)?;
            //while op.status.as_deref().unwrap() != "DONE" {
            //    (_, op) = compute.zone_operations().get(&project, &zone, &op.name.unwrap()).doit().await?;
            //}
            //println!("{op:#?}");
        }
    }


    //let instances = paginated!(compute.instances().list(&project, &zone));
    //for i in instances {
    //    println!("{:?}", i.name);
    //}

    Ok(())
}
