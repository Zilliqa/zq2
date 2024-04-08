use eyre::Result;

/// Code for all the z2 commands, so you can invoke it from your own programs.
use crate::setup;
use std::env;

pub async fn run_local_net(config_dir: &str, log_level: &str) -> Result<()> {
    // Now build the log string. If there already was one, use that ..
    let log_spec = env::var("RUST_LOG").unwrap_or(format!("zilliqa={log_level}"));
    let mut setup_obj = setup::Setup::new(4, config_dir, &log_spec)?;
    setup_obj.run().await?;
    Ok(())
}
