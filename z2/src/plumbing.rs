use eyre::Result;

/// Code for all the z2 commands, so you can invoke it from your own programs.
use crate::setup;

pub async fn run_local_net(config_dir: &str) -> Result<()> {
    let mut setup_obj = setup::Setup::new(4, config_dir)?;
    setup_obj.run().await?;
    Ok(())
}
