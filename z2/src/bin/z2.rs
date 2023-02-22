use eyre::Result;
use tokio::sync::mpsc;
use z2lib::collector;
use z2lib::runner;
use z2lib::setup;

#[tokio::main]
async fn main() -> Result<()> {
    println!("Hello, world!");
    let mut setup_obj = setup::Setup::new(4)?;
    setup_obj.run().await?;
    Ok(())
}
