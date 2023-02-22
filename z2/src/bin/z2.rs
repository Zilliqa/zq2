use eyre::Result;
use tokio::sync::mpsc;
use z2lib::collector;
use z2lib::runner;
use z2lib::setup;

#[tokio::main]
async fn main() -> Result<()> {
    let mut result = collector::Collector::new(8).await?;
    result.complete().await;
    println!("Hello, world!");
    let setup_obj = setup::Setup::new()?;
    let new_key = setup_obj.generate_secret_key_hex()?;
    println!("New key {new_key}");
    Ok(())
}
