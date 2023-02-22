use eyre::Result;
use tokio::sync::mpsc;
use z2lib::collector;
use z2lib::runner;

#[tokio::main]
async fn main() -> Result<()> {
    let mut result = collector::Collector::new(8).await?;
    result.complete().await;
    println!("Hello, world!");
    Ok(())
}
