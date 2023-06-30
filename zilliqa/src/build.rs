use std::error::Error;
use vergen::EmitBuilder;

// This build script will be executed when building the project and will provide
// the git commit as an environment variable
fn main() -> Result<(), Box<dyn Error>> {
    // Emit the instructions
    println!("cargo:rerun-if-changed=$path");
    EmitBuilder::builder().all_git().emit()?;

    Ok(())

}
