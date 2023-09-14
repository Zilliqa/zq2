use std::error::Error;

use vergen::EmitBuilder;

fn main() -> Result<(), Box<dyn Error>> {
    // Emit the instructions
    EmitBuilder::builder().all_git().emit()?;

    prost_build::compile_protos(&["src/zq1/ZilliqaMessage.proto"], &["src/"])?;

    Ok(())
}
