use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    prost_build::compile_protos(&["src/zq1/ZilliqaMessage.proto"], &["src/"])?;

    Ok(())
}
