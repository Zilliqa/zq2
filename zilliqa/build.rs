use anyhow::Result;
use vergen::EmitBuilder;

fn main() -> Result<()> {
    EmitBuilder::builder()
        .git_describe(true, true, None)
        .git_sha(false)
        .fail_on_error()
        .emit()?;

    Ok(())
}
