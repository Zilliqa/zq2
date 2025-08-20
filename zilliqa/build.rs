use anyhow::Result;
use vergen_git2::{Emitter, Git2Builder};

fn main() -> Result<()> {
    Emitter::default()
        .add_instructions(
            &Git2Builder::default()
                .describe(true, false, None)
                .sha(false)
                .build()?,
        )?
        .emit()?;

    Ok(())
}
