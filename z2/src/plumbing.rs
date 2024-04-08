use std::env;

use crate::otel;
use eyre::Result;

/// Code for all the z2 commands, so you can invoke it from your own programs.
use crate::setup;

pub async fn run_local_net(
    config_dir: &str,
    log_level: &str,
    debug_modules: &Vec<String>,
    trace_modules: &Vec<String>,
) -> Result<()> {
    // Now build the log string. If there already was one, use that ..
    let log_var = env::var("RUST_LOG");
    let log_spec = match log_var {
        Ok(val) => {
            println!("Using RUST_LOG from environment");
            val
        }
        _ => {
            let mut val = log_level.to_string();
            for i in debug_modules {
                val.push_str(&format!(",{i}=debug"));
            }
            for i in trace_modules {
                val.push_str(&format!(",{i}=trace"));
            }
            val.push_str(",opentelemetry=trace,opentelemetry_otlp=trace");
            val
        }
    };
    println!("RUST_LOG = {log_spec}");
    println!("Setting up otel .. ");
    let otel = otel::Otel::new(config_dir)?;
    otel.write_files().await?;
    otel.ensure_otel().await?;
    let mut setup_obj = setup::Setup::new(4, config_dir, &log_spec)?;
    setup_obj.run().await?;
    Ok(())
}
