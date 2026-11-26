#![forbid(unsafe_code)]

use clap::Parser;
use net2rust_cli::{Cli, run_cli};
use tracing_subscriber::EnvFilter;

fn init_tracing(level: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

fn main() -> anyhow::Result<()> {
    let _ = ctrlc::set_handler(|| {
        std::process::exit(130);
    });

    let cli = Cli::parse();
    init_tracing(&cli.log_level);
    run_cli(cli)
}
