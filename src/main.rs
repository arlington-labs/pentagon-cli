use clap::Parser;
use pentagon_cli::cli::Cli;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_target(false)
        .without_time()
        .init();

    if let Err(error) = Cli::parse().run().await {
        let safe = pentagon_cli::secret::Redactor::default().redact(&error.to_string());
        eprintln!("Error: {safe}");
        std::process::exit(error.exit_code());
    }
}
