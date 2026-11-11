use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    init_tracing();
    let code = netatlas::cli::run().await;
    std::process::exit(code);
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
