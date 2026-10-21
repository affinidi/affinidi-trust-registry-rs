use trust_registry::server::start;

#[tokio::main]
async fn main() {
    // `trust-registry setup …` provisions the registry at a VTA and exits;
    // anything else runs the service.
    #[cfg(feature = "vta")]
    if std::env::args_os().nth(1).is_some_and(|a| a == "setup") {
        std::process::exit(trust_registry::setup::run_cli(std::env::args_os().skip(1)).await);
    }
    start().await
}
