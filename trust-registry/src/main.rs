use trust_registry::server::start;

#[tokio::main]
async fn main() {
    return start().await;
}
