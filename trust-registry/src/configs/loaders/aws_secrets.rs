use aws_config::{self, BehaviorVersion};
use aws_sdk_secretsmanager;

pub async fn load(secret_name: &str) -> Result<String, String> {
    let config = aws_config::load_defaults(BehaviorVersion::v2025_08_07()).await;
    let client = aws_sdk_secretsmanager::Client::new(&config);

    let result = client
        .get_secret_value()
        .secret_id(secret_name)
        .send()
        .await
        .map_err(|e| format!("Failed to get secret '{secret_name}': {e}"))?;

    result
        .secret_string()
        .map(|s| s.to_string())
        .ok_or_else(|| format!("Secret '{secret_name}' has no string value"))
}
