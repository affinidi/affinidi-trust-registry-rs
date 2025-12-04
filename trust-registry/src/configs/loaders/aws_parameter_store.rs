use aws_config::{self, BehaviorVersion};
use aws_sdk_ssm;

pub async fn load(param_name: &str) -> Result<String, String> {
    let config = aws_config::load_defaults(BehaviorVersion::v2025_08_07()).await;
    let client = aws_sdk_ssm::Client::new(&config);

    let result = client
        .get_parameter()
        .name(param_name)
        .with_decryption(true)
        .send()
        .await
        .map_err(|e| format!("Failed to get parameter '{}': {}", param_name, e))?;

    result
        .parameter()
        .and_then(|p| p.value())
        .map(|v| v.to_string())
        .ok_or_else(|| format!("Parameter '{}' has no value", param_name))
}
