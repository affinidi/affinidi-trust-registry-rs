#[cfg(feature = "loaders-aws")]
pub mod aws_parameter_store;
#[cfg(feature = "loaders-aws")]
pub mod aws_secrets;
pub mod environment;
pub mod file;
pub mod string;

/// Resolve a config value from a loader URI.
///
/// `string://` and `file://` are dependency-free and always available. The AWS
/// schemes are behind `loaders-aws`; when that feature is off they are rejected
/// by name rather than silently falling through to `string::load`, which would
/// hand the caller the literal URI as if it were the secret.
pub async fn load(input: &str) -> Result<String, String> {
    if let Some(content) = input.strip_prefix("string://") {
        string::load(content)
    } else if let Some(path) = input.strip_prefix("file://") {
        file::load(path)
    } else if let Some(_secret_name) = input.strip_prefix("aws_secrets://") {
        #[cfg(feature = "loaders-aws")]
        {
            aws_secrets::load(_secret_name).await
        }
        #[cfg(not(feature = "loaders-aws"))]
        Err("aws_secrets:// requires the `loaders-aws` feature, which is not compiled in".into())
    } else if let Some(_param_name) = input.strip_prefix("aws_parameter_store://") {
        #[cfg(feature = "loaders-aws")]
        {
            aws_parameter_store::load(_param_name).await
        }
        #[cfg(not(feature = "loaders-aws"))]
        Err(
            "aws_parameter_store:// requires the `loaders-aws` feature, which is not compiled in"
                .into(),
        )
    } else {
        string::load(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_load_string_uri() {
        let result = load("string://test content").await.unwrap();
        assert_eq!(result, "test content");
    }

    #[tokio::test]
    async fn test_load_string_uri_json() {
        let json = r#"{"key":"value"}"#;
        let result = load(&format!("string://{}", json)).await.unwrap();
        assert_eq!(result, json);
    }

    #[tokio::test]
    async fn test_load_file_uri() {
        let temp_file = NamedTempFile::new().unwrap();
        fs::write(&temp_file, "file content").unwrap();

        let uri = format!("file://{}", temp_file.path().to_str().unwrap());
        let result = load(&uri).await.unwrap();
        assert_eq!(result, "file content");
    }

    #[tokio::test]
    async fn test_load_invalid_uri_scheme() {
        let result = load("invalid://test").await;
        assert!(result.is_ok());
        assert!(result.unwrap().contains("invalid://test"));
    }

    #[tokio::test]
    async fn test_load_no_scheme() {
        let result = load("just-a-string").await;
        assert!(result.is_ok());
        assert!(result.unwrap().contains("just-a-string"));
    }
}
