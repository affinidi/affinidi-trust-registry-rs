pub mod aws_parameter_store;
pub mod aws_secrets;
pub mod environment;
pub mod file;
pub mod string;

pub async fn load(input: &str) -> Result<String, String> {
    if let Some(content) = input.strip_prefix("string://") {
        string::load(content)
    } else if let Some(path) = input.strip_prefix("file://") {
        file::load(path)
    } else if let Some(secret_name) = input.strip_prefix("aws_secrets://") {
        aws_secrets::load(secret_name).await
    } else if let Some(param_name) = input.strip_prefix("aws_parameter_store://") {
        aws_parameter_store::load(param_name).await
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
