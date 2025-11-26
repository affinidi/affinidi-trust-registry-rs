use std::fs;
use tracing::info;

#[derive(Debug)]
pub enum DidDocumentSource {
    File(String),
    AwsParameterStore(String),
}

pub struct DidDocumentLoader {
    source: DidDocumentSource,
}

impl DidDocumentLoader {
    pub fn new(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let source = if let Some(file_path) = path.strip_prefix("file://") {
            DidDocumentSource::File(file_path.to_string())
        } else if let Some(param_name) = path.strip_prefix("aws_parameter_store://") {
            DidDocumentSource::AwsParameterStore(param_name.to_string())
        } else {
            return Err(format!(
                "Invalid DID_WEB_DOCUMENT_PATH format. Expected 'file://<path>' or 'aws_parameter_store://<parameter_name>', got: {}",
                path
            ).into());
        };

        Ok(Self { source })
    }

    pub async fn load(&self) -> Result<String, Box<dyn std::error::Error>> {
        match &self.source {
            DidDocumentSource::File(path) => {
                info!("Loading DID document from file: {}", path);
                let content = fs::read_to_string(path)
                    .map_err(|e| format!("Failed to read DID document from file {}: {}", path, e))?;
                Ok(content)
            }
            DidDocumentSource::AwsParameterStore(param_name) => {
                info!("Loading DID document from AWS Parameter Store: {}", param_name);
                self.load_from_aws_parameter_store(param_name).await
            }
        }
    }

    async fn load_from_aws_parameter_store(
        &self,
        param_name: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        use aws_config::BehaviorVersion;
        use aws_sdk_ssm::Client;

        let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
        let client = Client::new(&config);

        let response = client
            .get_parameter()
            .name(param_name)
            .with_decryption(true)
            .send()
            .await
            .map_err(|e| {
                format!(
                    "Failed to fetch parameter '{}' from AWS Parameter Store: {}",
                    param_name, e
                )
            })?;

        let value = response
            .parameter()
            .and_then(|p| p.value())
            .ok_or_else(|| {
                format!(
                    "Parameter '{}' exists but has no value",
                    param_name
                )
            })?;

        Ok(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    // TODO: improve with temp file
    use super::*;

    #[test]
    fn test_parse_file_path() {
        let loader = DidDocumentLoader::new("file:///path/to/did.json").unwrap();
        match loader.source {
            DidDocumentSource::File(path) => assert_eq!(path, "/path/to/did.json"),
            _ => panic!("Expected File source"),
        }
    }

    #[test]
    fn test_parse_aws_parameter_store() {
        let loader = DidDocumentLoader::new("aws_parameter_store:///prod/did-document").unwrap();
        match loader.source {
            DidDocumentSource::AwsParameterStore(param) => assert_eq!(param, "/prod/did-document"),
            _ => panic!("Expected AwsParameterStore source"),
        }
    }

    #[test]
    fn test_invalid_path() {
        let result = DidDocumentLoader::new("https://example.com/did.json");
        assert!(result.is_err());
    }
}
