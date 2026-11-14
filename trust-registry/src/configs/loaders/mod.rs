#[cfg(feature = "loaders-aws")]
pub mod aws_parameter_store;
#[cfg(feature = "loaders-aws")]
pub mod aws_secrets;
pub mod environment;
pub mod file;
pub mod string;

/// The loader schemes [`load`] understands, for error messages.
pub const SUPPORTED_SCHEMES: &str = "string://, file://, aws_secrets://, aws_parameter_store://";

/// The scheme of `input` if it looks like a URI: a letter followed by letters,
/// digits, `+`, `-`, `.` or `_`, then a `:`. Inline JSON (`{...}`, `[...]`)
/// and other text without such a prefix has none.
///
/// `_` is accepted (RFC 3986 does not) because two supported schemes contain
/// one, so a typo such as `aws_secret://` must still be recognised as a scheme.
fn uri_scheme(input: &str) -> Option<&str> {
    let (scheme, _) = input.split_once(':')?;
    let mut chars = scheme.chars();
    let first = chars.next()?;
    (first.is_ascii_alphabetic()
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.' | '_')))
    .then_some(scheme)
}

/// Resolve a config value from a loader URI.
///
/// `string://` and `file://` are dependency-free and always available. The AWS
/// schemes are behind `loaders-aws`; when that feature is off they are rejected
/// by name rather than silently falling through to `string::load`, which would
/// hand the caller the literal URI as if it were the secret.
///
/// Input with no scheme (inline JSON, for instance) is the value itself. Input
/// that starts like a URI (`<scheme>:`) with any other scheme (a typo such as
/// `aws_secret://`, `File:///` or `file:/etc/...`) is an error listing the
/// supported schemes, never a literal value.
///
/// Errors never include the value: it may be the secret itself. Callers
/// should use [`load_setting`], which names the setting.
pub async fn load(input: &str) -> Result<String, String> {
    if let Some(content) = input.strip_prefix("string://") {
        string::load(content)
    } else if let Some(path) = input.strip_prefix("file://") {
        file::load(path).await
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
    } else if let Some(scheme) = uri_scheme(input.trim_start()) {
        Err(format!(
            "unsupported loader scheme '{scheme}:'; the supported schemes are \
             {SUPPORTED_SCHEMES} (case-sensitive, each followed by '//'), or an inline \
             JSON value"
        ))
    } else {
        string::load(input)
    }
}

/// [`load`] the value of the setting `name`, prefixing any error with the
/// setting's name so the operator knows which variable to fix.
pub async fn load_setting(name: &str, input: &str) -> Result<String, String> {
    load(input).await.map_err(|e| format!("{name}: {e}"))
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

    /// A URI with a scheme the loader does not know used to be returned as
    /// the literal value, so a typo surfaced later as a JSON parse error.
    #[tokio::test]
    async fn test_load_invalid_uri_scheme() {
        for input in [
            "invalid://test",
            "aws_secret://tr/profile",
            "aws-secrets://tr/profile",
            "File:///etc/tr/profile.json",
            "file:/etc/tr/profile.json",
            "  string:{}",
        ] {
            let err = load(input).await.expect_err(input);
            assert!(err.contains("unsupported loader scheme"), "{input}: {err}");
            assert!(err.contains("file://"), "{input}: {err}");
        }
    }

    #[tokio::test]
    async fn test_load_no_scheme() {
        let result = load("just-a-string").await;
        assert!(result.is_ok());
        assert!(result.unwrap().contains("just-a-string"));
    }

    #[tokio::test]
    async fn inline_json_is_the_value_itself() {
        let json = r#"{"did":"did:example:1","note":"a: b://c"}"#;
        assert_eq!(load(json).await.unwrap(), json);
        assert_eq!(load(" [1, 2]").await.unwrap(), " [1, 2]");
    }

    #[tokio::test]
    async fn load_setting_names_the_setting_and_not_the_value() {
        let err = load_setting("PROFILE_CONFIG", "aws_secret://s3cr3t-name")
            .await
            .unwrap_err();
        assert!(err.starts_with("PROFILE_CONFIG: "), "{err}");
        assert!(!err.contains("s3cr3t-name"), "{err}");
        let err = load_setting("DID_DOCUMENT", "file:///does/not/exist.json")
            .await
            .unwrap_err();
        assert!(err.starts_with("DID_DOCUMENT: "), "{err}");
    }
}
