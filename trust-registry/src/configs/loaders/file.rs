use std::fs;

pub fn load(path: &str) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("Failed to read file '{}': {}", path, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_file_success() {
        let temp_file = NamedTempFile::new().unwrap();
        fs::write(&temp_file, "file content").unwrap();

        let result = load(temp_file.path().to_str().unwrap()).unwrap();
        assert_eq!(result, "file content");
    }

    #[test]
    fn test_load_file_not_found() {
        let result = load("/nonexistent/file.txt");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to read file"));
    }

    #[test]
    fn test_load_json_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let json = r#"{"did":"did:example:123","secrets":[]}"#;
        fs::write(&temp_file, json).unwrap();

        let result = load(temp_file.path().to_str().unwrap()).unwrap();
        assert_eq!(result, json);
    }
}
