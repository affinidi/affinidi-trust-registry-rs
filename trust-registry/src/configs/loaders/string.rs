pub fn load(content: &str) -> Result<String, String> {
    Ok(content.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_load_returns_content() {
        let result = load("test content").unwrap();
        assert_eq!(result, "test content");
    }
    
    #[test]
    fn test_load_json_string() {
        let json = r#"{"key":"value"}"#;
        let result = load(json).unwrap();
        assert_eq!(result, json);
    }
}