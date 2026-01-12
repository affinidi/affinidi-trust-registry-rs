use std::env;

pub fn required_env(env_name: &str) -> Result<String, String> {
    env::var(env_name).map_err(|_| format!("Required environment variable '{env_name}' is not set"))
}

pub fn optional_env(env_name: &str) -> Option<String> {
    env::var(env_name).ok()
}

pub fn env_or(env_name: &str, default: &str) -> String {
    optional_env(env_name).unwrap_or_else(|| default.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_required_env_success() {
        unsafe {
            std::env::set_var("TEST_VAR", "value");
        }

        assert_eq!(required_env("TEST_VAR").unwrap(), "value");

        unsafe {
            std::env::remove_var("TEST_VAR");
        }
    }

    #[test]
    fn test_required_env_missing() {
        unsafe {
            std::env::remove_var("MISSING_VAR");
        }
        assert!(required_env("MISSING_VAR").is_err());
    }

    #[test]
    fn test_optional_env_present() {
        unsafe {
            std::env::set_var("OPT_VAR", "value");
        }
        assert_eq!(optional_env("OPT_VAR"), Some("value".to_string()));

        unsafe {
            std::env::remove_var("OPT_VAR");
        }
    }

    #[test]
    fn test_optional_env_missing() {
        unsafe {
            std::env::remove_var("MISSING_OPT");
        }
        assert_eq!(optional_env("MISSING_OPT"), None);
    }

    #[test]
    fn test_env_or_present() {
        unsafe {
            std::env::set_var("ENV_VAR", "actual");
        }
        assert_eq!(env_or("ENV_VAR", "default"), "actual");

        unsafe {
            std::env::remove_var("ENV_VAR");
        }
    }

    #[test]
    fn test_env_or_missing_uses_default() {
        unsafe {
            std::env::remove_var("MISSING");
        }
        assert_eq!(env_or("MISSING", "default"), "default");
    }
}
