//! Environment readers used by the [`Configs`](crate::configs::Configs)
//! implementations — the only place the registry reads its environment.
//!
//! Every typed reader reports a bad value as `<NAME> must be <expectation>
//! (got '<value>')`, so the operator can tell from the log which setting was
//! wrong. A value that does not parse is an error, never a silent default.

use std::env;
use std::str::FromStr;

pub fn required_env(env_name: &str) -> Result<String, String> {
    env::var(env_name).map_err(|_| format!("Required environment variable '{env_name}' is not set"))
}

pub fn optional_env(env_name: &str) -> Option<String> {
    env::var(env_name).ok()
}

pub fn env_or(env_name: &str, default: &str) -> String {
    optional_env(env_name).unwrap_or_else(|| default.to_string())
}

/// `env_name`, trimmed, or `None` when it is unset or blank.
pub fn non_empty_env(env_name: &str) -> Option<String> {
    optional_env(env_name)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Parse `env_name` as a `T`, or `default` when it is unset or blank.
///
/// `expectation` completes the sentence "`<NAME>` must be ..." in the error.
pub fn parse_env<T: FromStr>(env_name: &str, default: T, expectation: &str) -> Result<T, String> {
    match non_empty_env(env_name) {
        None => Ok(default),
        Some(raw) => raw
            .parse::<T>()
            .map_err(|_| format!("{env_name} must be {expectation} (got '{raw}')")),
    }
}

/// Parse `env_name` as a whole number greater than zero, or `default` when it
/// is unset or blank. Zero is an error.
pub fn positive_env(env_name: &str, default: u64) -> Result<u64, String> {
    let value = parse_env(env_name, default, "a positive whole number")?;
    if value == 0 {
        return Err(format!(
            "{env_name} must be a positive whole number (got '0')"
        ));
    }
    Ok(value)
}

/// Parse a boolean environment flag, defaulting when unset or empty.
///
/// Only `true`/`false` are accepted (case-insensitively): a typo like
/// `ENABLE_TSP=yes` must not silently read as "off" and leave the operator
/// believing TSP is running.
pub fn env_flag(env_name: &str, default: bool) -> Result<bool, String> {
    match env::var(env_name) {
        Err(_) => Ok(default),
        Ok(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "" => Ok(default),
            "true" => Ok(true),
            "false" => Ok(false),
            other => Err(format!(
                "{env_name} must be 'true' or 'false' (got '{other}')"
            )),
        },
    }
}

#[cfg(test)]
// `std::env::{set_var, remove_var}` are unsafe since edition 2024.
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use serial_test::serial;

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

    #[test]
    #[serial]
    fn parse_env_names_the_variable_and_value_on_error() {
        unsafe { std::env::set_var("TR_TEST_PARSE_ENV", "ten") };
        let err = parse_env::<u32>("TR_TEST_PARSE_ENV", 1, "a whole number").unwrap_err();
        assert_eq!(err, "TR_TEST_PARSE_ENV must be a whole number (got 'ten')");
        unsafe { std::env::set_var("TR_TEST_PARSE_ENV", " 7 ") };
        assert_eq!(parse_env::<u32>("TR_TEST_PARSE_ENV", 1, "x"), Ok(7));
        unsafe { std::env::set_var("TR_TEST_PARSE_ENV", "") };
        assert_eq!(parse_env::<u32>("TR_TEST_PARSE_ENV", 1, "x"), Ok(1));
        unsafe { std::env::remove_var("TR_TEST_PARSE_ENV") };
        assert_eq!(parse_env::<u32>("TR_TEST_PARSE_ENV", 1, "x"), Ok(1));
    }

    #[test]
    #[serial]
    fn positive_env_refuses_zero() {
        unsafe { std::env::set_var("TR_TEST_POSITIVE_ENV", "0") };
        let err = positive_env("TR_TEST_POSITIVE_ENV", 5).unwrap_err();
        assert!(err.starts_with("TR_TEST_POSITIVE_ENV"), "{err}");
        unsafe { std::env::remove_var("TR_TEST_POSITIVE_ENV") };
        assert_eq!(positive_env("TR_TEST_POSITIVE_ENV", 5), Ok(5));
    }

    #[test]
    #[serial]
    fn env_flag_accepts_only_true_or_false() {
        unsafe { std::env::set_var("TR_TEST_FLAG", "yes") };
        let err = env_flag("TR_TEST_FLAG", false).unwrap_err();
        assert!(err.contains("TR_TEST_FLAG"), "{err}");
        unsafe { std::env::set_var("TR_TEST_FLAG", " TRUE ") };
        assert_eq!(env_flag("TR_TEST_FLAG", false), Ok(true));
        unsafe { std::env::remove_var("TR_TEST_FLAG") };
        assert_eq!(env_flag("TR_TEST_FLAG", true), Ok(true));
    }
}
