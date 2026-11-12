//! Writing `.env`-style files that may hold private keys.
//!
//! Shared by the `dev-tools` binaries through `#[path]`. Every file written
//! here is readable by its owner only (0600 on Unix), whether it is created,
//! copied from an example or already there.

use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::Path,
};

/// Open `path` for writing, truncated, with owner-only permissions.
///
/// The mode is applied to a new file as it is created and set again on an
/// existing one, so a file first written with a wider mode is narrowed.
pub fn open_private(path: &Path) -> std::io::Result<fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

/// Merge `new_vars` into the env file at `file_path` and drop the keys in
/// `remove`.
///
/// When the file does not exist and `example_file_path` does, the example's
/// variables are the starting point. The file is (re)written owner-only.
pub fn insert_env_vars(
    file_path: &str,
    new_vars: HashMap<String, String>,
    remove: &[&str],
    example_file_path: Option<&str>,
) -> std::io::Result<()> {
    let path = Path::new(file_path);
    let source = if path.exists() {
        Some(path)
    } else {
        example_file_path.map(Path::new).filter(|p| p.exists())
    };

    let mut existing_vars = HashMap::new();
    if let Some(source) = source {
        let reader = BufReader::new(fs::File::open(source)?);
        for line in reader.lines() {
            let line = line?;
            if let Some((key, value)) = line.split_once('=') {
                existing_vars.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
    }

    for (key, value) in new_vars {
        existing_vars.insert(key, value);
    }
    for key in remove {
        existing_vars.remove(*key);
    }

    let mut file = open_private(path)?;
    let mut keys: Vec<&String> = existing_vars.keys().collect();
    keys.sort();
    for key in keys {
        writeln!(file, "{}={}", key, existing_vars[key])?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn tmp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tr-env-file-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn merges_removes_and_starts_from_the_example() {
        let dir = tmp_dir("merge");
        let example = dir.join("example");
        fs::write(&example, "A=1\nPROFILE_CONFIG='x'\n").unwrap();
        let target = dir.join(".env");

        let mut vars = HashMap::new();
        vars.insert("B".to_string(), "2".to_string());
        insert_env_vars(
            target.to_str().unwrap(),
            vars,
            &["PROFILE_CONFIG"],
            Some(example.to_str().unwrap()),
        )
        .unwrap();

        assert_eq!(fs::read_to_string(&target).unwrap(), "A=1\nB=2\n");
        // The example is a template, never written to.
        assert_eq!(
            fs::read_to_string(&example).unwrap(),
            "A=1\nPROFILE_CONFIG='x'\n"
        );
        fs::remove_dir_all(dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn a_new_file_is_owner_only_even_when_the_example_is_not() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_dir("new");
        let example = dir.join("example");
        fs::write(&example, "A=1\n").unwrap();
        fs::set_permissions(&example, fs::Permissions::from_mode(0o644)).unwrap();
        let target = dir.join(".env");

        insert_env_vars(
            target.to_str().unwrap(),
            HashMap::new(),
            &[],
            Some(example.to_str().unwrap()),
        )
        .unwrap();

        assert_eq!(mode(&target), 0o600);
        fs::remove_dir_all(dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn an_existing_wider_file_is_narrowed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_dir("existing");
        let target = dir.join(".env");
        fs::write(&target, "A=1\n").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();

        let mut vars = HashMap::new();
        vars.insert("SECRET".to_string(), "s".to_string());
        insert_env_vars(target.to_str().unwrap(), vars, &[], None).unwrap();

        assert_eq!(mode(&target), 0o600);
        assert_eq!(fs::read_to_string(&target).unwrap(), "A=1\nSECRET=s\n");
        fs::remove_dir_all(dir).ok();
    }
}
