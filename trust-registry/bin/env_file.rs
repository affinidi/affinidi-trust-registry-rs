//! Reading and editing `.env`-style files that may hold private keys.
//!
//! Used by the `setup-trust-registry` binary through `#[path]`. Every file
//! written here is readable by its owner only (0600 on Unix), whether it is
//! created, copied from an example or already there. An edit changes only the
//! lines of the keys it sets or removes: comments, blank lines, ordering and
//! every other variable stay as they were. The new content is written to a
//! temporary file beside the target and renamed over it, so an interruption
//! leaves either the old file or the new one, never a truncated one.

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
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

/// Create `path` owner-only with `contents`, refusing to replace an existing
/// file.
pub fn create_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

/// The key and value of an assignment line, or `None` for a comment, a blank
/// line or anything else that is not `KEY=value`.
///
/// The value is returned as written (trimmed), quotes and any inline comment
/// included; [`is_blank_value`] decides whether it is empty.
pub fn parse_line(line: &str) -> Option<(&str, &str)> {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') {
        return None;
    }
    let trimmed = trimmed.strip_prefix("export ").unwrap_or(trimmed);
    let (key, value) = trimmed.split_once('=')?;
    let key = key.trim();
    let valid = !key.is_empty()
        && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !key.starts_with(|c: char| c.is_ascii_digit());
    valid.then_some((key, value.trim()))
}

/// Whether an env value carries nothing: empty, empty quotes, or only an
/// inline comment.
pub fn is_blank_value(value: &str) -> bool {
    let v = value.trim();
    v.is_empty() || v == "''" || v == "\"\"" || v.starts_with('#')
}

/// The variables of the env file at `path`, last assignment winning, or
/// `None` when it does not exist.
pub fn read_env_vars(path: &Path) -> std::io::Result<Option<BTreeMap<String, String>>> {
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(path)?;
    Ok(Some(
        text.lines()
            .filter_map(parse_line)
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    ))
}

/// `text` with `set` applied and the keys in `remove` dropped.
///
/// An assignment of a key in `set` has its value replaced where it stands; a
/// key in `set` that the text does not assign is appended, in key order.
/// Every other line is kept byte for byte.
pub fn edit_env_text(text: &str, set: &BTreeMap<String, String>, remove: &[&str]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut written: Vec<&str> = Vec::new();
    for line in text.lines() {
        match parse_line(line) {
            Some((key, _)) if remove.contains(&key) => {}
            Some((key, _)) if set.contains_key(key) => {
                // A key assigned twice keeps one assignment, the first.
                if !written.contains(&key) {
                    out.push_str(&format!("{key}={}\n", set[key]));
                    written.push(key);
                }
            }
            _ => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    for (key, value) in set {
        if !written.contains(&key.as_str()) {
            out.push_str(&format!("{key}={value}\n"));
        }
    }
    out
}

/// Write `contents` to `path` owner-only through a temporary file in the same
/// directory, renamed over the target.
pub fn write_atomically(path: &Path, contents: &str) -> std::io::Result<()> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "env".to_string());
    let tmp = dir.join(format!(".{name}.tmp-{}", std::process::id()));
    let result = (|| {
        let mut file = open_private(&tmp)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        fs::remove_file(&tmp).ok();
    }
    result
}

/// Merge `new_vars` into the env file at `file_path` and drop the keys in
/// `remove`, editing only those lines (see [`edit_env_text`]).
///
/// When the file does not exist and `example_file_path` does, the example is
/// the starting point. The file is (re)written owner-only and atomically.
pub fn insert_env_vars(
    file_path: &str,
    new_vars: BTreeMap<String, String>,
    remove: &[&str],
    example_file_path: Option<&str>,
) -> std::io::Result<()> {
    let path = Path::new(file_path);
    let source = if path.exists() {
        Some(path)
    } else {
        example_file_path.map(Path::new).filter(|p| p.exists())
    };
    let text = match source {
        Some(source) => fs::read_to_string(source)?,
        None => String::new(),
    };
    write_atomically(path, &edit_env_text(&text, &new_vars, remove))
}

/// A sibling of `path` named `<name>.backup-<UTC timestamp>`.
pub fn backup_path(path: &Path, stamp: &str) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    path.with_file_name(format!("{name}.backup-{stamp}"))
}

/// Copy `path` to an owner-only backup beside it and return where.
pub fn backup_file(path: &Path, stamp: &str) -> std::io::Result<PathBuf> {
    let backup = backup_path(path, stamp);
    create_private(&backup, &fs::read(path)?)?;
    Ok(backup)
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

    fn vars(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn merges_removes_and_starts_from_the_example() {
        let dir = tmp_dir("merge");
        let example = dir.join("example");
        fs::write(&example, "A=1\nPROFILE_CONFIG='x'\n").unwrap();
        let target = dir.join(".env");

        insert_env_vars(
            target.to_str().unwrap(),
            vars(&[("B", "2")]),
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

    /// Comments, blank lines and order survive; only the set keys change,
    /// in place, and an inline comment on a replaced line goes with it.
    #[test]
    fn an_edit_keeps_comments_order_and_other_lines() {
        let text = "# Storage\nTR_STORAGE_BACKEND=csv\n\n## ACL mode, = sign in comment\n\
                    ACL_MODE=ExplicitDeny # Options: ExplicitDeny, ExplicitAllow\nZ=last\n";
        let out = edit_env_text(
            text,
            &vars(&[("ACL_MODE", "ExplicitAllow"), ("NEW", "n")]),
            &["Z"],
        );
        assert_eq!(
            out,
            "# Storage\nTR_STORAGE_BACKEND=csv\n\n## ACL mode, = sign in comment\n\
             ACL_MODE=ExplicitAllow\nNEW=n\n"
        );
        // Deterministic: the same edit twice gives the same file.
        assert_eq!(
            edit_env_text(
                &out,
                &vars(&[("ACL_MODE", "ExplicitAllow"), ("NEW", "n")]),
                &[]
            ),
            out
        );
    }

    #[test]
    fn lines_parse_as_assignments_only_when_they_are() {
        assert_eq!(parse_line("A=1"), Some(("A", "1")));
        assert_eq!(parse_line("export A = 1 "), Some(("A", "1")));
        assert_eq!(parse_line("# A=1"), None);
        assert_eq!(parse_line("  # comment"), None);
        assert_eq!(parse_line("not an assignment"), None);
        assert_eq!(parse_line("1A=x"), None);
        assert!(is_blank_value(""));
        assert!(is_blank_value("''"));
        assert!(is_blank_value("# nothing"));
        assert!(!is_blank_value("did:example:a"));
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
            BTreeMap::new(),
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

        insert_env_vars(
            target.to_str().unwrap(),
            vars(&[("SECRET", "s")]),
            &[],
            None,
        )
        .unwrap();

        assert_eq!(mode(&target), 0o600);
        assert_eq!(fs::read_to_string(&target).unwrap(), "A=1\nSECRET=s\n");
        // No temporary file is left behind.
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_backup_is_an_owner_only_copy_and_never_replaced() {
        let dir = tmp_dir("backup");
        let target = dir.join(".env");
        fs::write(&target, "PROFILE_CONFIG='secret'\n").unwrap();
        let backup = backup_file(&target, "20261114T000000Z").unwrap();
        assert_eq!(backup, dir.join(".env.backup-20261114T000000Z"));
        assert_eq!(
            fs::read_to_string(&backup).unwrap(),
            "PROFILE_CONFIG='secret'\n"
        );
        #[cfg(unix)]
        assert_eq!(mode(&backup), 0o600);
        assert!(backup_file(&target, "20261114T000000Z").is_err());
        fs::remove_dir_all(dir).ok();
    }
}
