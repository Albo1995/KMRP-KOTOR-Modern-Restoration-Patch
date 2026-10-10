//! Filesystem helpers for game installs.
//!
//! `chitin.key` names its BIFs with Windows paths (`data\2da.bif`), and the
//! files on disk may differ in case from what the KEY says. On Windows that
//! does not matter; on a case-sensitive filesystem (Linux, Proton, macOS with a
//! case-sensitive volume) it does. [`resolve`] tries the path as given, then
//! matches each component case-insensitively.

use std::path::{Path, PathBuf};

/// Resolve `relative` (which may use `\` or `/`) under `root`, matching each
/// component case-insensitively if the exact path does not exist.
pub fn resolve(root: &Path, relative: &str) -> Option<PathBuf> {
    let parts: Vec<&str> = relative
        .split(['\\', '/'])
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    let exact: PathBuf = parts.iter().fold(root.to_path_buf(), |p, c| p.join(c));
    if exact.exists() {
        return Some(exact);
    }
    let mut cur = root.to_path_buf();
    for part in parts {
        let direct = cur.join(part);
        if direct.exists() {
            cur = direct;
            continue;
        }
        let found = std::fs::read_dir(&cur).ok()?.flatten().find(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.eq_ignore_ascii_case(part))
        })?;
        cur = found.path();
    }
    Some(cur)
}

/// Files directly in `dir` whose extension matches `ext` case-insensitively,
/// sorted by name. A missing directory yields an empty list.
pub fn files_with_extension(dir: &Path, ext: &str) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.is_file()
                    && p.extension()
                        .and_then(|e| e.to_str())
                        .is_some_and(|e| e.eq_ignore_ascii_case(ext))
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    v.sort();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_case_insensitively() {
        let base =
            std::env::temp_dir().join(format!("kotor-formats-fsutil-{}", std::process::id()));
        let data = base.join("Data");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(data.join("Two.BIF"), b"x").unwrap();
        let got = resolve(&base, "data\\two.bif").unwrap();
        assert_eq!(got, data.join("Two.BIF"));
        assert!(resolve(&base, "data\\missing.bif").is_none());
        assert_eq!(files_with_extension(&data, "bif").len(), 1);
        std::fs::remove_dir_all(&base).unwrap();
    }
}
