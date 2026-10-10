//! The model against the real files in this repository: KMRP's hook tables
//! and every hooks/manifest file in the KPM submodule (when checked out).

use std::path::{Path, PathBuf};

use kpm_sdk::model::{HookType, HooksFile, Manifest, Severity};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(&p, out);
        } else {
            out.push(p);
        }
    }
}

#[test]
fn kmrp_hook_tables_parse_with_no_errors() {
    let dir = repo().join("src/controller-native");
    let mut files = Vec::new();
    walk(&dir, &mut files);
    files.retain(|p| p.to_string_lossy().ends_with("hooks.toml"));
    if files.is_empty() {
        eprintln!("no KMRP hook tables found; skipping");
        return;
    }
    let mut hooks = 0;
    for path in &files {
        let text = std::fs::read_to_string(path).unwrap();
        let file = HooksFile::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        for h in &file.hooks {
            for issue in h.issues() {
                assert_ne!(
                    issue.severity,
                    Severity::Error,
                    "{}: {}: {issue}",
                    path.display(),
                    h.label()
                );
            }
            assert!(
                h.extra.is_empty(),
                "{}: unmodelled keys {:?}",
                h.label(),
                h.extra
            );
        }
        hooks += file.hooks.len();
    }
    // kotor1.hooks.toml alone held 52 on 2026-10-10.
    assert!(hooks >= 50, "{hooks}");
    let main =
        HooksFile::parse(&std::fs::read_to_string(dir.join("kotor1.hooks.toml")).unwrap()).unwrap();
    assert!(main.hooks.iter().any(|h| h.kind == HookType::Replace));
    assert!(main.hooks.iter().any(|h| h.kpm_provided_by.is_some()));
    assert!(main.hooks.iter().any(|h| h.consumed_exit_address.is_some()));
}

#[test]
fn kpm_patches_parse() {
    let dir = repo().join("third_party/Kotor-Patch-Manager/Patches");
    let mut files = Vec::new();
    walk(&dir, &mut files);
    if files.is_empty() {
        eprintln!("KPM submodule not checked out; skipping");
        return;
    }
    let (mut hooks_files, mut manifests) = (0, 0);
    for path in &files {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if name.ends_with("hooks.toml") {
            let text = std::fs::read_to_string(path).unwrap();
            let file =
                HooksFile::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            for issue in file.issues() {
                assert_ne!(
                    issue.severity,
                    Severity::Error,
                    "{}: {issue}",
                    path.display()
                );
            }
            // x86_64 Mach-O hooks (above 4 GB) follow the 64-bit wrapper's rules.
            for h in file.hooks.iter().filter(|h| h.address() <= u32::MAX as u64) {
                let errors: Vec<_> = h
                    .issues()
                    .into_iter()
                    .filter(|i| i.severity == Severity::Error)
                    .collect();
                assert!(
                    errors.is_empty(),
                    "{}: {}: {errors:?}",
                    path.display(),
                    h.label()
                );
            }
            hooks_files += 1;
        } else if name == "manifest.toml" {
            let text = std::fs::read_to_string(path).unwrap();
            let m = Manifest::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            let errors: Vec<_> = m
                .issues()
                .into_iter()
                .filter(|i| i.severity == Severity::Error)
                .collect();
            assert!(errors.is_empty(), "{}: {errors:?}", path.display());
            manifests += 1;
        }
    }
    assert!(
        hooks_files > 50 && manifests > 30,
        "{hooks_files} {manifests}"
    );
}
