//! A line log in the game folder (next to `swkotor2.exe`).
//!
//! Each line is `2026-10-10T12:34:56.789Z <message>` (UTC), appended and
//! flushed immediately so the file survives a crash. The file is opened on the
//! first line, not at [`init`], so a module that never logs creates nothing.
//! Logging never panics and never fails the caller: an I/O error is dropped.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Logger {
    path: PathBuf,
    file: Mutex<Option<File>>,
}

impl Logger {
    /// A logger writing to `path`.
    pub fn at(path: impl Into<PathBuf>) -> Logger {
        Logger {
            path: path.into(),
            file: Mutex::new(None),
        }
    }

    /// A logger writing `file_name` in the game folder ([`crate::process::game_dir`]),
    /// or the working directory if that cannot be determined.
    pub fn in_game_dir(file_name: &str) -> Logger {
        let dir = crate::process::game_dir().unwrap_or_else(|_| PathBuf::from("."));
        Logger::at(dir.join(file_name))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one timestamped line.
    pub fn line(&self, message: &str) {
        let text = format!("{} {}\n", timestamp(SystemTime::now()), message);
        let Ok(mut guard) = self.file.lock() else {
            return;
        };
        if guard.is_none() {
            *guard = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .ok();
        }
        if let Some(file) = guard.as_mut() {
            let _ = file.write_all(text.as_bytes());
            let _ = file.flush();
        }
    }
}

static GLOBAL: OnceLock<Logger> = OnceLock::new();

/// Set the module-wide log file (in the game folder). The first call wins;
/// later calls return the existing logger.
pub fn init(file_name: &str) -> &'static Logger {
    GLOBAL.get_or_init(|| Logger::in_game_dir(file_name))
}

/// Set the module-wide log file to an explicit path. The first call wins.
pub fn init_at(path: impl Into<PathBuf>) -> &'static Logger {
    let path = path.into();
    GLOBAL.get_or_init(|| Logger::at(path))
}

/// The module-wide logger, if [`init`] has run.
pub fn global() -> Option<&'static Logger> {
    GLOBAL.get()
}

/// Write a line to the module-wide logger; a no-op before [`init`].
pub fn line(message: &str) {
    if let Some(l) = global() {
        l.line(message);
    }
}

/// `format!`-style logging to the module-wide logger.
#[macro_export]
macro_rules! kpm_log {
    ($($arg:tt)*) => { $crate::log::line(&::std::format!($($arg)*)) };
}

/// Route panic messages (with location) to the module-wide log in addition
/// to the default hook, which writes to a stderr the game does not have.
pub fn install_panic_logger() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        line(&format!("panic: {info}"));
        previous(info);
    }));
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ` for a UTC instant.
pub fn timestamp(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    let (y, m, day) = civil_from_days((secs / 86_400) as i64);
    let rem = secs % 86_400;
    format!(
        "{y:04}-{m:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60,
        d.subsec_millis()
    )
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian
/// (Howard Hinnant's `civil_from_days`).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn timestamps() {
        assert_eq!(timestamp(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        // 2026-10-10T12:34:56.789Z
        let t = UNIX_EPOCH + Duration::from_millis(1_791_635_696_789);
        assert_eq!(timestamp(t), "2026-10-10T12:34:56.789Z");
        // Leap day.
        let t = UNIX_EPOCH + Duration::from_secs(951_782_400);
        assert_eq!(timestamp(t), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn appends_lines() {
        let dir = std::env::temp_dir().join(format!("kpm-sdk-log-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.log");
        let _ = std::fs::remove_file(&path);
        let l = Logger::at(&path);
        l.line("one");
        l.line("two");
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].ends_with("Z one"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
