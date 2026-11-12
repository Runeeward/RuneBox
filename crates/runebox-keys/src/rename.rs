//! The fallback from paths named `runeward` before v0.4.4.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Mutex;

/// Returns `new`, or `old` while only the pre-v0.4.4 `old` path exists, so
/// state, keys and logins made by v0.4.3 are not lost. Prints one line per
/// path asking for the rename. Remove once v0.4.3 installs have moved.
pub fn renamed_path(new: PathBuf, old: PathBuf) -> PathBuf {
    if new.exists() || !old.exists() {
        return new;
    }
    static WARNED: Mutex<Option<HashSet<PathBuf>>> = Mutex::new(None);
    let mut warned = WARNED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if warned.get_or_insert_with(HashSet::new).insert(old.clone()) {
        eprintln!(
            "runebox: using {}; rename it to {}",
            old.display(),
            new.display()
        );
    }
    old
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_new_and_falls_back_to_old_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (new, old) = (dir.path().join("runebox"), dir.path().join("runeward"));
        assert_eq!(renamed_path(new.clone(), old.clone()), new);
        std::fs::create_dir(&old).expect("old");
        assert_eq!(renamed_path(new.clone(), old.clone()), old);
        std::fs::create_dir(&new).expect("new");
        assert_eq!(renamed_path(new.clone(), old), new);
    }
}
