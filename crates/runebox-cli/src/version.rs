//! The build version reported by `runebox version` and embedded in
//! evidence and telemetry.

/// `$RUNEBOX_VERSION` at build time, else the package version plus the git
/// commit (see `build.rs`).
pub const VERSION: &str = env!("RUNEBOX_BUILD_VERSION");

/// `runebox version`.
pub fn print() {
    println!("runebox {VERSION}");
}
