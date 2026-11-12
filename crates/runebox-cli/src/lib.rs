//! The `runebox` command-line interface for Rune Box.
//!
//! Every command, flag, environment variable, default and exit code of the
//! Go CLI is kept: a bare `runebox <charter>` means `enter <charter>`,
//! `-c/--config-dir` (or `$RUNEBOX_CONFIG_DIR`) pins Charter resolution,
//! and any failure prints `error: <message>` and exits 1. Human-readable
//! output (tables, `validate`, `doctor`, `version`, verification messages)
//! is byte-compatible with the Go binary; the golden tests under `tests/`
//! hold recorded Go output.

mod audit;
mod auth;
mod cli;
mod cohort;
mod common;
mod efficiency;
mod enter;
mod inspect;
mod kube;
mod onboarding;
mod policy;
mod remote;
mod runtime;
mod serve;
mod signing;
mod tabwriter;
mod version;

pub use cli::{Cli, RESERVED, execute, rewrite_for_enter};
pub use version::VERSION;
