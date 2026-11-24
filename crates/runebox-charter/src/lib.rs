//! Charters: the declarative security contract a Rune Box session runs under.
//!
//! A Charter (called a "profile" in the Go implementation and on the wire) is
//! resolved by name from `.runebox/` or the user config dir, decoded strictly
//! from TOML, YAML or JSON, defaulted and validated. [`lint`] then reports
//! softer misconfigurations, [`print`] renders a redacted human view, and
//! [`Signature`] implements the detached `runebox.profile.sig.v1` envelope
//! that signed-Charter enforcement checks before decoding.

mod duration;
mod governance;
mod lint;
mod load;
mod print;
mod runtimes;
mod schema;
mod signature;
mod tabwriter;
pub mod templates;
mod validate;

pub use duration::{DurationError, parse_duration, parse_go_duration};
pub use governance::{
    Credential, Endpoint, Filesystem, Isolation, IsolationLevel, MIN_IDLE_TIMEOUT, Process,
    RequestRule, Schedule, Workspace,
};
pub use lint::{Finding, Severity, lint};
pub use load::{
    CHARTER_EXTENSIONS, LoadError, Options, REQUIRE_SIGNED_ENV, SignatureFailure, SignedCharters,
    VERIFY_KEY_ENV, list, load, parse_bytes, parse_file,
};
pub use print::{REDACTED, print, render};
pub use runtimes::{FIRECRACKER_NO_SHARED_FS, KRUN_NO_EXEC, RuntimeFamily, is_engine_name};
pub use schema::{
    Audit, CelRule, Charter, EnvVar, File, Fleet, Host, HostType, Ide, Limits, Network,
    NetworkRule, PolicyBundle, PolicyRule, Prompt, RegoPolicy, Verdict,
};
pub use signature::{SIGNATURE_FORMAT, Signature, SignatureError, sign, verify};
pub use validate::ValidationError;

/// The image a Charter without `host.image` runs, pinned by digest.
pub const DEFAULT_SANDBOX_IMAGE: &str = "ghcr.io/runeeward/runebox-sandbox:v0.4.4@sha256:2d474e36f9e26cff4b14757ab4c26dd239e91c14d4b05ca2220fdb7fec7759c1";

/// Host uid reserved for the strict-mode egress proxy; sandboxes may not run
/// as it, because iptables exempts its traffic from interception.
pub const STRICT_PROXY_UID: u32 = 1337;

#[cfg(test)]
mod examples_tests;
