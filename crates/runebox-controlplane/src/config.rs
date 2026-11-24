//! Operator settings, read once from `RUNEBOX_*` variables.

use std::path::PathBuf;
use std::time::Duration;

use runebox_charter::SignedCharters;

/// Overrides the state directory (ledger, keys, `runs.json`, ...).
pub const STATE_DIR_ENV: &str = "RUNEBOX_STATE_DIR";
/// `off` disables ledger signing.
pub const LEDGER_SIGN_ENV: &str = "RUNEBOX_LEDGER_SIGN";
/// Directory for the ledger signing key (default `keys/` beside the
/// ledger). Point it at a path the ledger's writers can't reach.
pub const LEDGER_KEY_DIR_ENV: &str = "RUNEBOX_LEDGER_KEY_DIR";
/// File the ledger head is appended to periodically (off when unset). Put
/// it on storage the node can append to but not rewrite.
pub const LEDGER_ANCHOR_ENV: &str = "RUNEBOX_LEDGER_ANCHOR";
/// How often the head is anchored (Go duration; default 5m).
pub const LEDGER_ANCHOR_INTERVAL_ENV: &str = "RUNEBOX_LEDGER_ANCHOR_INTERVAL";
/// Cohort claim lease (Go duration; `0`/`off`/`none` disables expiry).
pub const FLEET_LEASE_ENV: &str = "RUNEBOX_FLEET_LEASE";
/// Ignores client-reported usage when enforcing budgets.
pub const IGNORE_CLIENT_USAGE_ENV: &str = "RUNEBOX_IGNORE_CLIENT_USAGE";
/// `1` enables the experimental in-sandbox browser.
pub const EXPERIMENTAL_BROWSER_ENV: &str = "RUNEBOX_ENABLE_EXPERIMENTAL_BROWSER";
/// `1` enables the experimental browser IDE.
pub const EXPERIMENTAL_IDE_ENV: &str = "RUNEBOX_ENABLE_EXPERIMENTAL_IDE";
/// `0` keeps Chromium's own sandbox (drops `--no-sandbox`).
pub const BROWSER_NO_SANDBOX_ENV: &str = "RUNEBOX_BROWSER_NO_SANDBOX";
/// A PEM file of extra roots the request broker trusts towards inspected
/// upstreams (internal APIs behind a private CA), on top of the Mozilla
/// roots.
pub const BROKER_UPSTREAM_CA_ENV: &str = "RUNEBOX_BROKER_UPSTREAM_CA";

/// Control-plane settings. [`ManagerConfig::from_env`] reads them the way
/// the Go control plane does; tests build one with
/// [`ManagerConfig::from_lookup`] or by hand.
#[derive(Debug, Clone)]
pub struct ManagerConfig {
    /// Pins Charter resolution to one directory (`--config-dir`).
    pub config_dir: Option<PathBuf>,
    /// Holds the ledger, signing and lease keys and every state file. `None`
    /// disables persistence of runs, Cohorts, snapshots and agent sessions.
    pub state_dir: Option<PathBuf>,
    /// Signs ledger records (default on).
    pub sign_ledger: bool,
    /// Where the signing key lives; `None` is `keys/` beside the ledger.
    pub ledger_key_dir: Option<PathBuf>,
    /// The anchor file the ledger head is appended to; `None` disables it.
    pub ledger_anchor: Option<PathBuf>,
    /// How often the head is anchored.
    pub ledger_anchor_interval: Duration,
    /// How long a require-approval call blocks before returning pending;
    /// `None` waits until the call is dropped.
    pub approval_wait: Option<Duration>,
    /// Cohort claim lease; zero disables expiry.
    pub fleet_lease: Duration,
    /// How often expired Cohort leases are swept; `None` disables the
    /// sweeper.
    pub sweep_interval: Option<Duration>,
    /// `RUNEBOX_POLICY_DEFAULT`: the no-match verdict when a Charter sets
    /// none.
    pub policy_default: Option<String>,
    /// Skips budget enforcement from client-reported usage.
    pub ignore_client_usage: bool,
    /// Enables the experimental browser tools.
    pub experimental_browser: bool,
    /// Enables the experimental browser IDE.
    pub experimental_ide: bool,
    /// Keeps Chromium's sandbox instead of passing `--no-sandbox`.
    pub chromium_sandbox: bool,
    /// Signed-Charter enforcement for Charter loads.
    pub signed_charters: SignedCharters,
    /// Extra upstream roots for request brokers (PEM file).
    pub broker_upstream_ca: Option<PathBuf>,
    /// How long create waits for the in-sandbox supervisor's report.
    pub supervisor_report_wait: Duration,
    /// How often idle persistent workspaces are put to sleep and due
    /// schedules fire; `None` disables both (tests drive them directly).
    pub context_tick: Option<Duration>,
}

impl Default for ManagerConfig {
    /// Defaults with no environment: no persistence, signing on.
    fn default() -> Self {
        Self::from_lookup(|_| None)
    }
}

impl ManagerConfig {
    /// Reads the process environment.
    pub fn from_env() -> Self {
        let mut c = Self::from_lookup(|k| std::env::var(k).ok());
        c.state_dir = Some(default_state_dir(std::env::var(STATE_DIR_ENV).ok()));
        c.signed_charters = SignedCharters::FromEnv;
        c
    }

    /// Reads settings through `lookup`. The state directory is only set when
    /// `RUNEBOX_STATE_DIR` is present.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let get = |k: &str| lookup(k).unwrap_or_default();
        let flag = |k: &str| get(k).trim() == "1";
        Self {
            config_dir: None,
            state_dir: lookup(STATE_DIR_ENV)
                .filter(|s| !s.is_empty())
                .map(PathBuf::from),
            sign_ledger: !get(LEDGER_SIGN_ENV).eq_ignore_ascii_case("off"),
            ledger_key_dir: lookup(LEDGER_KEY_DIR_ENV)
                .filter(|s| !s.trim().is_empty())
                .map(PathBuf::from),
            ledger_anchor: lookup(LEDGER_ANCHOR_ENV)
                .filter(|s| !s.trim().is_empty())
                .map(PathBuf::from),
            ledger_anchor_interval: anchor_interval(&get(LEDGER_ANCHOR_INTERVAL_ENV)),
            approval_wait: Some(Duration::from_secs(5 * 60)),
            fleet_lease: fleet_lease(&get(FLEET_LEASE_ENV)),
            sweep_interval: Some(Duration::from_secs(30)),
            policy_default: lookup(runebox_policy::POLICY_DEFAULT_ENV),
            ignore_client_usage: matches!(
                get(IGNORE_CLIENT_USAGE_ENV).trim().to_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            ),
            experimental_browser: flag(EXPERIMENTAL_BROWSER_ENV),
            experimental_ide: flag(EXPERIMENTAL_IDE_ENV),
            chromium_sandbox: get(BROWSER_NO_SANDBOX_ENV) == "0",
            signed_charters: SignedCharters::from_lookup(&lookup),
            broker_upstream_ca: lookup(BROKER_UPSTREAM_CA_ENV)
                .filter(|s| !s.trim().is_empty())
                .map(PathBuf::from),
            supervisor_report_wait: Duration::from_secs(20),
            context_tick: Some(Duration::from_secs(15)),
        }
    }

    pub(crate) fn charter_options(&self) -> runebox_charter::Options {
        runebox_charter::Options {
            config_dir: self.config_dir.clone(),
            working_dir: None,
            signed: self.signed_charters.clone(),
        }
    }
}

/// `$RUNEBOX_FLEET_LEASE`: default 2m; `0`/`off`/`none` disables; an
/// unparsable value keeps the default.
fn fleet_lease(v: &str) -> Duration {
    let default = Duration::from_secs(120);
    match v.trim().to_lowercase().as_str() {
        "" => return default,
        "0" | "off" | "none" => return Duration::ZERO,
        _ => {}
    }
    runebox_charter::parse_go_duration(v)
        .ok()
        .and_then(|n| u64::try_from(n).ok())
        .map_or(default, Duration::from_nanos)
}

/// `$RUNEBOX_LEDGER_ANCHOR_INTERVAL`: default 5m; an unparsable or
/// non-positive value keeps the default.
fn anchor_interval(v: &str) -> Duration {
    runebox_charter::parse_go_duration(v.trim())
        .ok()
        .and_then(|n| u64::try_from(n).ok())
        .filter(|n| *n > 0)
        .map_or(Duration::from_secs(5 * 60), Duration::from_nanos)
}

/// `$RUNEBOX_STATE_DIR`, else `<user cache dir>/runebox` (or the pre-v0.4.4
/// `<user cache dir>/runeward` while only that exists).
fn default_state_dir(env: Option<String>) -> PathBuf {
    if let Some(d) = env.filter(|d| !d.is_empty()) {
        return PathBuf::from(d);
    }
    let cache = user_cache_dir();
    runebox_keys::renamed_path(cache.join("runebox"), cache.join("runeward"))
}

/// Go's `os.UserCacheDir`, falling back to the temp dir.
fn user_cache_dir() -> PathBuf {
    let home = std::env::home_dir().filter(|h| !h.as_os_str().is_empty());
    if cfg!(target_os = "macos") {
        if let Some(h) = home {
            return h.join("Library").join("Caches");
        }
    } else {
        if let Some(x) = std::env::var_os("XDG_CACHE_HOME")
            && std::path::Path::new(&x).is_absolute()
        {
            return PathBuf::from(x);
        }
        if let Some(h) = home {
            return h.join(".cache");
        }
    }
    std::env::temp_dir()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(pairs: &[(&str, &str)]) -> ManagerConfig {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        ManagerConfig::from_lookup(move |k| {
            pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
        })
    }

    #[test]
    fn fleet_lease_parsing_matches_go() {
        assert_eq!(fleet_lease(""), Duration::from_secs(120));
        assert_eq!(fleet_lease("off"), Duration::ZERO);
        assert_eq!(fleet_lease("None"), Duration::ZERO);
        assert_eq!(fleet_lease("90s"), Duration::from_secs(90));
        assert_eq!(fleet_lease("bogus"), Duration::from_secs(120));
    }

    #[test]
    fn flags() {
        let c = cfg(&[]);
        assert!(c.sign_ledger && !c.experimental_ide && !c.experimental_browser);
        assert!(c.state_dir.is_none());
        assert!(c.ledger_key_dir.is_none() && c.ledger_anchor.is_none());
        assert_eq!(c.ledger_anchor_interval, Duration::from_secs(300));
        let c = cfg(&[
            (LEDGER_KEY_DIR_ENV, "/secure/keys"),
            (LEDGER_ANCHOR_ENV, "/mnt/anchor/head.jsonl"),
            (LEDGER_ANCHOR_INTERVAL_ENV, "30s"),
        ]);
        assert_eq!(c.ledger_key_dir, Some(PathBuf::from("/secure/keys")));
        assert_eq!(
            c.ledger_anchor,
            Some(PathBuf::from("/mnt/anchor/head.jsonl"))
        );
        assert_eq!(c.ledger_anchor_interval, Duration::from_secs(30));
        for bad in ["", "soon", "0s", "-1m"] {
            let c = cfg(&[(LEDGER_ANCHOR_INTERVAL_ENV, bad)]);
            assert_eq!(c.ledger_anchor_interval, Duration::from_secs(300), "{bad}");
        }
        let c = cfg(&[
            (LEDGER_SIGN_ENV, "OFF"),
            (EXPERIMENTAL_IDE_ENV, "1"),
            (EXPERIMENTAL_BROWSER_ENV, " 1 "),
            (IGNORE_CLIENT_USAGE_ENV, "yes"),
            (BROWSER_NO_SANDBOX_ENV, "0"),
            (STATE_DIR_ENV, "/tmp/x"),
        ]);
        assert!(!c.sign_ledger && c.experimental_ide && c.experimental_browser);
        assert!(c.ignore_client_usage && c.chromium_sandbox);
        assert_eq!(c.state_dir, Some(PathBuf::from("/tmp/x")));
        assert_eq!(default_state_dir(Some("/x".into())), PathBuf::from("/x"));
        let dir = default_state_dir(None);
        assert!(dir.ends_with("runebox") || dir.ends_with("runeward"));
    }
}
