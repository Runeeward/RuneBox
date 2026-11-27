//! `runebox doctor` (readiness checks) and `runebox fix` (safe local
//! repairs for what doctor found).
//!
//! Every check has a stable ID (see [`ids`]); `--json`, `fix --check` and
//! the docs refer to checks by it. Doctor changes nothing. A check that has
//! a safe repair records it as an [`Action`], and `fix` applies those only
//! with `--yes`. Repairs are local and reversible, and stay inside the
//! configuration and state directories.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, bail};
use runebox_charter::{Charter, HostType, Severity};
use runebox_controlplane::ManagerConfig;
use serde::Serialize;

use crate::common::{
    charter_options, expand_home, go_io_error, go_join, go_quote, resolve_config_dir,
};
use crate::signing::mkdir_all;
use crate::version::VERSION;

/// Stable check IDs, in report order. Never rename one: scripts match on
/// them.
pub mod ids {
    /// The CLI version (always ok).
    pub const VERSION: &str = "cli.version";
    /// Charter directories and files are not writable by group or others.
    pub const CONFIG_DIR: &str = "config.dir";
    /// At least one Charter is on the search path.
    pub const POLICIES: &str = "config.policies";
    /// The state directory exists, is private and is writable.
    pub const STATE_DIR: &str = "state.dir";
    /// The selected Charter loads and passes lint.
    pub const CHARTER: &str = "charter.lint";
    /// The Charter's runtime backend is reachable.
    pub const RUNTIME: &str = "runtime.backend";
    /// Every `[[env]]` secret source resolves.
    pub const SECRETS: &str = "secrets.sources";
    /// The sandbox image is a published reference.
    pub const IMAGE: &str = "image.reference";

    /// Every ID, in report order.
    pub const ALL: &[&str] = &[
        VERSION, CONFIG_DIR, POLICIES, STATE_DIR, CHARTER, RUNTIME, SECRETS, IMAGE,
    ];
}

const OK: &str = "ok";
const WARN: &str = "warn";
const FAIL: &str = "fail";

/// One readiness check reported by `doctor`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DoctorCheck {
    /// Stable ID (see [`ids`]).
    pub id: String,
    /// Short name, kept for readers of the older `--json` output.
    pub name: String,
    /// `ok`, `warn` or `fail`.
    pub status: String,
    /// Details.
    pub message: String,
    /// The repair `runebox fix` would make, when a safe one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

/// A safe, local repair for a check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Create a directory, private (0700).
    CreateDir(PathBuf),
    /// Set a path's permission bits.
    Chmod(PathBuf, u32),
    /// Write the starter Charter (`quickstart`) into this directory.
    WriteStarter(PathBuf),
}

impl Action {
    /// One line saying what the repair changes.
    pub fn describe(&self) -> String {
        match self {
            Self::CreateDir(path) => format!("create {} (mode 0700)", path.display()),
            Self::Chmod(path, mode) => format!("chmod {mode:04o} {}", path.display()),
            Self::WriteStarter(dir) => format!(
                "write the starter policy {}",
                dir.join("quickstart.toml").display()
            ),
        }
    }

    fn apply(&self) -> Result<()> {
        match self {
            Self::CreateDir(path) => {
                let dir = path.to_string_lossy();
                mkdir_all(&dir, 0o700).map_err(|e| anyhow!(go_io_error("mkdir", &dir, &e)))?;
                chmod(path, 0o700)
            }
            Self::Chmod(path, mode) => chmod(path, *mode),
            Self::WriteStarter(dir) => {
                crate::onboarding::write_starter_into(&dir.to_string_lossy(), "quickstart", false)
                    .map(|_| ())
            }
        }
    }
}

/// A repair and the check it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repair {
    /// The check ID.
    pub check: &'static str,
    /// What the repair does.
    pub action: Action,
}

/// What `doctor` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnosis {
    /// The checks, in report order.
    pub checks: Vec<DoctorCheck>,
    /// Safe repairs for checks that are not ok.
    pub repairs: Vec<Repair>,
    /// No check failed.
    pub ready: bool,
}

impl Diagnosis {
    fn new() -> Self {
        Self {
            checks: Vec::new(),
            repairs: Vec::new(),
            ready: true,
        }
    }

    fn push(
        &mut self,
        id: &'static str,
        status: &str,
        message: impl Into<String>,
        repairs: Vec<Action>,
    ) {
        if status == FAIL {
            self.ready = false;
        }
        let fix = (!repairs.is_empty()).then(|| {
            repairs
                .iter()
                .map(Action::describe)
                .collect::<Vec<_>>()
                .join("; ")
        });
        self.repairs.extend(
            repairs
                .into_iter()
                .map(|action| Repair { check: id, action }),
        );
        self.checks.push(DoctorCheck {
            id: id.into(),
            name: short_name(id).into(),
            status: status.into(),
            message: message.into(),
            fix,
        });
    }

    /// The check with this ID, if it ran.
    #[cfg(test)]
    fn check(&self, id: &str) -> Option<&DoctorCheck> {
        self.checks.iter().find(|c| c.id == id)
    }
}

/// The pre-ID check names, still reported as `name`.
fn short_name(id: &str) -> &str {
    match id {
        ids::VERSION => "version",
        ids::CONFIG_DIR => "config",
        ids::POLICIES => "policies",
        ids::STATE_DIR => "state",
        ids::CHARTER => "charter",
        ids::RUNTIME => "runtime",
        ids::SECRETS => "secrets",
        ids::IMAGE => "image",
        other => other,
    }
}

#[cfg(unix)]
fn chmod(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| {
        let p = path.to_string_lossy();
        anyhow!(go_io_error("chmod", &p, &e))
    })
}

#[cfg(not(unix))]
fn chmod(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

fn marker(status: &str) -> &'static str {
    match status {
        OK => "[ok]",
        WARN => "[warn]",
        _ => "[fail]",
    }
}

/// The text report: one line per check, plus the repair `fix` would make.
pub fn render_checks(checks: &[DoctorCheck]) -> String {
    let mut out = String::new();
    for c in checks {
        out.push_str(&format!(
            "{:<6} {:<16} {}\n",
            marker(&c.status),
            c.id,
            c.message
        ));
        if let Some(fix) = &c.fix {
            out.push_str(&format!("{:<6} {:<16} fix: {fix}\n", "", ""));
        }
    }
    out
}

#[derive(Serialize)]
struct DoctorReport<'a> {
    checks: &'a [DoctorCheck],
    ready: bool,
}

/// `runebox doctor [charter]`.
pub async fn doctor(name: Option<&str>, as_json: bool, config_dir: &str) -> Result<()> {
    let d = run_doctor(&resolve_config_dir(config_dir), name.unwrap_or("")).await;
    let mut stdout = std::io::stdout().lock();
    if as_json {
        runebox_ledger::gojson::encode_indent(
            &mut stdout,
            &DoctorReport {
                checks: &d.checks,
                ready: d.ready,
            },
        )?;
    } else {
        stdout.write_all(render_checks(&d.checks).as_bytes())?;
        if !d.repairs.is_empty() {
            writeln!(
                stdout,
                "run `runebox fix` to see the repairs, `--yes` to apply"
            )?;
        }
    }
    if !d.ready {
        bail!("setup is not ready; fix the failed checks above");
    }
    Ok(())
}

/// `runebox fix [charter] [--check ID]... [--dry-run] [--yes]`.
pub async fn fix(
    name: Option<&str>,
    only: &[String],
    dry_run: bool,
    yes: bool,
    config_dir: &str,
) -> Result<()> {
    for id in only {
        if !ids::ALL.contains(&id.as_str()) {
            bail!(
                "unknown check {}; known checks: {}",
                go_quote(id),
                ids::ALL.join(", ")
            );
        }
    }
    let config_dir = resolve_config_dir(config_dir);
    let name = name.unwrap_or("");
    let d = run_doctor(&config_dir, name).await;
    let wanted = |id: &str| only.is_empty() || only.iter().any(|o| o == id);
    let plan: Vec<&Repair> = d.repairs.iter().filter(|r| wanted(r.check)).collect();
    let manual: Vec<&DoctorCheck> = d
        .checks
        .iter()
        .filter(|c| c.status != OK && c.fix.is_none() && wanted(&c.id))
        .collect();

    let mut out = std::io::stdout().lock();
    for r in &plan {
        writeln!(out, "{:<7} {:<16} {}", "plan", r.check, r.action.describe())?;
    }
    for c in &manual {
        writeln!(out, "{:<7} {:<16} {}", "manual", c.id, c.message)?;
    }
    if plan.is_empty() {
        writeln!(out, "nothing to repair")?;
        if manual.iter().any(|c| c.status == FAIL) {
            bail!("setup is not ready; the checks above need manual steps");
        }
        return Ok(());
    }
    if dry_run {
        writeln!(out, "dry run: nothing changed")?;
        return Ok(());
    }
    if !yes {
        writeln!(out, "nothing changed; run again with --yes to apply")?;
        return Ok(());
    }

    let mut failed = 0;
    for r in &plan {
        match r.action.apply() {
            Ok(()) => writeln!(
                out,
                "{:<7} {:<16} {}",
                "fixed",
                r.check,
                r.action.describe()
            )?,
            Err(e) => {
                failed += 1;
                writeln!(
                    out,
                    "{:<7} {:<16} {}: {e}",
                    "failed",
                    r.check,
                    r.action.describe()
                )?;
            }
        }
    }
    writeln!(out)?;
    let after = run_doctor(&config_dir, name).await;
    out.write_all(render_checks(&after.checks).as_bytes())?;
    if failed > 0 {
        bail!("{failed} of {} repairs failed", plan.len());
    }
    if !after.ready {
        bail!("setup is still not ready; see the checks above");
    }
    Ok(())
}

/// Runs every readiness check.
pub async fn run_doctor(config_dir: &str, requested: &str) -> Diagnosis {
    let state_dir = ManagerConfig::from_env().state_dir.unwrap_or_default();
    let mut d = local_checks(config_dir, &state_dir);
    let opts = charter_options(config_dir);
    let names = runebox_charter::list(&opts);
    if names.is_empty() {
        return d;
    }

    let name = if requested.is_empty() {
        preferred_doctor_profile(&names, config_dir)
    } else {
        requested.to_owned()
    };
    let p = match runebox_charter::load(&name, &opts) {
        Ok(p) => p,
        Err(e) => {
            d.push(ids::CHARTER, FAIL, e.to_string(), vec![]);
            return d;
        }
    };
    let findings = runebox_charter::lint(&p);
    let errs = findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .count();
    let warns = findings.len() - errs;
    let status = if errs > 0 {
        FAIL
    } else if warns > 0 {
        WARN
    } else {
        OK
    };
    d.push(
        ids::CHARTER,
        status,
        format!("{name} ({errs} errors, {warns} warnings)"),
        vec![],
    );

    match runebox_backend::for_charter(&p).await {
        Ok(be) => d.push(ids::RUNTIME, OK, format!("{} reachable", be.name()), vec![]),
        Err(e) => d.push(
            ids::RUNTIME,
            FAIL,
            friendly_runtime_error(&e.to_string()),
            vec![],
        ),
    }
    match check_profile_prerequisites(&p).await {
        Ok(()) => d.push(
            ids::SECRETS,
            OK,
            "required environment and secret sources resolved",
            vec![],
        ),
        Err(e) => d.push(ids::SECRETS, FAIL, e, vec![]),
    }
    let image = &p.host.image;
    if image.ends_with(":dev") || !image.contains('/') {
        d.push(
            ids::IMAGE,
            WARN,
            format!("{image} (local/development image; prefer a published immutable reference)"),
            vec![],
        );
    } else {
        d.push(ids::IMAGE, OK, image.clone(), vec![]);
    }
    d
}

/// The checks that need neither a Charter nor a runtime: the CLI version,
/// the configuration directories, the policies and the state directory.
pub fn local_checks(config_dir: &str, state_dir: &Path) -> Diagnosis {
    let mut d = Diagnosis::new();
    d.push(ids::VERSION, OK, VERSION, vec![]);
    let opts = charter_options(config_dir);
    check_config_dirs(&mut d, &runebox_charter::search_path(&opts));
    let names = runebox_charter::list(&opts);
    if names.is_empty() {
        d.push(
            ids::POLICIES,
            FAIL,
            "no policies found; run `runebox init`",
            vec![Action::WriteStarter(starter_dir(config_dir))],
        );
    } else {
        d.push(ids::POLICIES, OK, format!("{} found", names.len()), vec![]);
    }
    check_state_dir(&mut d, state_dir);
    d
}

/// Where a missing starter policy goes: the configuration directory, or the
/// project's `.runebox` as `runebox init` uses.
fn starter_dir(config_dir: &str) -> PathBuf {
    if config_dir.is_empty() {
        PathBuf::from(".runebox")
    } else {
        PathBuf::from(config_dir)
    }
}

#[cfg(unix)]
fn mode_bits(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o7777
}

/// Charter directories and files writable by group or others let another
/// user change the policy. Symlinks are left alone: a repair never follows
/// one out of the directory.
#[cfg(unix)]
fn check_config_dirs(d: &mut Diagnosis, dirs: &[PathBuf]) {
    use runebox_charter::CHARTER_EXTENSIONS;
    const OTHERS_WRITE: u32 = 0o022;
    let mut repairs = Vec::new();
    let mut found = 0;
    for dir in dirs {
        let Ok(meta) = std::fs::symlink_metadata(dir) else {
            continue;
        };
        if !meta.is_dir() {
            continue;
        }
        found += 1;
        let mode = mode_bits(&meta);
        if mode & OTHERS_WRITE != 0 {
            repairs.push(Action::Chmod(dir.clone(), mode & !OTHERS_WRITE));
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        let mut files: Vec<(PathBuf, u32)> = entries
            .flatten()
            .filter_map(|e| {
                let path = e.path();
                let ext = path.extension()?.to_str()?;
                if !CHARTER_EXTENSIONS.contains(&format!(".{ext}").as_str()) {
                    return None;
                }
                let meta = std::fs::symlink_metadata(&path).ok()?;
                meta.is_file().then(|| (path, mode_bits(&meta)))
            })
            .filter(|(_, mode)| mode & OTHERS_WRITE != 0)
            .collect();
        files.sort();
        repairs.extend(
            files
                .into_iter()
                .map(|(path, mode)| Action::Chmod(path, mode & !OTHERS_WRITE)),
        );
    }
    if found == 0 {
        // The policies check already says there is nothing to load.
        return;
    }
    if repairs.is_empty() {
        d.push(
            ids::CONFIG_DIR,
            OK,
            "Charters are not writable by group or others",
            vec![],
        );
    } else {
        d.push(
            ids::CONFIG_DIR,
            WARN,
            format!(
                "{} Charter paths are writable by group or others, who could change the policy",
                repairs.len()
            ),
            repairs,
        );
    }
}

#[cfg(not(unix))]
fn check_config_dirs(_d: &mut Diagnosis, _dirs: &[PathBuf]) {}

/// The state directory holds the signed ledger and keys: it must be a
/// writable directory that only its owner can read.
fn check_state_dir(d: &mut Diagnosis, dir: &Path) {
    let shown = dir.to_string_lossy().into_owned();
    if shown.is_empty() {
        d.push(
            ids::STATE_DIR,
            FAIL,
            "no state directory; set $RUNEBOX_STATE_DIR",
            vec![],
        );
        return;
    }
    let meta = match std::fs::metadata(dir) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            d.push(
                ids::STATE_DIR,
                WARN,
                format!("{shown} does not exist yet; it is created on first use"),
                vec![Action::CreateDir(dir.to_path_buf())],
            );
            return;
        }
        Err(e) => {
            d.push(
                ids::STATE_DIR,
                FAIL,
                go_io_error("stat", &shown, &e),
                vec![],
            );
            return;
        }
    };
    if !meta.is_dir() {
        d.push(
            ids::STATE_DIR,
            FAIL,
            format!("{shown} is not a directory"),
            vec![],
        );
        return;
    }
    if let Err(e) = probe_writable(&shown) {
        d.push(ids::STATE_DIR, FAIL, e, vec![]);
        return;
    }
    #[cfg(unix)]
    {
        let mode = mode_bits(&meta);
        if mode & 0o077 != 0 {
            d.push(
                ids::STATE_DIR,
                WARN,
                format!(
                    "{shown} is open to group or others (mode {mode:04o}); it holds the signed ledger and keys"
                ),
                vec![Action::Chmod(dir.to_path_buf(), 0o700)],
            );
            return;
        }
    }
    d.push(ids::STATE_DIR, OK, shown, vec![]);
}

/// Proves a file can be created and removed in `dir`.
fn probe_writable(dir: &str) -> Result<(), String> {
    let probe = tempfile::Builder::new()
        .prefix(".doctor-")
        .tempfile_in(dir)
        .map_err(|e| {
            format!(
                "state directory {dir} is not writable: {}",
                go_io_error("open", &go_join(&[dir, ".doctor-*"]), &e)
            )
        })?;
    let name = probe.path().to_string_lossy().into_owned();
    probe.close().map_err(|e| {
        format!(
            "remove state-directory probe {name}: {}",
            go_io_error("remove", &name, &e)
        )
    })
}

/// Resolves every `[[env]]` source without exposing values, failing closed
/// like the control plane does when it provisions a sandbox.
async fn check_profile_prerequisites(p: &Charter) -> Result<(), String> {
    let resolver = runebox_secrets::Dispatcher::from_env();
    for e in &p.env {
        if !e.op.is_empty() {
            resolver.resolve(&e.op).await.map_err(|err| {
                format!(
                    "env {}: resolve {}: {err}",
                    go_quote(&e.name),
                    go_quote(&e.op)
                )
            })?;
        } else if !e.file.is_empty() {
            let path = expand_home(&e.file);
            std::fs::read(&path).map_err(|err| {
                format!(
                    "env {}: read file {}: {}",
                    go_quote(&e.name),
                    go_quote(&e.file),
                    go_io_error("open", &path, &err)
                )
            })?;
        }
    }
    Ok(())
}

/// Picks the Charter to check: a well-known starter name, else the first
/// container-hosted Charter, else the first name.
fn preferred_doctor_profile(names: &[String], config_dir: &str) -> String {
    for preferred in ["quickstart", "dev", "ns-auto"] {
        if names.iter().any(|n| n == preferred) {
            return preferred.to_owned();
        }
    }
    let mut sorted = names.to_vec();
    sorted.sort();
    let opts = charter_options(config_dir);
    for name in &sorted {
        if let Ok(p) = runebox_charter::load(name, &opts)
            && p.host.host_type == HostType::Container
        {
            return name.clone();
        }
    }
    sorted.first().cloned().unwrap_or_default()
}

/// Shortens an unreachable-engine error to an actionable message without
/// the raw socket detail.
pub fn friendly_runtime_error(msg: &str) -> String {
    if msg.contains("engine not reachable") {
        let short = match msg.find(" (") {
            Some(i) if i > 0 => &msg[..i],
            _ => msg,
        };
        return format!("{short}; start Docker/Podman, then run `runebox doctor` again");
    }
    msg.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local(config: &Path, state: &Path) -> Diagnosis {
        local_checks(&config.to_string_lossy(), state)
    }

    /// Runs doctor, applies every repair for `id`, runs doctor again and
    /// expects that check to be ok.
    fn repair_round_trip(config: &Path, state: &Path, id: &str) {
        let before = local(config, state);
        let check = before.check(id).unwrap();
        assert_ne!(check.status, OK, "{id} should need a repair: {check:?}");
        assert!(check.fix.is_some(), "{id} has no repair: {check:?}");
        for r in before.repairs.iter().filter(|r| r.check == id) {
            r.action.apply().unwrap();
        }
        let after = local(config, state);
        assert_eq!(after.check(id).unwrap().status, OK, "{after:?}");
        assert!(after.repairs.iter().all(|r| r.check != id), "{after:?}");
    }

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        let state = tmp.path().join("state");
        (tmp, config, state)
    }

    #[test]
    fn missing_policy_is_written_by_fix() {
        let (_tmp, config, state) = fixture();
        repair_round_trip(&config, &state, ids::POLICIES);
        assert!(config.join("quickstart.toml").is_file());
    }

    #[test]
    fn missing_state_dir_is_created_by_fix() {
        let (_tmp, config, state) = fixture();
        repair_round_trip(&config, &state, ids::STATE_DIR);
        assert!(state.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn open_state_dir_is_made_private_by_fix() {
        let (_tmp, config, state) = fixture();
        std::fs::create_dir(&state).unwrap();
        chmod(&state, 0o755).unwrap();
        repair_round_trip(&config, &state, ids::STATE_DIR);
        let meta = std::fs::metadata(&state).unwrap();
        assert_eq!(mode_bits(&meta), 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn writable_charters_are_tightened_by_fix() {
        let (_tmp, config, state) = fixture();
        crate::onboarding::write_starter_into(&config.to_string_lossy(), "quickstart", false)
            .unwrap();
        let charter = config.join("quickstart.toml");
        let link = config.join("linked.toml");
        std::os::unix::fs::symlink(&charter, &link).unwrap();
        chmod(&config, 0o777).unwrap();
        chmod(&charter, 0o666).unwrap();
        let before = local(&config, &state);
        assert_eq!(before.check(ids::CONFIG_DIR).unwrap().status, WARN);
        assert!(
            before
                .repairs
                .iter()
                .all(|r| !matches!(&r.action, Action::Chmod(p, _) if p == &link)),
            "a repair followed a symlink: {before:?}"
        );
        repair_round_trip(&config, &state, ids::CONFIG_DIR);
        assert_eq!(mode_bits(&std::fs::metadata(&config).unwrap()), 0o755);
        assert_eq!(mode_bits(&std::fs::metadata(&charter).unwrap()), 0o644);
    }

    #[test]
    fn healthy_local_setup_has_no_repairs() {
        let (_tmp, config, state) = fixture();
        crate::onboarding::write_starter_into(&config.to_string_lossy(), "quickstart", false)
            .unwrap();
        crate::signing::mkdir_all(&state.to_string_lossy(), 0o700).unwrap();
        let d = local(&config, &state);
        assert!(d.ready, "{d:?}");
        assert!(d.repairs.is_empty(), "{d:?}");
        assert!(d.checks.iter().all(|c| c.status == OK), "{d:?}");
    }

    #[test]
    fn ids_are_unique_and_known() {
        let mut seen = std::collections::BTreeSet::new();
        for id in ids::ALL {
            assert!(seen.insert(*id), "duplicate check id {id}");
            assert_ne!(short_name(id), *id, "{id} has no short name");
        }
    }

    #[test]
    fn friendly_runtime_error_redacts_socket_detail() {
        let got = friendly_runtime_error(
            "docker engine not reachable; is docker running? (dial unix /private/path.sock)",
        );
        assert!(
            !got.contains("/private/path.sock"),
            "raw socket path leaked: {got}"
        );
        assert!(
            got.contains("runebox doctor"),
            "missing recovery instruction: {got}"
        );
    }

    #[test]
    fn checks_render_with_ids_and_repairs() {
        let mut d = Diagnosis::new();
        d.push(ids::VERSION, OK, "1.0", vec![]);
        d.push(
            ids::STATE_DIR,
            WARN,
            "x",
            vec![Action::CreateDir(PathBuf::from("/s"))],
        );
        let indent = " ".repeat(24);
        assert_eq!(
            render_checks(&d.checks),
            format!(
                "[ok]   cli.version      1.0\n[warn] state.dir        x\n{indent}fix: create /s (mode 0700)\n"
            )
        );
    }
}
