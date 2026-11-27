//! First-run commands: `init` (starter Charter) and `quickstart` (starter
//! Charter plus an allow/deny/audit proof). `doctor` lives in
//! [`crate::doctor`].

use std::io::Write;

use anyhow::{Result, anyhow, bail};
use runebox_charter::Verdict;
use runebox_controlplane::{CreateOptions, Manager};

use crate::common::{go_dir, go_io_error, go_join, go_quote, manager_config_dir};
use crate::signing::mkdir_all;

/// The Charter written by `init` and `quickstart`.
pub const STARTER_CHARTER: &str = r#"# Rune Box starter policy (a "Charter").
# Common terms come first: this file defines one governed AI-agent sandbox.
policy_default = "allow"

[host]
type    = "container"
image   = "ghcr.io/runeeward/runebox-sandbox:v0.4.4@sha256:2d474e36f9e26cff4b14757ab4c26dd239e91c14d4b05ca2220fdb7fec7759c1"
workdir = "/workspace"

# Start with no outbound network access. Add only the hosts the task needs.
[network]
default = "deny"

# Keep strict validation useful while preserving deny-by-default egress.
[[network.rule]]
verdict  = "allow"
hostname = "example.com"

# Demonstrates deterministic pre-execution blocking.
[[policy]]
tool    = "shell"
match   = "rm -rf *"
verdict = "deny"
reason  = "recursive force delete blocked by the starter policy"

# Keep ordinary local work usable while the starter policy stays understandable.
[[policy]]
tool    = "shell"
match   = "*"
verdict = "allow"

[[policy]]
tool    = "file.write"
match   = "/workspace/**"
verdict = "allow"

[[policy]]
tool    = "file.write"
match   = "*"
verdict = "require-approval"
reason  = "writes outside /workspace require human approval"

[rationing]
wall_clock = "30m"
max_execs  = 200

[chronicle]
redact = true
"#;

#[cfg(unix)]
fn chmod(path: &str, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn chmod(_path: &str, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

/// Writes the starter Charter to `<project_dir>/.runebox/<name>.toml`
/// (0600 in a 0700 directory). An existing file is kept (and re-secured)
/// unless `force`. Returns the path and whether it was written.
pub fn write_starter_charter(project_dir: &str, name: &str, force: bool) -> Result<(String, bool)> {
    write_starter_into(&go_join(&[project_dir, ".runebox"]), name, force)
}

/// Writes the starter Charter to `<config_dir>/<name>.toml`, with the same
/// modes and rules as [`write_starter_charter`].
pub fn write_starter_into(config_dir: &str, name: &str, force: bool) -> Result<(String, bool)> {
    let name = name.trim();
    if name.is_empty() || name.contains(['/', '\\']) || name == "." || name == ".." {
        bail!("invalid starter policy name {}", go_quote(name));
    }
    mkdir_all(config_dir, 0o700).map_err(|e| {
        anyhow!(
            "create {config_dir}: {}",
            go_io_error("mkdir", config_dir, &e)
        )
    })?;
    chmod(config_dir, 0o700).map_err(|e| {
        anyhow!(
            "secure {config_dir}: {}",
            go_io_error("chmod", config_dir, &e)
        )
    })?;
    let path = go_join(&[config_dir, &format!("{name}.toml")]);
    match std::fs::metadata(&path) {
        Ok(_) if !force => {
            chmod(&path, 0o600)
                .map_err(|e| anyhow!("secure {path}: {}", go_io_error("chmod", &path, &e)))?;
            return Ok((path, false));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => bail!(go_io_error("stat", &path, &e)),
    }
    crate::signing::write_file(&path, STARTER_CHARTER.as_bytes(), 0o600)
        .map_err(|e| anyhow!("write {path}: {e}"))?;
    chmod(&path, 0o600)
        .map_err(|e| anyhow!("secure {path}: {}", go_io_error("chmod", &path, &e)))?;
    Ok((path, true))
}

/// `runebox init [project-dir]`.
pub fn init(dir: Option<&str>, name: &str, force: bool) -> Result<()> {
    let dir = dir.unwrap_or(".");
    let (path, created) = write_starter_charter(dir, name, force)?;
    let verb = if created { "created" } else { "already exists" };
    let config = go_quote(&go_dir(&path));
    println!("{verb}: {path}");
    println!(
        "next: runebox --config-dir {config} doctor {name} && runebox --config-dir {config} enter {name} -- echo hello"
    );
    Ok(())
}

/// `runebox quickstart [project-dir]`.
pub async fn quickstart(dir: Option<&str>, no_run: bool, force: bool) -> Result<()> {
    let dir = dir.unwrap_or(".");
    let (path, _) = write_starter_charter(dir, "quickstart", force)?;
    println!("starter policy: {path}");
    if no_run {
        println!(
            "setup complete; run `runebox doctor quickstart` when your container engine is ready"
        );
        return Ok(());
    }
    let config_dir = go_join(&[dir, ".runebox"]);
    let diagnosis = crate::doctor::run_doctor(&config_dir, "quickstart").await;
    if !diagnosis.ready {
        print!("{}", crate::doctor::render_checks(&diagnosis.checks));
        bail!("quickstart is not ready; start the container engine and retry (or use --no-run)");
    }
    run_quickstart_proof(&config_dir).await
}

/// Creates a sandbox from the starter Charter, runs an allowed command,
/// proves a destructive one is denied, and verifies the signed Chronicle.
async fn run_quickstart_proof(config_dir: &str) -> Result<()> {
    let mgr = Manager::open(manager_config_dir(config_dir)).await?;
    let result = quickstart_proof(&mgr).await;
    let _ = mgr.close().await;
    result
}

async fn quickstart_proof(mgr: &Manager) -> Result<()> {
    let sb = mgr
        .create_sandbox("quickstart", CreateOptions::default())
        .await?;
    let result = async {
        let allowed = mgr
            .shell(
                &sb.id,
                &argv(&["sh", "-lc", "echo 'allow: sandbox command executed'"]),
                "/workspace",
            )
            .await?;
        print!("{}", allowed.stdout);
        std::io::stdout().flush()?;
        let denied = mgr
            .shell(
                &sb.id,
                &argv(&["rm", "-rf", "/tmp/runebox-proof"]),
                "/workspace",
            )
            .await?;
        if denied.verdict != Verdict::Deny {
            bail!(
                "starter policy proof failed: destructive command verdict was {}",
                go_quote(denied.verdict.as_str())
            );
        }
        println!("deny: {}", denied.reason);
        mgr.verify_ledger().await?;
        println!("audit: signed Chronicle verified for sandbox {}", sb.id);
        println!("next: runebox --config-dir .runebox serve");
        Ok(())
    }
    .await;
    let _ = mgr.kill_sandbox(&sb.id).await;
    result
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| (*s).to_owned()).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn mode(path: &str) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn write_starter_charter_creates_a_strict_private_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_string_lossy().into_owned();
        let (path, created) = write_starter_charter(&dir, "quickstart", false).unwrap();
        assert!(created, "starter should be created");
        assert_eq!(path, go_join(&[&dir, ".runebox", "quickstart.toml"]));
        #[cfg(unix)]
        {
            assert_eq!(mode(&go_dir(&path)), 0o700);
            assert_eq!(mode(&path), 0o600);
        }
        let p = runebox_charter::load(
            "quickstart",
            &runebox_charter::Options {
                working_dir: Some(tmp.path().to_path_buf()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(p.host.image, runebox_charter::DEFAULT_SANDBOX_IMAGE);
        assert_eq!(p.network.default, "deny");
        let findings = runebox_charter::lint(&p);
        assert!(
            findings.is_empty(),
            "starter must pass strict validation, findings: {findings:?}"
        );

        std::fs::write(&path, "sentinel").unwrap();
        #[cfg(unix)]
        {
            chmod(&go_dir(&path), 0o755).unwrap();
            chmod(&path, 0o644).unwrap();
        }
        let (_, created) = write_starter_charter(&dir, "quickstart", false).unwrap();
        assert!(!created, "existing file must not be recreated");
        assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), "sentinel");
        #[cfg(unix)]
        {
            assert_eq!(mode(&go_dir(&path)), 0o700);
            assert_eq!(mode(&path), 0o600);
        }
    }

    #[test]
    fn starter_names_must_be_plain() {
        for bad in ["", "a/b", "a\\b", ".", ".."] {
            assert!(write_starter_charter(".", bad, false).is_err(), "{bad:?}");
        }
    }
}
