//! `runeward policy`: offline simulation (`test`), ready-made templates
//! (`scaffold`), rule suggestions from a verified audit trail (`learn`) and
//! a review of the access a Charter change adds (`diff`).

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::Write as _;
use std::net::IpAddr;

use anyhow::{Result, anyhow, bail};
use runeward_charter::{Charter, Verdict};
use runeward_ledger::evidence;
use runeward_ledger::{Bundle, Event};
use runeward_policy::{Action, Evaluator};
use serde::Deserialize;

use crate::common::{expand_home, go_quote, load_profile, read_file};

// ---------------------------------------------------------------------------
// policy diff

/// What a changed Charter grants beyond the current one.
#[derive(Debug, Default)]
pub struct DiffReport {
    /// One entry per wider dimension (`dimension: reason`).
    pub broader: Vec<String>,
    /// Places a credential is now sent to.
    pub credential_reach: Vec<String>,
}

impl DiffReport {
    /// Whether the change adds no access.
    pub fn is_empty(&self) -> bool {
        self.broader.is_empty() && self.credential_reach.is_empty()
    }
}

/// Compares `old` and `new` for review before a change is approved.
pub fn diff_charters(old: &Charter, new: &Charter) -> DiffReport {
    DiffReport {
        broader: runeward_policy::broadening(old, new, None)
            .iter()
            .map(ToString::to_string)
            .collect(),
        credential_reach: runeward_policy::new_credential_reach(old, new)
            .iter()
            .map(ToString::to_string)
            .collect(),
    }
}

/// Renders a [`DiffReport`] as text (`json = false`) or JSON.
pub fn render_diff(old: &str, new: &str, r: &DiffReport, json: bool) -> String {
    if json {
        let doc = serde_json::json!({
            "old": old,
            "new": new,
            "adds_access": !r.is_empty(),
            "broader": r.broader,
            "credential_reach": r.credential_reach,
        });
        return format!("{doc:#}\n");
    }
    if r.is_empty() {
        return format!("{new} grants nothing {old} does not.\n");
    }
    let mut out = format!("{new} grants access {old} does not:\n");
    for line in r.credential_reach.iter().chain(&r.broader) {
        let _ = writeln!(out, "  - {line}");
    }
    out
}

/// A Charter by name, or from a file path (a proposed change usually is
/// one), named after the file's stem.
fn load_charter_arg(arg: &str, config_dir: &str) -> Result<Charter> {
    let path = std::path::Path::new(arg);
    if path.is_file() {
        let name = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let opts = crate::common::charter_options(config_dir);
        return Ok(runeward_charter::parse_file(path, &name, &opts.signed)?);
    }
    Ok(load_profile(arg, config_dir)?)
}

/// `runeward policy diff <old> <new>`: exits non-zero when `new` adds
/// access, so a change can be held for review in CI.
pub fn diff(old: &str, new: &str, json: bool, config_dir: &str) -> Result<()> {
    let a = load_charter_arg(old, config_dir)?;
    let b = load_charter_arg(new, config_dir)?;
    let r = diff_charters(&a, &b);
    print!("{}", render_diff(old, new, &r, json));
    std::io::stdout().flush()?;
    if !r.is_empty() {
        bail!("{} adds access; review it before approving", go_quote(new));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// policy learn

/// `runeward policy learn <evidence-or-chronicle.json>`.
pub fn learn(path: &str, include_allowed: bool) -> Result<()> {
    let events = read_learning_events(path)?;
    print!("{}", render_learned_policy(&events, include_allowed));
    std::io::stdout().flush()?;
    Ok(())
}

/// Reads the events of a portable evidence package or a signed Chronicle
/// bundle, refusing input whose signatures do not verify.
fn read_learning_events(path: &str) -> Result<Vec<Event>> {
    read_verified_events(path, "learn from")
}

/// Reads the events of a portable evidence package or a signed Chronicle
/// bundle for `purpose` (named in the refusal), refusing input whose
/// signatures do not verify.
pub(crate) fn read_verified_events(path: &str, purpose: &str) -> Result<Vec<Event>> {
    let b = read_file(path).map_err(|e| anyhow!(e))?;
    let envelope: serde_json::Value =
        serde_json::from_slice(&b).map_err(|e| anyhow!("decode audit input: {e}"))?;
    let format = envelope
        .get("format")
        .and_then(|f| f.as_str())
        .unwrap_or_default();
    if !format.is_empty() {
        let doc = evidence::read(b.as_slice())?;
        evidence::verify(&doc)
            .map_err(|e| anyhow!("refusing to {purpose} unverified evidence: {e}"))?;
        return Ok(doc.chronicle.events);
    }
    let bundle: Bundle =
        serde_json::from_slice(&b).map_err(|e| anyhow!("decode audit input: {e}"))?;
    if bundle.events.is_empty() {
        bail!("audit input contains no events");
    }
    bundle
        .verify()
        .map_err(|e| anyhow!("refusing to {purpose} an unverified Chronicle bundle: {e}"))?;
    Ok(bundle.events)
}

/// Renders exact, reviewable rules for the denied and approval-gated (and
/// optionally allowed) actions in `events`.
pub fn render_learned_policy(events: &[Event], include_allowed: bool) -> String {
    // (tool, action, verdict), sorted by tool then action as Go sorts them.
    let mut seen: BTreeSet<(String, String, String)> = BTreeSet::new();
    let mut skipped_redacted = 0;
    for event in events {
        let verdict = event.verdict.as_str();
        if verdict == "allow" && !include_allowed {
            continue;
        }
        if !matches!(verdict, "allow" | "deny" | "require-approval") {
            continue;
        }
        if event.redacted || event.action.trim().is_empty() {
            skipped_redacted += 1;
            continue;
        }
        if event.tool == "approval" || event.tool == "fleet" {
            continue;
        }
        seen.insert((event.tool.clone(), event.action.clone(), verdict.to_owned()));
    }

    let mut out = String::new();
    out.push_str("# Generated by `runeward policy learn`. Review before adding to a Charter.\n");
    out.push_str(
        "# Rules are intentionally exact; broaden globs only when the risk is understood.\n",
    );
    if skipped_redacted > 0 {
        let _ = writeln!(
            out,
            "# Skipped {skipped_redacted} redacted/empty action(s); plaintext is intentionally unavailable."
        );
    }
    if seen.is_empty() {
        out.push_str(
            "# No eligible actions found. Use --include-allowed to include observed allows.\n",
        );
        return out;
    }
    for (tool, action, verdict) in &seen {
        if tool == "net" && valid_exact_hostname(action) {
            out.push_str("\n[[network.rule]]\n");
            let _ = writeln!(out, "verdict  = {}", go_quote(verdict));
            let _ = writeln!(out, "hostname = {}", go_quote(action));
            continue;
        }
        out.push_str("\n[[policy]]\n");
        let _ = writeln!(out, "tool    = {}", go_quote(tool));
        let _ = writeln!(out, "match   = {}", go_quote(action));
        let _ = writeln!(out, "verdict = {}", go_quote(verdict));
        out.push_str(
            "reason  = \"learned from a verified audit trail; reviewed by POLICY_OWNER\"\n",
        );
    }
    out
}

/// Reports whether `s` is a plain DNS name usable as an exact egress rule.
fn valid_exact_hostname(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() || s.contains([' ', '/', ',', '\t', '\n']) {
        return false;
    }
    if s.parse::<IpAddr>().is_ok() {
        return false;
    }
    s.contains('.') && !s.starts_with('.') && !s.ends_with('.')
}

// ---------------------------------------------------------------------------
// policy scaffold

/// `runeward policy scaffold [template]`.
pub fn scaffold(name: Option<&str>, list: bool) -> Result<()> {
    let mut out = String::new();
    match name {
        Some(name) if !list => {
            let body = runeward_charter::templates::render(name)
                .map_err(|e| anyhow!("{e} (see: runeward policy scaffold --list)"))?;
            out.push_str(body);
            out.push('\n');
        }
        _ => {
            out.push_str("Available policy templates:\n");
            for t in runeward_charter::templates::all() {
                let _ = writeln!(out, "  {:<24} {}", t.name, t.title);
            }
            out.push_str("\nPrint one with: runeward policy scaffold <name>\n");
        }
    }
    std::io::stdout().write_all(out.as_bytes())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// policy test

/// One sample action asserted against a Charter's policy (a `[[case]]`
/// table in the `--cases` file).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct PolicyCase {
    /// Optional label used in the PASS/FAIL output.
    pub name: String,
    /// The action surface (`shell`, `file.read`, `net`, ...).
    pub tool: String,
    /// The primary argument (command line, path or hostname).
    pub action: String,
    /// Alias for `action`.
    pub arg: String,
    /// Optional raw argv for argv-aware rules.
    pub args: Vec<String>,
    /// The expected verdict: allow | deny | require-approval.
    pub expect: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct CasesFile {
    #[serde(rename = "case")]
    cases: Vec<PolicyCase>,
}

/// `runeward policy test <charter> --cases <file> [--case ...]`.
pub fn test(name: &str, cases_path: &str, inline: &[String], config_dir: &str) -> Result<()> {
    let p = load_profile(name, config_dir)?;
    let engine = policy_engine_for_profile(&p)?;
    let cases = collect_policy_cases(cases_path, inline)?;
    if cases.is_empty() {
        bail!(
            "no cases provided; pass --cases <file> and/or --case tool=...,action=...,expect=..."
        );
    }
    run_policy_cases(&p.name, engine.as_ref(), &cases)
}

/// Builds the policy engine for a Charter offline. A signed OCI bundle is
/// remote, so it cannot be simulated.
fn policy_engine_for_profile(p: &Charter) -> Result<Box<dyn Evaluator>> {
    if p.uses_policy_bundle() {
        let reference = p
            .policy_bundle
            .as_ref()
            .map(|b| b.r#ref.clone())
            .unwrap_or_default();
        bail!(
            "profile {} sources its policy from an OCI policy bundle ({reference}); bundle-backed policies cannot be simulated offline",
            go_quote(&p.name)
        );
    }
    Ok(runeward_policy::engine_for_charter(p, Verdict::Allow)?)
}

/// Loads cases from the optional TOML file, then appends inline `--case`
/// flags.
fn collect_policy_cases(cases_path: &str, inline: &[String]) -> Result<Vec<PolicyCase>> {
    let mut cases = Vec::new();
    if !cases_path.is_empty() {
        let b = read_file(&expand_home(cases_path)).map_err(|e| anyhow!("read cases file: {e}"))?;
        let doc: CasesFile = toml::from_slice(&b)
            .map_err(|e| anyhow!("parse cases file {}: {e}", go_quote(cases_path)))?;
        cases.extend(doc.cases);
    }
    for spec in inline {
        cases.push(parse_inline_case(spec)?);
    }
    Ok(cases)
}

/// Parses a `key=value,key=value` `--case` flag. Commas always separate
/// pairs, so a value containing one belongs in `--cases`.
pub fn parse_inline_case(spec: &str) -> Result<PolicyCase> {
    let mut c = PolicyCase::default();
    for pair in spec.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let Some((k, v)) = pair.split_once('=') else {
            bail!(
                "invalid --case {}: expected key=value pairs",
                go_quote(spec)
            );
        };
        let v = v.trim().to_owned();
        match k.trim() {
            "name" => c.name = v,
            "tool" => c.tool = v,
            "action" | "arg" => c.action = v,
            "expect" => c.expect = v,
            other => bail!(
                "invalid --case {}: unknown key {}",
                go_quote(spec),
                go_quote(other)
            ),
        }
    }
    Ok(c)
}

/// Evaluates every case, printing a PASS/FAIL line each and a summary;
/// fails when any case fails.
fn run_policy_cases(profile: &str, engine: &dyn Evaluator, cases: &[PolicyCase]) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    writeln!(
        stdout,
        "policy test: charter {}, {} case(s)",
        go_quote(profile),
        cases.len()
    )?;
    let mut failed = 0;
    for (i, c) in cases.iter().enumerate() {
        let want =
            normalize_verdict(&c.expect).map_err(|e| anyhow!("case {}: {e}", case_label(c, i)))?;
        let arg = if c.action.is_empty() {
            c.arg.clone()
        } else {
            c.action.clone()
        };
        let got = engine
            .evaluate(&Action::new(c.tool.clone(), arg.clone()).with_args(c.args.clone()))
            .verdict;
        let status = if got == want {
            "PASS"
        } else {
            failed += 1;
            "FAIL"
        };
        writeln!(
            stdout,
            "  {status}  {}\ttool={} action={} expect={want} got={got}",
            case_label(c, i),
            c.tool,
            go_quote(&arg)
        )?;
    }
    writeln!(stdout, "{} passed, {failed} failed", cases.len() - failed)?;
    if failed > 0 {
        bail!("{failed} of {} policy case(s) failed", cases.len());
    }
    Ok(())
}

/// The case's name, else its 1-based index.
fn case_label(c: &PolicyCase, i: usize) -> String {
    if c.name.trim().is_empty() {
        format!("#{}", i + 1)
    } else {
        c.name.clone()
    }
}

/// Maps user-facing verdict spellings (and a few aliases) to a verdict.
pub fn normalize_verdict(s: &str) -> Result<Verdict> {
    match s.trim().to_lowercase().as_str() {
        "allow" => Ok(Verdict::Allow),
        "deny" => Ok(Verdict::Deny),
        "require-approval" | "require_approval" | "approval" | "approve" => {
            Ok(Verdict::RequireApproval)
        }
        "" => bail!("missing expect verdict (allow|deny|require-approval)"),
        _ => bail!(
            "unknown expect verdict {} (allow|deny|require-approval)",
            go_quote(s)
        ),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn event(tool: &str, action: &str, verdict: &str, redacted: bool) -> Event {
        Event {
            tool: tool.into(),
            action: action.into(),
            verdict: verdict.into(),
            redacted,
            ..Event::default()
        }
    }

    fn charter(toml: &str) -> Charter {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        std::fs::write(&path, toml).unwrap();
        load_charter_arg(path.to_str().unwrap(), "").unwrap()
    }

    const OLD: &str = r#"
[network]
default = "deny"

[[credential]]
name = "gh"
source = "env://GH_TOKEN"
placeholder_env = "GITHUB_TOKEN"

[[endpoint]]
name = "github"
host = "api.github.com"
protocol = "rest"
credential = "gh"
  [[endpoint.allow]]
  method = "GET"
  path = "/repos/**"
"#;

    #[test]
    fn diff_flags_a_new_host_reachable_with_a_credential() {
        let old = charter(OLD);
        assert!(diff_charters(&old, &charter(OLD)).is_empty());
        let new = charter(&format!(
            "{OLD}\n[[endpoint]]\nname = \"uploads\"\nhost = \"uploads.example.test\"\nprotocol = \"rest\"\ncredential = \"gh\"\n  [[endpoint.allow]]\n  method = \"POST\"\n  path = \"/**\"\n"
        ));
        let r = diff_charters(&old, &new);
        assert_eq!(
            r.credential_reach,
            ["credential \"gh\" is sent to uploads.example.test:443 (endpoint \"uploads\")"]
        );
        assert!(
            r.broader.iter().any(|b| b.starts_with("network: ")),
            "{:?}",
            r.broader
        );
        let text = render_diff("old.toml", "new.toml", &r, false);
        assert!(
            text.starts_with("new.toml grants access old.toml does not:\n  - credential"),
            "{text}"
        );
        let json: serde_json::Value =
            serde_json::from_str(&render_diff("old.toml", "new.toml", &r, true)).unwrap();
        assert_eq!(json["adds_access"], true);
        assert_eq!(json["credential_reach"][0], r.credential_reach[0]);
        // The reverse change only removes access.
        let back = diff_charters(&new, &old);
        assert!(back.is_empty(), "{back:?}");
        assert_eq!(
            render_diff("new.toml", "old.toml", &back, false),
            "old.toml grants nothing new.toml does not.\n"
        );
    }

    #[test]
    fn render_learned_policy_is_exact_and_reviewable() {
        let events = [
            event("shell", "terraform apply", "deny", false),
            event("net", "api.openai.com", "allow", false),
            event("file.write", "/workspace/secret", "require-approval", true),
        ];
        let got = render_learned_policy(&events, true);
        for want in [
            r#"tool    = "shell""#,
            r#"match   = "terraform apply""#,
            r#"verdict = "deny""#,
            r#"hostname = "api.openai.com""#,
            "Skipped 1 redacted",
            "POLICY_OWNER",
        ] {
            assert!(got.contains(want), "missing {want:?} in:\n{got}");
        }
    }

    #[test]
    fn render_learned_policy_omits_allowed_by_default() {
        let got = render_learned_policy(&[event("shell", "echo ok", "allow", false)], false);
        assert!(
            !got.contains("[[policy]]"),
            "unexpected allow suggestion:\n{got}"
        );
    }

    #[test]
    fn parse_inline_case_reads_pairs() {
        let c = parse_inline_case("tool=shell,action=rm -rf /,expect=deny").unwrap();
        assert_eq!(c.tool, "shell");
        assert_eq!(c.action, "rm -rf /");
        assert_eq!(c.expect, "deny");
        assert!(parse_inline_case("tool=shell,bogus=1").is_err());
        assert!(parse_inline_case("noequals").is_err());
    }

    #[test]
    fn normalize_verdict_accepts_aliases() {
        for (input, want) in [
            ("allow", Verdict::Allow),
            ("DENY", Verdict::Deny),
            ("require-approval", Verdict::RequireApproval),
            ("approval", Verdict::RequireApproval),
        ] {
            assert_eq!(normalize_verdict(input).unwrap(), want, "{input}");
        }
        assert!(normalize_verdict("maybe").is_err());
        assert!(normalize_verdict("").is_err());
    }

    #[test]
    fn hostnames_must_be_plain_dns_names() {
        assert!(valid_exact_hostname("api.example.com"));
        assert!(!valid_exact_hostname("10.0.0.1"));
        assert!(!valid_exact_hostname("localhost"));
        assert!(!valid_exact_hostname(".example.com"));
        assert!(!valid_exact_hostname("a b.com"));
    }
}
