//! `runeward evidence efficiency`: repeated and avoidable calls in a
//! recorded run, read from a verified evidence package or Chronicle bundle.
//! Nothing is run or replayed; the report only reads what was recorded.
//!
//! - **Repeated calls**: the same call (tool, action and arguments) made more
//!   than once in one session.
//! - **Retried after a refusal**: repeats of a call that policy had already
//!   denied or held for approval; with an unchanged Charter they are refused
//!   again.
//! - **Repeated failures**: repeats of a call whose previous run failed with
//!   the same exit code.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Write as _;

use anyhow::Result;
use runeward_ledger::Event;
use serde::Serialize;

/// Lifecycle and bookkeeping events, not calls an agent made.
const NOT_CALLS: &[&str] = &[
    "approval",
    "browser",
    "citadel",
    "fleet",
    "ide",
    "sandbox",
    "schedule",
    "snapshot",
    "stderr",
    "stdout",
    "supervisor",
    "terminal",
    "usage",
    "workspace",
];

/// One call made more than once in a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Repeat {
    pub session: String,
    pub tool: String,
    pub action: String,
    /// Times the call was made.
    pub count: usize,
    /// Repeats that followed a deny or require-approval of the same call.
    pub after_refusal: usize,
    /// Repeats that followed a failure of the same call with the same exit
    /// code.
    pub repeated_failures: usize,
    /// Time spent in the repeats (every call after the first), in ms.
    pub repeat_ms: i64,
}

/// The efficiency report of a recorded run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Report {
    /// Calls read (lifecycle events excluded).
    pub calls: usize,
    /// Calls that repeated an earlier identical call.
    pub repeats: usize,
    /// Of those, repeats after a refusal.
    pub after_refusal: usize,
    /// Of those, repeats after an identical failure.
    pub repeated_failures: usize,
    /// Time spent in repeats, in ms.
    pub repeat_ms: i64,
    /// Repeated calls, most repeated first.
    pub top: Vec<Repeat>,
}

/// A call's identity in a session: (session, tool, action, arguments).
type CallKey<'a> = (&'a str, &'a str, &'a str, Vec<&'a str>);

fn is_call(e: &Event) -> bool {
    !e.tool.is_empty()
        && !NOT_CALLS.contains(&e.tool.as_str())
        && !(e.tool == "egress" && e.action.starts_with("decisions-"))
}

fn refused(verdict: &str) -> bool {
    matches!(verdict, "deny" | "require-approval")
}

/// Builds the report from `events` in recorded order, keeping the `top`
/// most repeated calls.
pub fn analyse(events: &[Event], top: usize) -> Report {
    // call -> (repeat, previous verdict, previous exit)
    let mut seen: BTreeMap<CallKey<'_>, (Repeat, String, i64)> = BTreeMap::new();
    let mut r = Report::default();
    for e in events.iter().filter(|e| is_call(e)) {
        r.calls += 1;
        let session = if e.session_id.is_empty() {
            e.sandbox.as_str()
        } else {
            e.session_id.as_str()
        };
        let key = (
            session,
            e.tool.as_str(),
            e.action.as_str(),
            e.args.iter().map(String::as_str).collect(),
        );
        let entry = seen.entry(key).or_insert_with(|| {
            (
                Repeat {
                    session: session.to_owned(),
                    tool: e.tool.clone(),
                    action: e.action.clone(),
                    count: 0,
                    after_refusal: 0,
                    repeated_failures: 0,
                    repeat_ms: 0,
                },
                String::new(),
                0,
            )
        });
        let (rep, prev_verdict, prev_exit) = entry;
        if rep.count > 0 {
            r.repeats += 1;
            rep.repeat_ms += e.duration_ms.max(0);
            if refused(prev_verdict) {
                rep.after_refusal += 1;
            } else if *prev_exit != 0 && *prev_exit == e.exit_code {
                rep.repeated_failures += 1;
            }
        }
        rep.count += 1;
        prev_verdict.clone_from(&e.verdict);
        *prev_exit = e.exit_code;
    }
    let mut repeats: Vec<Repeat> = seen
        .into_values()
        .map(|(rep, _, _)| rep)
        .filter(|rep| rep.count > 1)
        .collect();
    r.after_refusal = repeats.iter().map(|x| x.after_refusal).sum();
    r.repeated_failures = repeats.iter().map(|x| x.repeated_failures).sum();
    r.repeat_ms = repeats.iter().map(|x| x.repeat_ms).sum();
    repeats.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| (&a.session, &a.tool, &a.action).cmp(&(&b.session, &b.tool, &b.action)))
    });
    repeats.truncate(top);
    r.top = repeats;
    r
}

/// The report as text.
pub fn render(r: &Report) -> String {
    let mut out = format!(
        "{} calls, {} repeats of an earlier identical call ({} after a refusal, {} after the same failure), {} ms spent in repeats\n",
        r.calls, r.repeats, r.after_refusal, r.repeated_failures, r.repeat_ms
    );
    if r.top.is_empty() {
        out.push_str("No call was repeated.\n");
        return out;
    }
    for rep in &r.top {
        let mut notes = Vec::new();
        if rep.after_refusal > 0 {
            notes.push(format!("{} after a refusal", rep.after_refusal));
        }
        if rep.repeated_failures > 0 {
            notes.push(format!("{} after the same failure", rep.repeated_failures));
        }
        let notes = if notes.is_empty() {
            String::new()
        } else {
            format!(" ({})", notes.join(", "))
        };
        let _ = writeln!(
            out,
            "  {}x {} {:?} in {}{notes}",
            rep.count, rep.tool, rep.action, rep.session
        );
    }
    out
}

/// `runeward evidence efficiency <evidence-or-chronicle.json>`.
pub fn efficiency(path: &str, top: usize, json: bool) -> Result<()> {
    let events = crate::policy::read_verified_events(path, "report on")?;
    let r = analyse(&events, top);
    if json {
        println!("{}", serde_json::to_string_pretty(&r)?);
    } else {
        print!("{}", render(&r));
    }
    std::io::stdout().flush()?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn call(session: &str, tool: &str, action: &str, verdict: &str, exit: i64) -> Event {
        Event {
            session_id: session.into(),
            tool: tool.into(),
            action: action.into(),
            verdict: verdict.into(),
            exit_code: exit,
            duration_ms: 100,
            ..Event::default()
        }
    }

    #[test]
    fn repeats_refusal_retries_and_failures_are_counted() {
        let events = vec![
            call("s1", "sandbox", "create", "allow", 0),
            call("s1", "egress", "GET api.example.test/v1/items", "allow", 0),
            call("s1", "egress", "GET api.example.test/v1/items", "allow", 0),
            call("s1", "egress", "GET api.example.test/v1/items", "allow", 0),
            call("s1", "shell", "terraform apply", "deny", -1),
            call("s1", "shell", "terraform apply", "deny", -1),
            call("s1", "shell", "make test", "allow", 2),
            call("s1", "shell", "make test", "allow", 2),
            call("s1", "shell", "make test", "allow", 0),
            // Same call in another session is not a repeat.
            call("s2", "shell", "terraform apply", "deny", -1),
            call("s1", "egress", "decisions-detached", "error", -1),
            call("s1", "egress", "decisions-detached", "error", -1),
        ];
        let r = analyse(&events, 10);
        assert_eq!(r.calls, 9);
        assert_eq!(r.repeats, 5);
        assert_eq!(r.after_refusal, 1);
        assert_eq!(r.repeated_failures, 1);
        assert_eq!(r.repeat_ms, 500);
        let top: Vec<(usize, &str)> = r.top.iter().map(|x| (x.count, x.action.as_str())).collect();
        assert_eq!(
            top,
            [
                (3, "GET api.example.test/v1/items"),
                (3, "make test"),
                (2, "terraform apply"),
            ]
        );
        let text = render(&r);
        assert!(text.starts_with("9 calls, 5 repeats"), "{text}");
        assert!(
            text.contains("2x shell \"terraform apply\" in s1 (1 after a refusal)"),
            "{text}"
        );
        assert!(
            text.contains("3x shell \"make test\" in s1 (1 after the same failure)"),
            "{text}"
        );
        assert_eq!(analyse(&events, 1).top.len(), 1);
    }

    #[test]
    fn reads_a_verified_chronicle_bundle_and_refuses_a_tampered_one() {
        use runeward_ledger::{Ledger, Signer};
        let dir = tempfile::tempdir().unwrap();
        let l = Ledger::open(dir.path().join("ledger.jsonl")).unwrap();
        let signer = Signer::load_or_create(dir.path()).unwrap();
        l.set_signer(Some(signer.clone()));
        for (action, verdict) in [
            ("curl x", "allow"),
            ("curl x", "allow"),
            ("rm -rf /", "deny"),
            ("rm -rf /", "deny"),
        ] {
            l.append(call("s1", "shell", action, verdict, 0)).unwrap();
        }
        let mut buf = Vec::new();
        l.export_bundle(&mut buf, "s1", &signer.public()).unwrap();
        let path = dir.path().join("chronicle.json");
        std::fs::write(&path, &buf).unwrap();
        let events =
            crate::policy::read_verified_events(path.to_str().unwrap(), "report on").unwrap();
        let r = analyse(&events, 10);
        assert_eq!((r.calls, r.repeats, r.after_refusal), (4, 2, 1));

        let tampered = String::from_utf8(buf)
            .unwrap()
            .replacen("curl x", "curl y", 1);
        std::fs::write(&path, tampered).unwrap();
        let err =
            crate::policy::read_verified_events(path.to_str().unwrap(), "report on").unwrap_err();
        assert!(
            err.to_string()
                .starts_with("refusing to report on an unverified Chronicle bundle"),
            "{err}"
        );
    }

    #[test]
    fn arguments_tell_calls_apart() {
        let mut a = call("s", "shell", "ls", "allow", 0);
        a.args = vec!["ls".into(), "/a".into()];
        let mut b = a.clone();
        b.args = vec!["ls".into(), "/b".into()];
        let r = analyse(&[a.clone(), b, a], 10);
        assert_eq!(r.repeats, 1);
        assert_eq!(
            render(&analyse(&[], 10)),
            "0 calls, 0 repeats of an earlier identical call (0 after a refusal, 0 after the same failure), 0 ms spent in repeats\nNo call was repeated.\n"
        );
    }
}
