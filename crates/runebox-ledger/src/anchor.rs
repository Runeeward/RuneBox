//! External anchors of the ledger head.
//!
//! Signing alone can't catch a rewrite by someone who also holds the key.
//! An anchor file records the head (`seq` and `hash`) from time to time; kept
//! where the node can append but not rewrite (another host, an append-only
//! mount, object storage with retention), it pins history: a rewritten or
//! truncated ledger no longer matches its anchors.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::LedgerError;
use crate::ledger::{Event, Ledger};

/// One anchored ledger head: a JSON line in the anchor file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    /// When the head was anchored (RFC 3339, UTC).
    pub time: String,
    /// The sequence number of the head record.
    pub seq: i64,
    /// The hash of the head record.
    pub hash: String,
}

impl Ledger {
    /// The current head as (seq, hash); `(0, "")` when empty.
    pub fn head(&self) -> (i64, String) {
        let inner = self.lock();
        (inner.seq, inner.tip_hash.clone())
    }

    /// Appends the current head to the anchor file at `path` unless the
    /// ledger is empty or the head is `last_seq`. Returns the anchor written.
    pub fn anchor_head(&self, path: &Path, last_seq: i64) -> Result<Option<Anchor>, LedgerError> {
        let (seq, hash) = self.head();
        if seq == 0 || seq == last_seq {
            return Ok(None);
        }
        let anchor = Anchor {
            time: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            seq,
            hash,
        };
        append_anchor(path, &anchor)?;
        Ok(Some(anchor))
    }
}

/// Appends one anchor line to `path` (created 0600) and fsyncs it.
pub fn append_anchor(path: &Path, anchor: &Anchor) -> Result<(), LedgerError> {
    let err = |source| LedgerError::Anchor {
        path: path.to_path_buf(),
        source,
    };
    let mut line = serde_json::to_vec(anchor).map_err(|e| err(io::Error::other(e)))?;
    line.push(b'\n');
    let mut opts = OpenOptions::new();
    opts.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(err)?;
    f.write_all(&line).map_err(err)?;
    f.sync_all().map_err(err)
}

/// Reads every anchor in `path`; a missing file has none.
pub fn read_anchors(path: &Path) -> Result<Vec<Anchor>, LedgerError> {
    let raw = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(LedgerError::Anchor {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    raw.lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
        .map(|(i, l)| {
            serde_json::from_str(l).map_err(|source| LedgerError::AnchorParse {
                path: path.to_path_buf(),
                line: i + 1,
                source,
            })
        })
        .collect()
}

/// Checks that every anchor names a record still in `records` with the same
/// hash. Run it after [`Ledger::verify`], which checks the chain between
/// anchors.
pub fn verify_anchors(records: &[Event], anchors: &[Anchor]) -> Result<(), LedgerError> {
    let head = records.last().map_or(0, |r| r.seq);
    for a in anchors {
        let rec = usize::try_from(a.seq - 1)
            .ok()
            .and_then(|i| records.get(i))
            .filter(|r| r.seq == a.seq);
        let Some(rec) = rec else {
            return Err(LedgerError::AnchorPastHead { seq: a.seq, head });
        };
        if rec.hash != a.hash {
            return Err(LedgerError::AnchorMismatch {
                seq: a.seq,
                anchored: a.hash.clone(),
                got: rec.hash.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: &str) -> Event {
        Event {
            tool: kind.into(),
            ..Event::default()
        }
    }

    #[test]
    fn anchors_pin_the_head() {
        let dir = tempfile::tempdir().expect("tempdir");
        let l = Ledger::open(dir.path().join("ledger.jsonl")).expect("open");
        let anchors = dir.path().join("anchors.jsonl");
        assert_eq!(l.anchor_head(&anchors, 0).expect("empty"), None);
        l.append(ev("a")).expect("append");
        l.append(ev("b")).expect("append");
        let first = l
            .anchor_head(&anchors, 0)
            .expect("anchor")
            .expect("written");
        assert_eq!(first.seq, 2);
        assert_eq!(first.hash, l.head().1);
        // Unchanged head: nothing new.
        assert_eq!(l.anchor_head(&anchors, 2).expect("same"), None);
        l.append(ev("c")).expect("append");
        l.anchor_head(&anchors, 2)
            .expect("anchor")
            .expect("written");
        let got = read_anchors(&anchors).expect("read");
        assert_eq!(got.len(), 2);
        verify_anchors(&l.records().expect("records"), &got).expect("verify");
        assert!(
            read_anchors(&dir.path().join("none"))
                .expect("missing")
                .is_empty()
        );
    }

    #[test]
    fn rewritten_or_truncated_ledgers_fail() {
        let dir = tempfile::tempdir().expect("tempdir");
        let l = Ledger::open(dir.path().join("ledger.jsonl")).expect("open");
        for k in ["a", "b", "c"] {
            l.append(ev(k)).expect("append");
        }
        let recs = l.records().expect("records");
        let anchor = |seq: i64, hash: &str| Anchor {
            time: String::new(),
            seq,
            hash: hash.into(),
        };
        // A re-chained rewrite keeps verifying on its own but not against
        // the anchor.
        let err = verify_anchors(&recs, &[anchor(2, "forged")]).expect_err("mismatch");
        assert!(
            matches!(err, LedgerError::AnchorMismatch { seq: 2, .. }),
            "{err}"
        );
        let err = verify_anchors(&recs[..1], &[anchor(2, &recs[1].hash)]).expect_err("truncated");
        assert!(
            matches!(err, LedgerError::AnchorPastHead { seq: 2, head: 1 }),
            "{err}"
        );
        assert!(verify_anchors(&recs, &[anchor(0, "")]).is_err());
    }

    #[test]
    fn bad_anchor_lines_are_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("anchors.jsonl");
        fs::write(
            &p,
            "{\"time\":\"t\",\"seq\":1,\"hash\":\"h\"}\n\nnot json\n",
        )
        .expect("write");
        let err = read_anchors(&p).expect_err("parse");
        assert!(
            matches!(err, LedgerError::AnchorParse { line: 3, .. }),
            "{err}"
        );
    }
}
