//! The Chronicle signing key lives apart from the ledger, and the ledger
//! head can be anchored to an outside file.

use runebox_ledger::anchor::{Anchor, append_anchor, read_anchors};
use runebox_ledger::{Event, KEY_DIR_NAME, KEY_FILE_NAME, PUB_FILE_NAME};

use super::support::harness_with;

fn event() -> Event {
    Event {
        tool: "shell".into(),
        action: "true".into(),
        ..Event::default()
    }
}

#[tokio::test]
async fn signing_key_is_kept_apart_from_the_ledger() {
    let h = harness_with(None, |_| {}).await;
    let state = h.dir.path().join("state");
    assert!(state.join(KEY_DIR_NAME).join(KEY_FILE_NAME).exists());
    assert!(!state.join(KEY_FILE_NAME).exists());
    assert!(state.join(PUB_FILE_NAME).exists());

    let keys = tempfile::tempdir().expect("tempdir");
    let custom = keys.path().join("ledger-keys");
    let dir = custom.clone();
    let h = harness_with(None, move |c| c.ledger_key_dir = Some(dir)).await;
    assert!(custom.join(KEY_FILE_NAME).exists());
    assert!(!h.dir.path().join("state").join(KEY_DIR_NAME).exists());
    h.mgr.ledger().append(event()).expect("append");
    h.mgr.verify_ledger().await.expect("verifies");
}

#[tokio::test]
async fn ledger_heads_are_anchored_and_checked() {
    let out = tempfile::tempdir().expect("tempdir");
    let anchor = out.path().join("heads.jsonl");
    let path = anchor.clone();
    let h = harness_with(None, move |c| c.ledger_anchor = Some(path)).await;

    h.mgr.ledger().append(event()).expect("append");
    h.mgr.anchor_ledger().await;
    // An unchanged head is not anchored twice.
    h.mgr.anchor_ledger().await;
    let anchors = read_anchors(&anchor).expect("read");
    assert_eq!(anchors.len(), 1);
    let (seq, hash) = h.mgr.ledger().head();
    assert_eq!(
        (anchors[0].seq, anchors[0].hash.as_str()),
        (seq, hash.as_str())
    );
    h.mgr.verify_ledger().await.expect("verifies");

    // A ledger that no longer matches its anchors fails verification.
    append_anchor(
        &anchor,
        &Anchor {
            time: String::new(),
            seq,
            hash: "rewritten".into(),
        },
    )
    .expect("append anchor");
    let err = h.mgr.verify_ledger().await.expect_err("mismatch");
    assert!(err.to_string().contains("anchor"), "{err}");
}

#[tokio::test]
async fn close_anchors_the_final_head() {
    let out = tempfile::tempdir().expect("tempdir");
    let anchor = out.path().join("heads.jsonl");
    let path = anchor.clone();
    let h = harness_with(None, move |c| c.ledger_anchor = Some(path)).await;
    h.mgr.ledger().append(event()).expect("append");
    h.mgr.close().await.expect("close");
    let anchors = read_anchors(&anchor).expect("read");
    assert_eq!(anchors.last().map(|a| a.seq), Some(h.mgr.ledger().head().0));
}
