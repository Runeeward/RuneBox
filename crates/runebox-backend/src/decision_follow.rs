//! Follows an egress sidecar's log for decision lines and keeps following
//! it: a stream that ends or fails to open is reopened with backoff for as
//! long as the sidecar exists.
//!
//! Lines carry the runtime's log timestamp (`docker logs --timestamps`, the
//! Kubernetes `timestamps` log option). A reopened stream starts at the last
//! timestamp seen, and lines at or before it are skipped, so a reconnect
//! neither repeats nor drops decisions the runtime still holds. Losing the
//! stream and reading again are reported on the broker as
//! [`StreamNotice`]s, which the control plane records in the Chronicle.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use futures_util::stream::BoxStream;
use runebox_egress::broker::DecisionLine;
use runebox_egress::{Broker, StreamNotice};

/// First wait before reopening a stream.
pub(crate) const MIN_BACKOFF: Duration = Duration::from_millis(500);
/// Longest wait between attempts.
pub(crate) const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// The result of one attempt to open the sidecar's log.
pub(crate) enum Attach {
    /// Log lines, each starting with the runtime's timestamp.
    Lines(BoxStream<'static, String>),
    /// The sidecar no longer exists: stop following.
    Gone,
    /// The log could not be opened now; try again later.
    Failed(String),
}

/// Follows decision lines about `sandbox` and publishes them on `broker`
/// until `open` reports the sidecar gone. `open` receives the timestamp to
/// resume from (`None` on the first attempt).
pub(crate) async fn follow<F, Fut>(sandbox: String, broker: Arc<Broker>, mut open: F)
where
    F: FnMut(Option<DateTime<Utc>>) -> Fut,
    Fut: Future<Output = Attach>,
{
    let mut last: Option<DateTime<Utc>> = None;
    let mut backoff = MIN_BACKOFF;
    // Set while decisions may be going unrecorded; the resume is reported
    // with the first new line, so a stream that ends again at once (a
    // stopped sidecar) does not report detach/resume pairs on every retry.
    let mut detached = false;
    loop {
        let reason = match open(last).await {
            Attach::Gone => return,
            Attach::Failed(e) => e,
            Attach::Lines(mut lines) => {
                while let Some(line) = lines.next().await {
                    let (ts, rest) = split_timestamp(&line);
                    if let (Some(ts), Some(prev)) = (ts, last)
                        && ts <= prev
                    {
                        continue;
                    }
                    if detached {
                        broker.report_stream(StreamNotice::Resumed { since: last });
                        detached = false;
                    }
                    backoff = MIN_BACKOFF;
                    if ts.is_some() {
                        last = ts;
                    }
                    if let Some(l) = DecisionLine::parse(rest)
                        && l.sandbox_id == sandbox
                    {
                        broker.publish(l.decision);
                    }
                }
                "the egress sidecar's log stream ended".to_owned()
            }
        };
        if !detached {
            tracing::warn!(target: "runebox_backend", "egress decision stream for {sandbox} detached: {reason}");
            broker.report_stream(StreamNotice::Detached {
                reason,
                last_seen: last,
            });
            detached = true;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// Splits a log line into its leading RFC 3339 timestamp and the rest.
/// Lines without one are returned whole.
pub(crate) fn split_timestamp(line: &str) -> (Option<DateTime<Utc>>, &str) {
    let line = line.trim_end_matches(['\r', '\n']);
    if let Some((head, rest)) = line.split_once(' ')
        && let Ok(ts) = DateTime::parse_from_rfc3339(head)
    {
        return (Some(ts.with_timezone(&Utc)), rest);
    }
    (None, line)
}

/// The `--since` / `sinceTime` value to resume from `ts`.
pub(crate) fn since_arg(ts: DateTime<Utc>) -> String {
    ts.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use runebox_egress::Decision;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    const ID: &str = "0123456789abcdef0123456789abcdef";

    fn broker() -> Arc<Broker> {
        Arc::new(
            Broker::with_secret_values(ID, Vec::new(), Vec::new(), Default::default())
                .expect("broker"),
        )
    }

    fn line(ts: &str, host: &str) -> String {
        let d = Decision {
            host: host.into(),
            allow: true,
            ..Decision::default()
        };
        format!("{ts} {}", DecisionLine::new(ID, &d).to_line())
    }

    fn stream(lines: Vec<String>) -> Attach {
        Attach::Lines(futures_util::stream::iter(lines).boxed())
    }

    #[test]
    fn timestamps_are_split_from_log_lines() {
        let (ts, rest) = split_timestamp("2026-11-02T10:00:00.123456789Z {\"a\":1}\n");
        assert_eq!(
            since_arg(ts.expect("timestamp")),
            "2026-11-02T10:00:00.123456789Z"
        );
        assert_eq!(rest, "{\"a\":1}");
        assert_eq!(split_timestamp("{\"a\":1}"), (None, "{\"a\":1}"));
        assert_eq!(split_timestamp("egress: ready"), (None, "egress: ready"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_dropped_stream_resumes_without_repeats_or_gaps() {
        let b = broker();
        let mut decisions = b.subscribe();
        let mut notices = b.subscribe_stream();
        let t1 = "2026-11-02T10:00:01.000000001Z";
        let t2 = "2026-11-02T10:00:02.000000002Z";
        let t3 = "2026-11-02T10:00:03.000000003Z";
        // The first stream ends after two decisions; the next attempt fails;
        // the third replays from `since` (the runtime repeats t2) and adds
        // t3; then the sidecar is gone.
        let attempts = Arc::new(Mutex::new(VecDeque::from([
            stream(vec![line(t1, "a.test"), line(t2, "b.test")]),
            Attach::Failed("connection reset".into()),
            stream(vec![
                line(t2, "b.test"),
                "2026-11-02T10:00:02.500000000Z egress: not a decision".into(),
                line(t3, "c.test"),
            ]),
            Attach::Gone,
        ])));
        let since = Arc::new(Mutex::new(Vec::new()));
        let (a, s) = (Arc::clone(&attempts), Arc::clone(&since));
        follow(ID.into(), Arc::clone(&b), move |from| {
            s.lock().expect("lock").push(from.map(since_arg));
            let next = a.lock().expect("lock").pop_front().unwrap_or(Attach::Gone);
            async move { next }
        })
        .await;

        let hosts: Vec<String> = std::iter::from_fn(|| decisions.try_recv().ok())
            .map(|d| d.host)
            .collect();
        assert_eq!(hosts, ["a.test", "b.test", "c.test"]);
        assert_eq!(
            *since.lock().expect("lock"),
            [
                None,
                Some(t2.to_owned()),
                Some(t2.to_owned()),
                Some(t3.to_owned())
            ]
        );
        // One detach for the ended stream (the failed retry adds none), one
        // resume when new lines arrive, one detach for the last end.
        let got: Vec<StreamNotice> = std::iter::from_fn(|| notices.try_recv().ok()).collect();
        let t2 = split_timestamp(&format!("{t2} x")).0;
        let t3 = split_timestamp(&format!("{t3} x")).0;
        assert_eq!(
            got,
            [
                StreamNotice::Detached {
                    reason: "the egress sidecar's log stream ended".into(),
                    last_seen: t2,
                },
                StreamNotice::Resumed { since: t2 },
                StreamNotice::Detached {
                    reason: "the egress sidecar's log stream ended".into(),
                    last_seen: t3,
                },
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn retries_back_off_and_stop_when_the_sidecar_is_gone() {
        let b = broker();
        let mut notices = b.subscribe_stream();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let c = Arc::clone(&calls);
        let start = tokio::time::Instant::now();
        follow(ID.into(), Arc::clone(&b), move |_| {
            let mut c = c.lock().expect("lock");
            c.push(start.elapsed());
            let next = if c.len() < 5 {
                Attach::Failed("sidecar not running".into())
            } else {
                Attach::Gone
            };
            async move { next }
        })
        .await;
        let waits: Vec<u64> = calls
            .lock()
            .expect("lock")
            .windows(2)
            .map(|w| (w[1] - w[0]).as_millis() as u64)
            .collect();
        assert_eq!(waits, [500, 1000, 2000, 4000]);
        // Repeated failures report the detach once.
        assert_eq!(
            std::iter::from_fn(|| notices.try_recv().ok()).count(),
            1,
            "one detach notice"
        );
    }
}
