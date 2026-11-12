//! Opt-in end-to-end test for restart cleanup on Kubernetes.
//!
//! Runs only with `RUNEBOX_TEST_K8S=1`, against the kubeconfig context in
//! `RUNEBOX_KUBE_CONTEXT` (or the current one). Use a dedicated test
//! namespace or cluster: startup reconciles every `runebox.managed=true`
//! Pod in the configured namespace.
#![cfg(unix)]

use std::sync::Arc;

use runebox_backend::{Backend, BackendConfig, K8s};
use runebox_charter::SignedCharters;
use runebox_controlplane::{CreateOptions, Manager, ManagerConfig};

fn enabled() -> bool {
    std::env::var("RUNEBOX_TEST_K8S").is_ok_and(|value| value == "1")
}

fn backend_config() -> BackendConfig {
    let pairs: Vec<(String, String)> = ["RUNEBOX_KUBE_CONTEXT", "RUNEBOX_K8S_NAMESPACE"]
        .into_iter()
        .filter_map(|key| std::env::var(key).ok().map(|value| (key.into(), value)))
        .collect();
    BackendConfig::from_pairs(
        pairs
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str())),
    )
}

async fn manager(dir: &std::path::Path, backend: &BackendConfig) -> Arc<Manager> {
    let config = ManagerConfig {
        config_dir: Some(dir.join("charters")),
        state_dir: Some(dir.join("state")),
        sweep_interval: None,
        context_tick: None,
        signed_charters: SignedCharters::Disabled,
        policy_default: None,
        approval_wait: None,
        ..ManagerConfig::default()
    };
    Manager::builder(config)
        .backend_config(backend.clone())
        .build()
        .await
        .expect("manager")
}

#[tokio::test(flavor = "multi_thread")]
async fn restart_removes_ephemeral_managed_pod() {
    if !enabled() {
        eprintln!("skipped: set RUNEBOX_TEST_K8S=1 to run against a cluster");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("charters")).expect("mkdir");
    std::fs::write(
        dir.path().join("charters/plain.toml"),
        "[host]\ntype = \"k8s\"\nimage = \"debian:stable-slim\"\n",
    )
    .expect("charter");
    let backend = backend_config();

    let first = manager(dir.path(), &backend).await;
    let id = first
        .create_sandbox("plain", CreateOptions::default())
        .await
        .expect("create")
        .id;
    let k8s = K8s::new(backend.clone()).await.expect("k8s backend");
    assert!(k8s.exists(&id).await, "created Pod is missing");
    first.close().await.expect("close");
    drop(first);

    let restarted = manager(dir.path(), &backend).await;
    assert!(
        !k8s.exists(&id).await,
        "ephemeral Pod survived restart reconciliation"
    );
    let events = restarted.ledger().records().expect("ledger records");
    assert!(events.iter().any(|event| {
        event.sandbox == id
            && event.tool == "sandbox"
            && event.action == "orphan-cleanup"
            && event.verdict == "allow"
            && event
                .meta
                .get("backend")
                .is_some_and(|value| value == "k8s")
    }));
    restarted.close().await.expect("close restarted");
}
