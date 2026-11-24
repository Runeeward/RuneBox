//! Every default image Rune Box ships is pinned by digest (`name:tag@sha256:…`):
//! the built-in sandbox images, the base images of `deploy/Dockerfile*`, and
//! the images the Helm chart names. Rune Box's own release images (the
//! server, the egress sidecar and the CSI driver) are published by the same
//! release that builds the binary and the chart, so they are pinned to this
//! release's version tag, never a floating one.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use runebox_backend::config::{DEFAULT_EGRESS_IMAGE, DEFAULT_IMAGE};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// `name:tag@sha256:<64 lowercase hex>`.
fn pinned(image: &str) -> bool {
    let Some((name, digest)) = image.rsplit_once("@sha256:") else {
        return false;
    };
    let tagged = name
        .rsplit('/')
        .next()
        .is_some_and(|last| last.contains(':'));
    tagged
        && digest.len() == 64
        && digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[test]
fn pin_check() {
    assert!(pinned(
        "alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6"
    ));
    assert!(!pinned("alpine:3.24"));
    assert!(!pinned(
        "alpine@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6"
    ));
    assert!(!pinned("alpine:3.24@sha256:abc"));
}

#[test]
fn built_in_images_are_pinned() {
    for image in [DEFAULT_IMAGE, runebox_charter::DEFAULT_SANDBOX_IMAGE] {
        assert!(pinned(image), "{image} is not pinned by digest");
    }
    assert_eq!(
        DEFAULT_EGRESS_IMAGE,
        format!(
            "ghcr.io/runeeward/runebox-egress:v{}",
            env!("CARGO_PKG_VERSION")
        ),
        "the egress image follows this release"
    );
}

#[test]
fn dockerfile_base_images_are_pinned() {
    let dir = repo_root().join("deploy");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).expect("read deploy/") {
        let path = entry.expect("entry").path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !name.starts_with("Dockerfile") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read Dockerfile");
        let mut stages = HashSet::new();
        for line in text.lines() {
            let mut words = line.split_whitespace();
            if !words.next().is_some_and(|w| w.eq_ignore_ascii_case("FROM")) {
                continue;
            }
            let words: Vec<_> = words.filter(|w| !w.starts_with("--")).collect();
            let Some(image) = words.first() else {
                continue;
            };
            if !stages.contains(*image) {
                assert!(
                    pinned(image),
                    "{name}: FROM {image} is not pinned by digest"
                );
                checked += 1;
            }
            if let [_, as_kw, stage] = words.as_slice()
                && as_kw.eq_ignore_ascii_case("AS")
            {
                stages.insert((*stage).to_owned());
            }
        }
    }
    assert!(checked > 0, "no Dockerfile base images found");
}

/// Image references written into the chart: any `image:`-like value that
/// names a registry image rather than a template expression.
#[test]
fn helm_chart_images_are_pinned() {
    let chart = repo_root().join("deploy/helm/runebox");
    let mut files = vec![chart.join("values.yaml")];
    for entry in std::fs::read_dir(chart.join("templates")).expect("read templates") {
        files.push(entry.expect("entry").path());
    }
    let mut checked = 0;
    for path in files {
        let text = std::fs::read_to_string(&path).expect("read chart file");
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let key = key.trim().trim_start_matches("- ");
            let value = value.trim().trim_matches('"');
            let is_image_key =
                key == "image" || matches!(key, "provisioner" | "registrar" | "livenessProbe");
            if !is_image_key || value.is_empty() || value.starts_with("{{") {
                continue;
            }
            // A plain `image:` mapping key (with nested fields) has no value.
            assert!(
                pinned(value),
                "{}: {key}: {value} is not pinned by digest",
                path.display()
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "no chart images found");
}
