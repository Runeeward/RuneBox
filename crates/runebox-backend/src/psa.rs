//! The Pod Security Standards level a Citadel Pod needs, so the Kubernetes
//! backend can refuse a Pod its namespace would not admit, with the reason,
//! before creating anything.
//!
//! Only the controls the Pods Rune Box builds can touch are checked:
//! privileged containers, host namespaces, ports and paths, added
//! capabilities, privilege escalation, the user and the seccomp profile.

use k8s_openapi::api::core::v1::{Container, Pod, PodSecurityContext, SecurityContext, Volume};

/// A Pod Security Standards level, least to most permissive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PsaLevel {
    Restricted,
    Baseline,
    Privileged,
}

impl PsaLevel {
    /// The `pod-security.kubernetes.io/enforce` label value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Restricted => "restricted",
            Self::Baseline => "baseline",
            Self::Privileged => "privileged",
        }
    }

    /// Parses a label value (case-sensitive, as Kubernetes reads it).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "restricted" => Some(Self::Restricted),
            "baseline" => Some(Self::Baseline),
            "privileged" => Some(Self::Privileged),
            _ => None,
        }
    }
}

/// The capabilities `baseline` lets a container add.
const BASELINE_CAPS: [&str; 13] = [
    "AUDIT_WRITE",
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "FSETID",
    "KILL",
    "MKNOD",
    "NET_BIND_SERVICE",
    "SETFCAP",
    "SETGID",
    "SETPCAP",
    "SETUID",
    "SYS_CHROOT",
];

/// The level a Pod needs, with one line per control that keeps it above
/// `restricted`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodSecurity {
    pub level: PsaLevel,
    pub reasons: Vec<String>,
}

impl PodSecurity {
    fn need(&mut self, level: PsaLevel, reason: String) {
        self.level = self.level.max(level);
        self.reasons.push(reason);
    }

    /// The reasons that need more than `allowed`.
    pub fn above(&self, allowed: PsaLevel) -> Vec<&str> {
        self.reasons
            .iter()
            .filter(|r| reason_level(r) > allowed)
            .map(String::as_str)
            .collect()
    }
}

/// Reasons carry their level as a prefix (`baseline: ...`).
fn reason_level(reason: &str) -> PsaLevel {
    reason
        .split_once(": ")
        .and_then(|(l, _)| PsaLevel::parse(l))
        .unwrap_or(PsaLevel::Privileged)
}

/// Evaluates a Pod against the Pod Security Standards.
pub fn pod_security(pod: &Pod) -> PodSecurity {
    let mut out = PodSecurity {
        level: PsaLevel::Restricted,
        reasons: Vec::new(),
    };
    let Some(spec) = pod.spec.as_ref() else {
        return out;
    };
    let mut need = |level: PsaLevel, what: String| {
        out.need(level, format!("{}: {what}", level.as_str()));
    };
    for (on, what) in [
        (spec.host_network, "hostNetwork"),
        (spec.host_pid, "hostPID"),
        (spec.host_ipc, "hostIPC"),
    ] {
        if on == Some(true) {
            need(PsaLevel::Privileged, format!("the Pod sets {what}"));
        }
    }
    for v in spec.volumes.iter().flatten() {
        check_volume(v, &mut need);
    }
    let pod_sec = spec.security_context.as_ref();
    let containers = spec
        .init_containers
        .iter()
        .flatten()
        .chain(spec.containers.iter());
    for c in containers {
        check_container(c, pod_sec, &mut need);
    }
    out
}

fn check_volume(v: &Volume, need: &mut impl FnMut(PsaLevel, String)) {
    if v.host_path.is_some() {
        need(
            PsaLevel::Privileged,
            format!("volume {:?} is a hostPath", v.name),
        );
        return;
    }
    let allowed = v.config_map.is_some()
        || v.csi.is_some()
        || v.downward_api.is_some()
        || v.empty_dir.is_some()
        || v.ephemeral.is_some()
        || v.persistent_volume_claim.is_some()
        || v.projected.is_some()
        || v.secret.is_some();
    if !allowed {
        need(
            PsaLevel::Baseline,
            format!("volume {:?} is of a type restricted does not allow", v.name),
        );
    }
}

fn check_container(
    c: &Container,
    pod: Option<&PodSecurityContext>,
    need: &mut impl FnMut(PsaLevel, String),
) {
    let name = &c.name;
    let sec = c.security_context.clone().unwrap_or_default();
    if sec.privileged == Some(true) {
        need(
            PsaLevel::Privileged,
            format!("container {name:?} is privileged"),
        );
    }
    if c.ports
        .iter()
        .flatten()
        .any(|p| p.host_port.is_some_and(|h| h != 0))
    {
        need(
            PsaLevel::Privileged,
            format!("container {name:?} uses a hostPort"),
        );
    }
    check_capabilities(name, &sec, need);
    if sec.allow_privilege_escalation != Some(false) {
        need(
            PsaLevel::Baseline,
            format!("container {name:?} does not set allowPrivilegeEscalation: false"),
        );
    }
    let run_as_user = sec.run_as_user.or(pod.and_then(|p| p.run_as_user));
    let non_root = sec.run_as_non_root.or(pod.and_then(|p| p.run_as_non_root));
    if run_as_user == Some(0) {
        need(
            PsaLevel::Baseline,
            format!("container {name:?} runs as root"),
        );
    } else if non_root != Some(true) {
        need(
            PsaLevel::Baseline,
            format!("container {name:?} does not set runAsNonRoot: true"),
        );
    }
    let apparmor = sec
        .app_armor_profile
        .as_ref()
        .or(pod.and_then(|p| p.app_armor_profile.as_ref()));
    if apparmor.is_some_and(|a| a.type_ == "Unconfined") {
        need(
            PsaLevel::Privileged,
            format!("container {name:?} runs Unconfined by AppArmor"),
        );
    }
    let seccomp = sec
        .seccomp_profile
        .as_ref()
        .or(pod.and_then(|p| p.seccomp_profile.as_ref()))
        .map(|s| s.type_.as_str());
    match seccomp {
        Some("RuntimeDefault" | "Localhost") => {}
        Some("Unconfined") => need(
            PsaLevel::Privileged,
            format!("container {name:?} runs Unconfined by seccomp"),
        ),
        _ => need(
            PsaLevel::Baseline,
            format!("container {name:?} has no seccomp profile"),
        ),
    }
}

fn check_capabilities(name: &str, sec: &SecurityContext, need: &mut impl FnMut(PsaLevel, String)) {
    let caps = sec.capabilities.clone().unwrap_or_default();
    for cap in caps.add.iter().flatten() {
        let cap = cap.trim_start_matches("CAP_");
        if !BASELINE_CAPS.contains(&cap) {
            need(
                PsaLevel::Privileged,
                format!("container {name:?} adds {cap}"),
            );
        } else if cap != "NET_BIND_SERVICE" {
            need(PsaLevel::Baseline, format!("container {name:?} adds {cap}"));
        }
    }
    if !caps.drop.iter().flatten().any(|c| c == "ALL") {
        need(
            PsaLevel::Baseline,
            format!("container {name:?} does not drop ALL capabilities"),
        );
    }
}

#[cfg(test)]
mod tests {
    use k8s_openapi::api::core::v1::{Capabilities, HostPathVolumeSource, PodSpec, SeccompProfile};

    use super::*;

    fn hardened() -> SecurityContext {
        SecurityContext {
            allow_privilege_escalation: Some(false),
            run_as_non_root: Some(true),
            run_as_user: Some(1000),
            capabilities: Some(Capabilities {
                add: None,
                drop: Some(vec!["ALL".into()]),
            }),
            ..SecurityContext::default()
        }
    }

    fn pod(containers: Vec<Container>, volumes: Vec<Volume>) -> Pod {
        Pod {
            spec: Some(PodSpec {
                containers,
                volumes: Some(volumes),
                security_context: Some(PodSecurityContext {
                    seccomp_profile: Some(SeccompProfile {
                        type_: "RuntimeDefault".into(),
                        localhost_profile: None,
                    }),
                    ..PodSecurityContext::default()
                }),
                ..PodSpec::default()
            }),
            ..Pod::default()
        }
    }

    fn container(sec: SecurityContext) -> Container {
        Container {
            name: "c".into(),
            security_context: Some(sec),
            ..Container::default()
        }
    }

    #[test]
    fn levels() {
        let p = pod_security(&pod(vec![container(hardened())], Vec::new()));
        assert_eq!(p.level, PsaLevel::Restricted, "{:?}", p.reasons);

        let mut root = hardened();
        root.run_as_user = Some(0);
        root.run_as_non_root = None;
        let p = pod_security(&pod(vec![container(root)], Vec::new()));
        assert_eq!(p.level, PsaLevel::Baseline);
        assert_eq!(p.reasons, ["baseline: container \"c\" runs as root"]);

        let mut setuid = hardened();
        setuid.capabilities.as_mut().expect("caps").add = Some(vec!["SETUID".into()]);
        assert_eq!(
            pod_security(&pod(vec![container(setuid)], Vec::new())).level,
            PsaLevel::Baseline
        );

        let mut net = hardened();
        net.capabilities.as_mut().expect("caps").add = Some(vec!["NET_ADMIN".into()]);
        let p = pod_security(&pod(vec![container(net)], Vec::new()));
        assert_eq!(p.level, PsaLevel::Privileged);
        assert_eq!(
            p.above(PsaLevel::Baseline),
            ["privileged: container \"c\" adds NET_ADMIN"]
        );

        let mut bind = hardened();
        bind.capabilities.as_mut().expect("caps").add = Some(vec!["NET_BIND_SERVICE".into()]);
        assert_eq!(
            pod_security(&pod(vec![container(bind)], Vec::new())).level,
            PsaLevel::Restricted
        );

        let host = Volume {
            name: "h".into(),
            host_path: Some(HostPathVolumeSource {
                path: "/".into(),
                type_: None,
            }),
            ..Volume::default()
        };
        assert_eq!(
            pod_security(&pod(vec![container(hardened())], vec![host])).level,
            PsaLevel::Privileged
        );

        let mut escalate = hardened();
        escalate.allow_privilege_escalation = None;
        assert_eq!(
            pod_security(&pod(vec![container(escalate)], Vec::new())).level,
            PsaLevel::Baseline
        );
    }

    #[test]
    fn parse_round_trips() {
        for l in [
            PsaLevel::Restricted,
            PsaLevel::Baseline,
            PsaLevel::Privileged,
        ] {
            assert_eq!(PsaLevel::parse(l.as_str()), Some(l));
        }
        assert_eq!(PsaLevel::parse("Baseline"), None);
    }
}
