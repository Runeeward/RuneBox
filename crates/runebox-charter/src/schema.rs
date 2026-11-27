//! The declarative Charter schema.
//!
//! A Charter is a named security contract for a task, resolved fresh on every
//! invocation and never written back to disk. It may be authored in TOML, YAML
//! or JSON; every format uses the same snake_case keys.
//!
//! Every struct rejects unknown keys (the Go loader decodes strictly, so a typo
//! is an error rather than a silently ignored setting) and defaults missing
//! keys to their zero value. New sections are added as further `Option` or
//! defaulted fields, which keeps older Charters valid.

use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::governance::{
    Credential, Endpoint, Filesystem, Isolation, Process, Schedule, Workspace,
};

/// Generates a string-backed enum whose unknown spellings survive parsing.
///
/// Validation and lint report bad values with their original spelling, so
/// decoding must not reject them up front.
macro_rules! string_enum {
    (
        $(#[$meta:meta])*
        $name:ident { $($(#[$vmeta:meta])* $variant:ident => $text:literal),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
        pub enum $name {
            /// Not set (the empty string).
            #[default]
            Unset,
            $($(#[$vmeta])* $variant,)+
            /// Any other spelling, kept verbatim for error messages.
            Other(String),
        }

        impl $name {
            /// Returns the value as written in a Charter.
            pub fn as_str(&self) -> &str {
                match self {
                    Self::Unset => "",
                    $(Self::$variant => $text,)+
                    Self::Other(s) => s,
                }
            }

            /// Parses a spelling; never fails.
            pub fn parse(s: &str) -> Self {
                match s {
                    "" => Self::Unset,
                    $($text => Self::$variant,)+
                    other => Self::Other(other.to_owned()),
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                Self::parse(s)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                Ok(Self::parse(&s))
            }
        }
    };
}

string_enum! {
    /// Selects the execution backend a Charter runs on.
    HostType {
        /// A Docker/Podman container (the default).
        Container => "container",
        /// A Kubernetes Sandbox custom resource.
        K8s => "k8s",
        /// A microVM booted directly by the host (Firecracker or libkrun,
        /// chosen by `host.runtime`): no container engine, Kata or
        /// Kubernetes.
        Microvm => "microvm",
    }
}

string_enum! {
    /// The decision a policy rule renders for a matched action.
    Verdict {
        /// Let the action run.
        Allow => "allow",
        /// Refuse the action.
        Deny => "deny",
        /// Pause until a human approves.
        RequireApproval => "require-approval",
    }
}

impl Verdict {
    /// Reports whether this is one of the three recognised verdicts.
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Allow | Self::Deny | Self::RequireApproval)
    }
}

/// The top-level resolved contract read from `<name>.{toml,yaml,yml,json}`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Charter {
    /// Comes from the filename, not the file body.
    #[serde(skip)]
    pub name: String,
    /// The path the Charter was resolved from.
    #[serde(skip)]
    pub source: PathBuf,

    /// `[host]`: backend, image and sandbox hardening.
    pub host: Host,
    /// Optional tools present in the image (`python`, `node`, `browser`), so
    /// the dashboard does not offer actions the sandbox cannot execute.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    /// `[prompt]`: optional system prompt.
    pub prompt: Prompt,
    /// `[[env]]`: variables set in the sandbox, resolved on every run.
    pub env: Vec<EnvVar>,
    /// `[[file]]` entries (serialized as `file`): files written into the
    /// sandbox at creation.
    #[serde(rename = "file")]
    pub files: Vec<File>,
    /// `[network]`: the egress policy.
    pub network: Network,
    /// `[[policy]]`: built-in action rules, first match wins.
    pub policy: Vec<PolicyRule>,
    /// Fallback verdict when no rule matches; unset keeps the historical
    /// "allow", "deny" fails closed.
    pub policy_default: Verdict,
    /// `""`/`"builtin"` (the `[[policy]]` rules), `"cel"` or `"rego"`. Selecting
    /// cel or rego makes the `[[policy]]` rules ignored.
    pub policy_engine: String,
    /// `[[cel]]`: rules used when `policy_engine = "cel"`.
    pub cel: Vec<CelRule>,
    /// `[rego]`: the module used when `policy_engine = "rego"`.
    pub rego: RegoPolicy,
    /// When set, supersedes the inline policy with a signed OCI bundle.
    pub policy_bundle: Option<PolicyBundle>,
    /// `[rationing]` (serialized as `rationing`): cost and loop guardrails.
    #[serde(rename = "rationing")]
    pub limits: Limits,
    /// `[cohort]` (serialized as `cohort`): Cohort settings; `None` when the
    /// section is absent.
    #[serde(rename = "cohort")]
    pub fleet: Option<Fleet>,
    /// `[chronicle]` (serialized as `chronicle`): ledger sink and redaction.
    #[serde(rename = "chronicle")]
    pub audit: Audit,
    /// Optional in-sandbox browser IDE, gated at serve time by a feature flag.
    pub ide: Ide,
    /// Installed only with `--provision`, never on the run path.
    pub packages: Vec<String>,

    /// The weakest isolation boundary this Charter may run on.
    #[serde(skip_serializing_if = "Isolation::is_unset")]
    pub isolation: Isolation,
    /// Landlock filesystem confinement inside the sandbox.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filesystem: Option<Filesystem>,
    /// The identity the agent process runs as.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<Process>,
    /// Secrets attached by the egress broker; the sandbox sees placeholders.
    #[serde(rename = "credential", skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<Credential>,
    /// Upstreams with request-level rules.
    #[serde(rename = "endpoint", skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<Endpoint>,
    /// Persistent workspace and idle sleep.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace: Option<Workspace>,
    /// Agent self-service scheduling.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule: Option<Schedule>,
}

impl Charter {
    /// Reports whether the Charter selects the CEL authority engine.
    pub fn uses_cel(&self) -> bool {
        self.policy_engine == "cel"
    }

    /// Reports whether the Charter selects the Rego authority engine.
    pub fn uses_rego(&self) -> bool {
        self.policy_engine == "rego"
    }

    /// Reports whether the Citadel keeps its workspace across sleep/wake.
    pub fn persists_workspace(&self) -> bool {
        self.workspace.as_ref().is_some_and(|w| w.persist)
    }

    /// The idle timeout after which a persistent Citadel sleeps.
    pub fn idle_timeout(&self) -> Option<std::time::Duration> {
        self.workspace
            .as_ref()
            .and_then(Workspace::idle_timeout_duration)
    }

    /// Reports whether agents may schedule their own runs.
    pub fn schedule_self_service(&self) -> bool {
        self.schedule.as_ref().is_some_and(|s| s.self_service)
    }

    /// Reports whether policy comes from an OCI policy bundle.
    pub fn uses_policy_bundle(&self) -> bool {
        self.policy_bundle
            .as_ref()
            .is_some_and(|b| !b.r#ref.is_empty())
    }
}

/// An optional in-sandbox browser IDE (code-server / OpenVSCode).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ide {
    /// Turns the IDE on; the server must also enable the experimental IDE flag.
    pub enabled: bool,
    /// Container-local listen port; validation defaults it to 8080 when enabled.
    pub port: i64,
    /// Reserved URL base path; validation defaults it to "/" when enabled.
    pub path: String,
    /// CLI agents expected in the image, used only for dashboard hints.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<String>,
}

/// Where and how a session runs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Host {
    /// `type`: `container`, `k8s` or `microvm`; loading fills `container`
    /// when empty.
    #[serde(rename = "type")]
    pub host_type: HostType,
    /// Free-form label; only displayed and compared when checking that one
    /// Charter narrows another.
    pub name: String,
    /// Sandbox image; loading fills [`crate::DEFAULT_SANDBOX_IMAGE`] when empty.
    pub image: String,
    /// Identity as `user` or `user:group`, numeric on Kubernetes. Empty: the
    /// image's user on Docker/Podman, a fixed non-root uid on Kubernetes.
    pub user: String,
    /// Working directory inside the sandbox; loading fills `/workspace` when
    /// empty.
    pub workdir: String,
    /// Overrides the keep-alive entrypoint; empty means `sleep infinity`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
    /// Local directory copied (never mounted) into the workspace at creation.
    pub copy_from: String,
    /// Backend hint (`docker`, `podman`), or an OCI runtime (`krun`,
    /// `kata-fc`, `runsc`, ...) used when `runtime_class` is empty. With
    /// `type = "microvm"` it picks the monitor: `firecracker` or `libkrun`
    /// (empty: the operator's default).
    pub runtime: String,
    /// Sandboxed OCI runtime (Docker/Podman `--runtime`, Kubernetes
    /// RuntimeClass): `runsc`, `kata`, `kata-qemu`, `kata-clh`, `kata-fc`,
    /// `krun`, or any runtime registered with the engine.
    pub runtime_class: String,
    /// Mounts the root filesystem read-only (workspace and /tmp stay writable).
    pub read_only: bool,
    /// Seccomp profile path (or RuntimeDefault on Kubernetes when empty).
    pub seccomp: String,
    /// AppArmor profile name.
    pub apparmor: String,
}

impl Host {
    /// The OCI runtime the sandbox runs under: `runtime_class`, or
    /// `runtime` when that names an OCI runtime rather than an engine.
    /// Empty means the engine default.
    pub fn oci_runtime(&self) -> &str {
        let rc = self.runtime_class.trim();
        if !rc.is_empty() {
            return rc;
        }
        let rt = self.runtime.trim();
        if crate::runtimes::is_engine_name(rt) {
            ""
        } else {
            rt
        }
    }
}

/// An optional system prompt, inline or from a file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Prompt {
    /// Prompt text written in the Charter.
    pub inline: String,
    /// Path to a file holding the prompt.
    pub file: String,
}

/// One environment value resolved fresh per invocation. `value`, `file` and
/// `op` are mutually exclusive.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnvVar {
    /// Variable name set in the sandbox; required.
    pub name: String,
    /// A literal value.
    pub value: String,
    /// A path on the operator's machine to read the value from.
    pub file: String,
    /// A secret-manager reference (`env://`, `vault://`, `aws://`, `gcp://`,
    /// 1Password `op://`). The key
    /// stays "op" for backward compatibility.
    pub op: String,
    /// Marks a literal value as sensitive so it is redacted.
    pub secret: bool,
}

impl EnvVar {
    /// Reports whether the value is sensitive: file and op sources always are.
    pub fn is_secret(&self) -> bool {
        self.secret || !self.op.is_empty() || !self.file.is_empty()
    }
}

/// A file projected into the sandbox, owned root:root at `mode`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct File {
    /// Target path in the sandbox; a relative path lands under `host.workdir`.
    pub path: String,
    /// Octal mode of 3 or 4 digits, such as `"0600"`; empty means `0444`.
    pub mode: String,
    /// Source path on the operator's machine.
    pub file: String,
    /// Inline alternative to `file`.
    pub content: String,
}

/// The declarative egress policy. An empty block is fully open; `default =
/// "deny"` enables the allowlist.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Network {
    /// `"deny"` blocks unmatched egress; `"allow"` or empty lets it through.
    pub default: String,
    /// `[[network.rule]]` entries (serialized as `rule`); the first match wins.
    #[serde(rename = "rule")]
    pub rules: Vec<NetworkRule>,
    /// How a deny policy is enforced. `""` (the default), `"strict"` and its
    /// alias `"l3"` all mean kernel-level enforcement: every TCP connection
    /// is redirected through the egress proxy whatever the workload's proxy
    /// settings, and a backend that cannot do that refuses the Charter.
    /// There is no proxy-only mode. Any other value is refused at
    /// validation.
    pub enforce: String,
}

/// The accepted `[network] enforce` values.
pub const ENFORCE_MODES: [&str; 3] = ["", "strict", "l3"];

impl Network {
    /// Reports whether kernel-level egress enforcement applies: always for
    /// a deny policy (see [`Network::enforce`]).
    pub fn strict_egress(&self) -> bool {
        self.deny_by_default()
    }

    /// Reports whether unmatched egress is blocked.
    pub fn deny_by_default(&self) -> bool {
        self.default == "deny"
    }
}

/// Allows or denies traffic to a hostname (with `*.` wildcards) or CIDR.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkRule {
    /// `allow` (any case) permits the target; any other value, empty
    /// included, denies it.
    pub verdict: String,
    /// Host to match; `*.example.com` matches subdomains at any depth but
    /// not the bare domain. One host per rule.
    pub hostname: String,
    /// IP range such as `10.0.0.0/8`, matched only when the destination is an
    /// IP address.
    pub cidr: String,
}

/// Maps an action to a verdict evaluated before the action executes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyRule {
    /// Action surface: shell, python, node, file.read, file.write, file.edit,
    /// net, or `*`.
    pub tool: String,
    /// Glob over the action's primary argument (command, path or hostname).
    #[serde(rename = "match")]
    pub match_glob: String,
    /// Glob over `argv[0]`, so `sh -c 'rm …'` or `/bin/rm` cannot sidestep a
    /// rule written against the joined command line.
    pub match_argv: String,
    /// `allow`, `deny` or `require-approval`; required.
    pub verdict: Verdict,
    /// Shown to the approver and recorded in the ledger.
    pub reason: String,
}

/// One CEL rule: a boolean `expr` over `tool` and `arg`; the first true rule
/// renders its verdict (unset means allow).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CelRule {
    /// CEL boolean expression over `tool` and `arg`.
    pub expr: String,
    /// Verdict when `expr` is true; unset means allow.
    pub verdict: Verdict,
    /// Recorded with the decision.
    pub reason: String,
}

/// The Rego (OPA) engine: exactly one of `module` (inline) or `file`. `query`
/// defaults to `data.runebox.decision` in the engine.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RegoPolicy {
    /// Inline Rego module source.
    pub module: String,
    /// Path to a Rego module file on the operator's machine (`~` expands).
    pub file: String,
    /// Query to evaluate; empty means `data.runebox.decision`.
    pub query: String,
}

/// A signed policy bundle stored as an OCI artifact.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyBundle {
    /// `oci://registry/repo:tag` or `repo@sha256:…`.
    #[serde(rename = "ref")]
    pub r#ref: String,
    /// Base64 ed25519 public key the bundle signature must verify against.
    pub verify_key: String,
    /// Allows plain-HTTP registries (local testing).
    pub plain_http: bool,
    /// Explicitly accepts an unverified bundle; without it a bundle with no
    /// verify key is rejected rather than trusted.
    #[serde(rename = "insecure_skip_verify")]
    pub insecure: bool,
}

/// Cost and loop guardrails, authored under `[rationing]`. Zero or empty
/// means unlimited (subject to backend ceilings).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Go duration string such as "30m"; see [`crate::parse_duration`].
    pub wall_clock: String,
    /// Most tool invocations per session; 0 or less is unlimited.
    pub max_execs: i64,
    /// Container memory cap such as "512m" or "2g".
    pub memory: String,
    /// CPU cores, e.g. 1.5.
    pub cpus: f64,
    /// Cap on outbound requests through the proxy.
    pub egress_requests: i64,
    /// A session repeating `loop_threshold` near-identical failing actions
    /// within `loop_window` is killed.
    pub loop_window: String,
    /// Failures of one action within `loop_window` that kill the session;
    /// 0, or an empty `loop_window`, disables loop detection.
    pub loop_threshold: i64,
    /// Cumulative model-token cap reported via the usage API.
    pub max_tokens: i64,
    /// Cumulative reported spend cap in US dollars.
    pub max_cost_usd: f64,
}

impl Limits {
    /// Reports whether every limit is unset.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Spawns N sandboxes sharing a task board, authored under `[cohort]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Fleet {
    /// Citadels the Cohort starts; values below 1 start one.
    pub replicas: i64,
    /// Optional task identifiers to distribute.
    pub task_board: Vec<String>,
}

/// The tamper-evident ledger sink and redaction policy, authored under
/// `[chronicle]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Audit {
    /// Path or URI of the append-only ledger.
    pub sink: String,
    /// Stores hashes instead of sensitive payloads; unset means true.
    pub redact: Option<bool>,
    /// Operator regexes appended to the built-in secret scrubbing.
    pub scrub_patterns: Vec<String>,
}

impl Audit {
    /// The effective redaction setting (defaults to true).
    pub fn redact_enabled(&self) -> bool {
        self.redact.unwrap_or(true)
    }
}
