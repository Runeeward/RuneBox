# Changelog

## v0.4.6

### Breaking: Kubernetes enforces Pod Security `restricted` by default

- The managed namespace now enforces the `restricted` Pod Security level by default (`RUNEBOX_K8S_PSA_ENFORCE`; Helm `podSecurityStandard.enforce`, now passed to the server and controller). It was `privileged`.
- Rune Box checks each Citadel pod against the configured level and refuses a Charter that needs more before creating anything. The error names the container, the control and the setting to change.
- Charters with `[network] default = "deny"` need `RUNEBOX_K8S_PSA_ENFORCE=privileged`. Charters with `[filesystem]` or `[process]` (the in-sandbox supervisor), or with `host.user = "root"`, need `baseline`.
- Unsupervised sandboxes run as a non-root `host.user` (uid 1000 when unset), and the workspace is group-owned by its gid. On Kubernetes, `host.user` must be numeric (`uid[:gid]`) or `root`.
- The proxy egress sidecar runs as the egress image's non-root user.
- The Helm chart refuses to render the direct-volume driver unless enforce is `privileged`.

### Added

- `GET /v1/charters` entries report each Charter's effective isolation: `enforce` (`strict`, `l3` or `none`), `dns_resolvers` (pinned resolver IPs, empty when none) and `runtime` (the OCI runtime or microVM monitor, `null` for the engine default). The TypeScript `Profile` type includes them.
- Releases publish `images.json`, the digest of every image built, with a keyless signature (`images.json.sigstore.json`).
- The published Helm chart pins Rune Box's own images (server, egress and CSI driver) by digest. The chart has a new `image.digest` value.
- A test keeps every default image pinned by digest. The binary's built-in egress image stays on the release tag; pin it with `RUNEBOX_EGRESS_IMAGE` from `images.json`.
