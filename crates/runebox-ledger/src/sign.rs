//! Ed25519 record signatures and self-contained, verifiable export bundles.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{BundleProblem, LedgerError};
use crate::gojson::{self, go_struct};
use crate::ledger::{Event, Ledger, check_link, hash_event};

/// On-disk name of the signing key (raw 64-byte `seed || public`).
pub const KEY_FILE_NAME: &str = "ledger.key";
/// The directory, beside the ledger, that holds the signing key when no
/// other key directory is configured.
pub const KEY_DIR_NAME: &str = "keys";
/// On-disk name of the base64 public key (0644).
pub const PUB_FILE_NAME: &str = "ledger.pub";

/// Signs ledger record hashes with an ed25519 key so a third party holding
/// the public key can verify records were not altered.
#[derive(Clone)]
pub struct Signer {
    key: SigningKey,
    key_id: String,
}

impl fmt::Debug for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signer")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl Signer {
    /// Wraps an existing signing key.
    pub fn new(key: SigningKey) -> Self {
        let key_id = runebox_keys::key_id(&key.verifying_key());
        Self { key, key_id }
    }

    /// Loads the signing key from dir, generating and persisting a new
    /// keypair on first use.
    pub fn load_or_create(dir: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let dir = dir.as_ref();
        create_dir_private(dir).map_err(LedgerError::SignerDir)?;
        let key_path = dir.join(KEY_FILE_NAME);

        match fs::read(&key_path) {
            Ok(raw) => {
                if raw.len() != runebox_keys::PRIVATE_KEY_LEN {
                    return Err(LedgerError::KeySize {
                        path: key_path,
                        size: raw.len(),
                    });
                }
                let key = runebox_keys::private_from_bytes(&raw).map_err(|source| {
                    LedgerError::InvalidKey {
                        path: key_path.clone(),
                        source,
                    }
                })?;
                return Ok(Self::new(key));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(LedgerError::ReadKey(e)),
        }

        let mut secret = [0u8; 32];
        rand::TryRng::try_fill_bytes(&mut rand::rngs::SysRng, &mut secret)
            .map_err(|e| LedgerError::GenerateKey(io::Error::other(e)))?;
        let key = SigningKey::from_bytes(&secret);
        write_file(&key_path, &key.to_keypair_bytes(), 0o600).map_err(LedgerError::WriteKey)?;
        let pub_line = format!("{}\n", runebox_keys::encode_public(&key.verifying_key()));
        write_file(&dir.join(PUB_FILE_NAME), pub_line.as_bytes(), 0o644)
            .map_err(LedgerError::WritePublicKey)?;
        Ok(Self::new(key))
    }

    /// Loads the signing key from `key_dir`, kept apart from the ledger in
    /// `ledger_dir`, generating one on first use. A key still beside the
    /// ledger (the layout before key directories) moves into `key_dir`.
    /// `key_dir` is made 0700 and the key 0400; the public key is also
    /// written beside the ledger, where verifiers look for it.
    pub fn load_or_create_apart(key_dir: &Path, ledger_dir: &Path) -> Result<Self, LedgerError> {
        if same_dir(key_dir, ledger_dir) {
            return Self::load_or_create(key_dir);
        }
        create_dir_private(key_dir).map_err(LedgerError::SignerDir)?;
        set_mode(key_dir, 0o700).map_err(LedgerError::SignerDir)?;
        let key_path = key_dir.join(KEY_FILE_NAME);
        let legacy = ledger_dir.join(KEY_FILE_NAME);
        match (key_path.exists(), legacy.exists()) {
            (false, true) => move_file(&legacy, &key_path).map_err(LedgerError::WriteKey)?,
            (true, true) => {
                let a = fs::read(&key_path).map_err(LedgerError::ReadKey)?;
                let b = fs::read(&legacy).map_err(LedgerError::ReadKey)?;
                if a != b {
                    return Err(LedgerError::KeyConflict {
                        key: key_path,
                        legacy,
                    });
                }
                fs::remove_file(&legacy).map_err(LedgerError::WriteKey)?;
            }
            _ => {}
        }
        let signer = Self::load_or_create(key_dir)?;
        set_mode(&key_path, 0o400).map_err(LedgerError::WriteKey)?;
        let pub_line = format!("{}\n", runebox_keys::encode_public(&signer.public()));
        for dir in [key_dir, ledger_dir] {
            let path = dir.join(PUB_FILE_NAME);
            if fs::read(&path).ok().as_deref() != Some(pub_line.as_bytes()) {
                write_file(&path, pub_line.as_bytes(), 0o644)
                    .map_err(LedgerError::WritePublicKey)?;
            }
        }
        Ok(signer)
    }

    /// Returns the base64 ed25519 signature over a record hash.
    pub fn sign(&self, hash_hex: &str) -> String {
        runebox_keys::encode(&self.key.sign(hash_hex.as_bytes()).to_bytes())
    }

    /// The signer's public key.
    pub fn public(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// The short public-key fingerprint recorded on signed events.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

fn create_dir_private(dir: &Path) -> io::Result<()> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
}

fn same_dir(a: &Path, b: &Path) -> bool {
    a == b
        || matches!(
            (fs::canonicalize(a), fs::canonicalize(b)),
            (Ok(x), Ok(y)) if x == y
        )
}

fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

/// Renames `from` to `to`, copying (0600) and removing across filesystems.
fn move_file(from: &Path, to: &Path) -> io::Result<()> {
    if fs::rename(from, to).is_ok() {
        return Ok(());
    }
    let data = fs::read(from)?;
    write_file(&to.to_path_buf(), &data, 0o600)?;
    fs::File::open(to)?.sync_all()?;
    fs::remove_file(from)
}

/// Like Go's os.WriteFile: the mode applies only when the file is created.
fn write_file(path: &PathBuf, data: &[u8], mode: u32) -> io::Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    opts.open(path)?.write_all(data)
}

/// Go's `base64.StdEncoding`: padding required, newlines ignored, and
/// non-zero trailing bits accepted.
const GO_STD_B64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
);

fn go_b64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    if s.contains(['\r', '\n']) {
        let cleaned: String = s.chars().filter(|c| !matches!(c, '\r' | '\n')).collect();
        return GO_STD_B64.decode(cleaned);
    }
    GO_STD_B64.decode(s)
}

/// Parses a base64-encoded ed25519 public key.
pub fn decode_public_key(s: &str) -> Result<VerifyingKey, LedgerError> {
    let raw = go_b64_decode(s).map_err(LedgerError::DecodePublicKey)?;
    if raw.len() != runebox_keys::PUBLIC_KEY_LEN {
        return Err(LedgerError::PublicKeySize(raw.len()));
    }
    runebox_keys::public_from_bytes(&raw).map_err(LedgerError::InvalidPublicKey)
}

/// Verifies a base64 signature over a record hash; a malformed signature
/// simply does not verify, as with Go's `ed25519.Verify`.
fn signature_ok(public: &VerifyingKey, hash: &str, sig: &[u8]) -> bool {
    Signature::from_slice(sig).is_ok_and(|sig| public.verify(hash.as_bytes(), &sig).is_ok())
}

impl Ledger {
    /// Recomputes every record's hash and checks signatures against
    /// `public`. When a key is given, or `require_all` is set, an unsigned
    /// record is an error.
    pub fn verify_signatures(
        &self,
        public: Option<&VerifyingKey>,
        require_all: bool,
    ) -> Result<(), LedgerError> {
        verify_records(&self.records()?, public, require_all)
    }

    /// Writes a [`Bundle`] of the session's events (all events when
    /// `session_id` is empty), embedding `public`.
    pub fn export_bundle<W: io::Write>(
        &self,
        w: W,
        session_id: &str,
        public: &VerifyingKey,
    ) -> Result<(), LedgerError> {
        let events = self.select(session_id)?;
        let scope = if session_id.is_empty() {
            "all".to_owned()
        } else {
            format!("session:{session_id}")
        };
        let bundle = BundleOut {
            key_id: runebox_keys::key_id(public),
            public_key: runebox_keys::encode_public(public),
            scope,
            events: events.as_deref(),
        };
        gojson::encode_indent(w, &bundle).map_err(LedgerError::ExportBundle)
    }
}

pub(crate) fn verify_records(
    recs: &[Event],
    public: Option<&VerifyingKey>,
    require_all: bool,
) -> Result<(), LedgerError> {
    if require_all && public.is_none() {
        return Err(LedgerError::SignaturesRequired);
    }
    let mut prev = "";
    for (i, ev) in recs.iter().enumerate() {
        check_link(i, ev, prev)?;
        prev = &ev.hash;
        if ev.sig.is_empty() {
            if require_all || public.is_some() {
                return Err(LedgerError::MissingSignature { seq: ev.seq });
            }
            continue;
        }
        let Some(public) = public else { continue };
        let sig = go_b64_decode(&ev.sig).map_err(|source| LedgerError::SignatureEncoding {
            seq: ev.seq,
            source,
        })?;
        if !signature_ok(public, &ev.hash, &sig) {
            return Err(LedgerError::BadSignature { seq: ev.seq });
        }
    }
    Ok(())
}

/// A self-contained export of events plus the public key needed to check
/// their signatures, verifiable with [`verify_bundle`]. Trust in the key
/// itself is established out of band.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Bundle {
    pub key_id: String,
    pub public_key: String,
    /// "all" or "session:<id>". Session exports may contain sequence gaps
    /// where other sessions' events were intentionally omitted.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub scope: String,
    pub events: Vec<Event>,
}

go_struct!(Bundle {
    "key_id" => key_id: Str,
    "public_key" => public_key: Str,
    "scope" => scope: Str,
    "events" => events: Events,
});

/// The exported form of a bundle; `events: None` encodes Go's nil slice.
#[derive(Serialize)]
struct BundleOut<'a> {
    key_id: String,
    public_key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    scope: String,
    events: Option<&'a [Event]>,
}

impl Bundle {
    /// Encodes the bundle as the Go exporter does (two-space indent and a
    /// trailing newline).
    pub fn to_json_pretty(&self) -> serde_json::Result<Vec<u8>> {
        gojson::marshal_indent(self)
    }

    /// Validates hashes, chain linkage, and a signature on every event,
    /// checked against the embedded public key, and returns the number of
    /// verified events. A session bundle need not start at seq 1, so linkage
    /// is checked between consecutive records only.
    pub fn verify(&self) -> Result<usize, LedgerError> {
        let public = decode_public_key(&self.public_key)?;
        let actual = runebox_keys::key_id(&public);
        if actual != self.key_id {
            return Err(LedgerError::BundleKeyId {
                declared: self.key_id.clone(),
                actual,
            });
        }
        let session = self.scope.strip_prefix("session:");
        let full = self.scope.is_empty() || self.scope == "all";
        for (index, ev) in self.events.iter().enumerate() {
            let fail = |problem| LedgerError::BundleEvent {
                index,
                seq: ev.seq,
                problem,
            };
            if ev.hash != hash_event(ev) {
                return Err(fail(BundleProblem::HashMismatch));
            }
            if let Some(prev) = index.checked_sub(1).map(|p| &self.events[p]) {
                if ev.seq <= prev.seq {
                    return Err(fail(BundleProblem::OutOfOrder));
                }
                // Full bundles must be contiguous. A session-scoped bundle can
                // legitimately skip global records belonging to other
                // sessions, but whenever two retained records are adjacent
                // their hash link must hold.
                let must_link = full || ev.seq == prev.seq + 1;
                if must_link && ev.prev_hash != prev.hash {
                    return Err(fail(BundleProblem::BrokenChain));
                }
            }
            if session.is_some_and(|s| ev.session_id != s) {
                return Err(fail(BundleProblem::OutsideScope));
            }
            if ev.sig.is_empty() {
                return Err(fail(BundleProblem::MissingSignature));
            }
            let sig = go_b64_decode(&ev.sig)
                .map_err(|source| LedgerError::BundleSignatureEncoding { index, source })?;
            if !signature_ok(&public, &ev.hash, &sig) {
                return Err(fail(BundleProblem::BadSignature));
            }
        }
        Ok(self.events.len())
    }
}

/// Decodes a bundle from r (the first JSON value; trailing data is ignored,
/// as with Go's `json.Decoder`) and verifies it. Returns the number of
/// verified events.
pub fn verify_bundle<R: Read>(r: R) -> Result<usize, LedgerError> {
    let mut de = serde_json::Deserializer::from_reader(r);
    let bundle = Bundle::deserialize(&mut de).map_err(LedgerError::DecodeBundle)?;
    bundle.verify()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_ledger(dir: &Path) -> (Ledger, Signer) {
        let l = Ledger::open(dir.join("ledger.jsonl")).expect("open");
        let signer = Signer::load_or_create(dir).expect("signer");
        l.set_signer(Some(signer.clone()));
        (l, signer)
    }

    fn ev(session: &str, action: &str) -> Event {
        Event {
            session_id: session.into(),
            tool: "shell".into(),
            action: action.into(),
            verdict: "allow".into(),
            ..Event::default()
        }
    }

    #[test]
    fn signed_ledger_verifies_and_detects_wrong_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (l, signer) = signed_ledger(dir.path());
        for _ in 0..3 {
            l.append(ev("", "echo")).expect("append");
        }
        l.verify_signatures(Some(&signer.public()), true)
            .expect("signatures verify");

        let other = Signer::load_or_create(tempfile::tempdir().expect("tempdir").path())
            .expect("other signer");
        assert!(matches!(
            l.verify_signatures(Some(&other.public()), true),
            Err(LedgerError::BadSignature { seq: 1 })
        ));
    }

    #[test]
    fn key_lives_apart_from_the_ledger() {
        let state = tempfile::tempdir().expect("tempdir");
        let keys = state.path().join(KEY_DIR_NAME);
        let a = Signer::load_or_create_apart(&keys, state.path()).expect("create");
        assert!(keys.join(KEY_FILE_NAME).exists());
        assert!(!state.path().join(KEY_FILE_NAME).exists());
        let pub_line = format!("{}\n", runebox_keys::encode_public(&a.public()));
        for dir in [keys.as_path(), state.path()] {
            assert_eq!(
                fs::read_to_string(dir.join(PUB_FILE_NAME)).expect("pub"),
                pub_line
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| fs::metadata(p).expect("stat").permissions().mode() & 0o777;
            assert_eq!(mode(&keys), 0o700);
            assert_eq!(mode(&keys.join(KEY_FILE_NAME)), 0o400);
        }
        // Reloads the same key (the read-only file is never rewritten).
        let b = Signer::load_or_create_apart(&keys, state.path()).expect("reload");
        assert_eq!(a.public(), b.public());
    }

    #[test]
    fn key_beside_the_ledger_moves_into_the_key_dir() {
        let state = tempfile::tempdir().expect("tempdir");
        let old = Signer::load_or_create(state.path()).expect("old layout");
        let keys = state.path().join("elsewhere");
        let moved = Signer::load_or_create_apart(&keys, state.path()).expect("migrate");
        assert_eq!(old.public(), moved.public());
        assert!(!state.path().join(KEY_FILE_NAME).exists());
        assert!(keys.join(KEY_FILE_NAME).exists());

        // An identical leftover copy is removed; a different one is refused.
        fs::write(
            state.path().join(KEY_FILE_NAME),
            fs::read(keys.join(KEY_FILE_NAME)).expect("read"),
        )
        .expect("copy");
        Signer::load_or_create_apart(&keys, state.path()).expect("same key");
        assert!(!state.path().join(KEY_FILE_NAME).exists());
        let other = tempfile::tempdir().expect("tempdir");
        Signer::load_or_create(other.path()).expect("other key");
        fs::copy(
            other.path().join(KEY_FILE_NAME),
            state.path().join(KEY_FILE_NAME),
        )
        .expect("copy");
        assert!(matches!(
            Signer::load_or_create_apart(&keys, state.path()),
            Err(LedgerError::KeyConflict { .. })
        ));
    }

    #[test]
    fn key_dir_equal_to_the_ledger_dir_keeps_the_old_layout() {
        let state = tempfile::tempdir().expect("tempdir");
        Signer::load_or_create_apart(state.path(), state.path()).expect("same dir");
        assert!(state.path().join(KEY_FILE_NAME).exists());
    }

    #[test]
    fn load_or_create_persists_and_reloads() {
        let dir = tempfile::tempdir().expect("tempdir");
        let a = Signer::load_or_create(dir.path()).expect("create");
        let b = Signer::load_or_create(dir.path()).expect("reload");
        assert_eq!(a.public(), b.public());
        assert_eq!(a.key_id(), b.key_id());
        let pub_file = fs::read_to_string(dir.path().join(PUB_FILE_NAME)).expect("pub");
        assert_eq!(
            pub_file,
            format!("{}\n", runebox_keys::encode_public(&a.public()))
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join(KEY_FILE_NAME))
                .expect("stat")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        fs::write(dir.path().join(KEY_FILE_NAME), [0u8; 10]).expect("truncate key");
        assert!(matches!(
            Signer::load_or_create(dir.path()),
            Err(LedgerError::KeySize { size: 10, .. })
        ));
    }

    #[test]
    fn export_and_verify_bundle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (l, signer) = signed_ledger(dir.path());
        for _ in 0..4 {
            l.append(ev("s1", "cmd")).expect("append");
        }
        let mut buf = Vec::new();
        l.export_bundle(&mut buf, "s1", &signer.public())
            .expect("export bundle");
        assert_eq!(verify_bundle(buf.as_slice()).expect("verify"), 4);

        let text = String::from_utf8(buf).expect("utf8");
        let corrupt = text.replacen("\"cmd\"", "\"xxx\"", 1);
        assert!(matches!(
            verify_bundle(corrupt.as_bytes()),
            Err(LedgerError::BundleEvent {
                problem: BundleProblem::HashMismatch,
                ..
            })
        ));
    }

    #[test]
    fn session_bundle_verifies_with_interleaved_global_events() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (l, signer) = signed_ledger(dir.path());
        for s in ["s1", "s2", "s1"] {
            l.append(ev(s, "echo")).expect("append");
        }
        let mut buf = Vec::new();
        l.export_bundle(&mut buf, "s1", &signer.public())
            .expect("export");
        assert_eq!(verify_bundle(buf.as_slice()).expect("verify"), 2);

        // The same gap is fatal in a full bundle, and scope is enforced.
        let mut b: Bundle = serde_json::from_slice(&buf).expect("decode");
        b.scope = "all".into();
        assert!(matches!(
            b.verify(),
            Err(LedgerError::BundleEvent {
                problem: BundleProblem::BrokenChain,
                ..
            })
        ));
        b.scope = "session:s2".into();
        assert!(matches!(
            b.verify(),
            Err(LedgerError::BundleEvent {
                problem: BundleProblem::OutsideScope,
                ..
            })
        ));
    }

    #[test]
    fn empty_full_bundle_encodes_null_events() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (l, signer) = signed_ledger(dir.path());
        let mut buf = Vec::new();
        l.export_bundle(&mut buf, "", &signer.public())
            .expect("export");
        let text = String::from_utf8(buf).expect("utf8");
        assert!(text.ends_with("\"events\": null\n}\n"), "{text}");
        assert_eq!(verify_bundle(text.as_bytes()).expect("verify"), 0);
    }

    #[test]
    fn verify_signatures_requires_all_when_key_provided() {
        let dir = tempfile::tempdir().expect("tempdir");
        let l = Ledger::open(dir.path().join("ledger.jsonl")).expect("open");
        for _ in 0..2 {
            l.append(ev("", "echo")).expect("append");
        }
        let signer =
            Signer::load_or_create(tempfile::tempdir().expect("tempdir").path()).expect("signer");
        assert!(matches!(
            l.verify_signatures(Some(&signer.public()), false),
            Err(LedgerError::MissingSignature { seq: 1 })
        ));
        assert!(matches!(
            l.verify_signatures(None, true),
            Err(LedgerError::SignaturesRequired)
        ));
    }

    #[test]
    fn verify_signatures_allows_unsigned_without_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let l = Ledger::open(dir.path().join("ledger.jsonl")).expect("open");
        for _ in 0..2 {
            l.append(ev("", "echo")).expect("append");
        }
        l.verify_signatures(None, false)
            .expect("unsigned ledger verifies without key");
    }

    #[test]
    fn base64_decoding_matches_go() {
        // Newlines are skipped and non-canonical trailing bits accepted.
        assert_eq!(go_b64_decode("aGk=\n").expect("newline"), b"hi");
        assert_eq!(go_b64_decode("aGl=").expect("trailing bits"), b"hi");
        assert!(go_b64_decode("aGk").is_err(), "padding is required");
        assert!(go_b64_decode(" aGk=").is_err(), "spaces are not skipped");
    }
}
