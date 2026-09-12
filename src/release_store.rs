//! Transactional, filesystem-backed release publication and private download.
//!
//! A publication declares immutable target sizes and hashes, streams each body
//! into a staging directory, then atomically replaces a small channel document
//! only after every target has been revalidated. Readers therefore observe the
//! previous complete build or the next complete build, never a partial mix.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::{AuthContext, Principal};
use crate::config::ReleaseStoreConfig;
use crate::reply::Reply;

const MAX_CONTROL_BODY: u64 = 256 * 1024;
const MAX_TARGETS: usize = 16;
static STORE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone)]
pub struct ReleaseStore {
    cfg: ReleaseStoreConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BeginPublication {
    schema: u32,
    channel: String,
    release: String,
    commit: String,
    sequence: u64,
    published_at: String,
    targets: BTreeMap<String, ArtifactSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactSpec {
    sha256: String,
    size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PublicationState {
    id: String,
    request: BeginPublication,
    identity: PublicationIdentity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PublicationIdentity {
    repository_id: String,
    workflow_ref: String,
    run_id: String,
    run_attempt: String,
    commit: String,
}

#[derive(Debug)]
struct StoreError {
    status: u16,
    message: String,
}

impl StoreError {
    fn new(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
    fn internal(context: &str, error: impl std::fmt::Display) -> Self {
        eprintln!("gatekeeper: release store: {context}: {error}");
        Self::new(500, "release store failure")
    }
    fn reply(self) -> Reply {
        Reply::status(self.status, &self.message)
            .with_header("Cache-Control", "private, no-store")
            .with_header("X-Content-Type-Options", "nosniff")
    }
}

impl ReleaseStore {
    pub fn new(cfg: ReleaseStoreConfig) -> Result<Self, String> {
        let store = Self { cfg };
        store.ensure_layout().map_err(|e| e.message)?;
        Ok(store)
    }

    pub fn handle(
        &self,
        auth: &AuthContext,
        method: &str,
        rest: &str,
        headers: &[tiny_http::Header],
        body_length: Option<usize>,
        body: &mut dyn Read,
    ) -> Reply {
        let result = match split_path(rest).as_slice() {
            ["publications"] if method == "POST" => self
                .require(auth, &self.cfg.publish_scope)
                .and_then(|_| read_control(body, body_length))
                .and_then(|bytes| self.begin(auth, &bytes))
                .map(json_reply),
            ["publications", id, target] if method == "PUT" => self
                .require(auth, &self.cfg.publish_scope)
                .and_then(|_| self.upload(auth, id, target, body_length, body))
                .map(json_reply),
            ["publications", id, "complete"] if method == "POST" => self
                .require(auth, &self.cfg.publish_scope)
                .and_then(|_| self.complete(auth, id))
                .map(json_reply),
            ["channels", file] if method == "GET" || method == "HEAD" => self
                .require(auth, &self.cfg.read_scope)
                .and_then(|_| self.channel(file, method == "HEAD")),
            ["builds", commit, file] if method == "GET" || method == "HEAD" => self
                .require(auth, &self.cfg.read_scope)
                .and_then(|_| self.artifact(commit, file, method == "HEAD", headers)),
            _ => Err(StoreError::new(404, "Not Found")),
        };
        result.unwrap_or_else(StoreError::reply)
    }

    fn require(&self, auth: &AuthContext, scope: &str) -> Result<(), StoreError> {
        if auth.allows(&[scope.to_string()]) {
            Ok(())
        } else {
            Err(StoreError::new(403, "Forbidden"))
        }
    }

    fn begin(&self, auth: &AuthContext, bytes: &[u8]) -> Result<serde_json::Value, StoreError> {
        let request: BeginPublication = serde_json::from_slice(bytes)
            .map_err(|e| StoreError::new(400, format!("invalid publication: {e}")))?;
        validate_begin(&request, self.cfg.max_artifact_bytes)?;
        let identity = publication_identity(auth)?;
        if identity.commit != request.commit {
            return Err(StoreError::new(
                403,
                "OIDC commit does not match publication",
            ));
        }
        let _guard = STORE_LOCK
            .lock()
            .map_err(|_| StoreError::new(500, "store lock poisoned"))?;
        self.ensure_layout()?;
        let id = uuid::Uuid::new_v4().simple().to_string();
        let dir = self.staging().join(&id);
        create_private_dir(&dir)?;
        let state = PublicationState {
            id: id.clone(),
            request,
            identity,
        };
        write_json_atomic(&dir.join("publication.json"), &state)?;
        Ok(serde_json::json!({ "publication": id, "state": "open" }))
    }

    fn upload(
        &self,
        auth: &AuthContext,
        id: &str,
        target: &str,
        body_length: Option<usize>,
        body: &mut dyn Read,
    ) -> Result<serde_json::Value, StoreError> {
        validate_segment(id, "publication id")?;
        validate_target(target)?;
        let identity = publication_identity(auth)?;
        let _guard = STORE_LOCK
            .lock()
            .map_err(|_| StoreError::new(500, "store lock poisoned"))?;
        let state = self.read_state(id)?;
        require_same_identity(&state.identity, &identity)?;
        let spec = state
            .request
            .targets
            .get(target)
            .ok_or_else(|| StoreError::new(404, "undeclared target"))?;
        if body_length.map(|n| n as u64) != Some(spec.size) {
            return Err(StoreError::new(
                400,
                "Content-Length does not match declaration",
            ));
        }
        let dir = self.staging().join(id);
        let final_path = dir.join(artifact_name(target));
        if final_path.exists() {
            let (size, hash) = hash_file(&final_path)?;
            if size == spec.size && hash == spec.sha256 {
                return Ok(serde_json::json!({ "target": target, "state": "uploaded" }));
            }
            return Err(StoreError::new(
                409,
                "target already exists with different contents",
            ));
        }
        let partial = dir.join(format!("{}.partial", artifact_name(target)));
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&partial)
            .map_err(|e| StoreError::internal("creating upload", e))?;
        out.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| StoreError::internal("setting upload permissions", e))?;
        let copied = copy_hashed(body, &mut out, spec.size);
        let (size, hash) = match copied {
            Ok(result) => result,
            Err(error) => {
                let _ = fs::remove_file(&partial);
                return Err(error);
            }
        };
        if size != spec.size || hash != spec.sha256 {
            let _ = fs::remove_file(&partial);
            return Err(StoreError::new(400, "uploaded artifact checksum mismatch"));
        }
        out.sync_all()
            .map_err(|e| StoreError::internal("syncing upload", e))?;
        fs::rename(&partial, &final_path)
            .map_err(|e| StoreError::internal("committing upload", e))?;
        sync_dir(&dir)?;
        Ok(serde_json::json!({ "target": target, "state": "uploaded" }))
    }

    fn complete(&self, auth: &AuthContext, id: &str) -> Result<serde_json::Value, StoreError> {
        validate_segment(id, "publication id")?;
        let identity = publication_identity(auth)?;
        let _guard = STORE_LOCK
            .lock()
            .map_err(|_| StoreError::new(500, "store lock poisoned"))?;
        let state = self.read_state(id)?;
        require_same_identity(&state.identity, &identity)?;
        let stage = self.staging().join(id);
        let builds = self.builds();
        let destination = builds.join(&state.request.commit);
        if destination.exists() {
            let existing: serde_json::Value =
                read_json_bounded(&destination.join("manifest.json"))?;
            let manifest = channel_manifest(&state.request);
            if existing != manifest {
                return Err(StoreError::new(
                    409,
                    "commit already exists with different metadata",
                ));
            }
            self.promote_channel(&state.request, &manifest)?;
            return Ok(serde_json::json!({
                "channel": state.request.channel,
                "commit": state.request.commit,
                "state": "published"
            }));
        }
        for (target, spec) in &state.request.targets {
            let (size, hash) = hash_file(&stage.join(artifact_name(target)))?;
            if size != spec.size || hash != spec.sha256 {
                return Err(StoreError::new(
                    409,
                    format!("target {target} is incomplete"),
                ));
            }
        }

        let incoming = builds.join(format!("{}.incoming-{}", state.request.commit, id));
        if incoming.exists() {
            fs::remove_dir_all(&incoming)
                .map_err(|e| StoreError::internal("cleaning interrupted build", e))?;
        }
        create_private_dir(&incoming)?;
        for target in state.request.targets.keys() {
            fs::hard_link(
                stage.join(artifact_name(target)),
                incoming.join(artifact_name(target)),
            )
            .map_err(|e| StoreError::internal("linking completed artifact", e))?;
        }
        let manifest = channel_manifest(&state.request);
        write_json_atomic(&incoming.join("manifest.json"), &manifest)?;
        sync_dir(&incoming)?;
        fs::rename(&incoming, &destination)
            .map_err(|e| StoreError::internal("committing immutable build", e))?;
        sync_dir(&builds)?;

        self.promote_channel(&state.request, &manifest)?;
        self.collect_old_builds()?;
        Ok(serde_json::json!({
            "channel": state.request.channel,
            "commit": state.request.commit,
            "state": "published"
        }))
    }

    fn promote_channel(
        &self,
        request: &BeginPublication,
        manifest: &serde_json::Value,
    ) -> Result<(), StoreError> {
        let path = self.channels().join(format!("{}.json", request.channel));
        if path.exists() {
            let current: serde_json::Value = read_json_bounded(&path)?;
            let current_commit = current.get("commit").and_then(|v| v.as_str());
            let current_sequence = current
                .get("sequence")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            if current_commit != Some(request.commit.as_str())
                && request.sequence <= current_sequence
            {
                return Err(StoreError::new(409, "channel sequence must increase"));
            }
        }
        write_json_atomic(&path, manifest)
    }

    fn channel(&self, file: &str, head: bool) -> Result<Reply, StoreError> {
        let channel = file
            .strip_suffix(".json")
            .ok_or_else(|| StoreError::new(404, "Not Found"))?;
        validate_segment(channel, "channel")?;
        self.stream_file(
            self.channels().join(file),
            head,
            None,
            "application/vnd.coil.update+json; version=1",
        )
    }

    fn artifact(
        &self,
        commit: &str,
        file: &str,
        head: bool,
        headers: &[tiny_http::Header],
    ) -> Result<Reply, StoreError> {
        validate_commit(commit)?;
        if !file.starts_with("coil-") || !file.ends_with(".tar.gz") {
            return Err(StoreError::new(404, "Not Found"));
        }
        validate_segment(file, "artifact")?;
        let range = header(headers, "range");
        self.stream_file(
            self.builds().join(commit).join(file),
            head,
            range,
            "application/gzip",
        )
    }

    fn stream_file(
        &self,
        path: PathBuf,
        head: bool,
        range: Option<&str>,
        content_type: &str,
    ) -> Result<Reply, StoreError> {
        let meta = fs::symlink_metadata(&path).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => StoreError::new(404, "Not Found"),
            _ => StoreError::internal("reading artifact metadata", e),
        })?;
        if !meta.file_type().is_file() {
            return Err(StoreError::new(404, "Not Found"));
        }
        let total = meta.len();
        let (start, end, status) = match range {
            None => (0, total.saturating_sub(1), 200),
            Some(raw) => {
                let (start, end) = parse_range(raw, total)?;
                (start, end, 206)
            }
        };
        let length = if total == 0 { 0 } else { end - start + 1 };
        let mut file =
            File::open(&path).map_err(|e| StoreError::internal("opening artifact", e))?;
        file.seek(SeekFrom::Start(start))
            .map_err(|e| StoreError::internal("seeking artifact", e))?;
        let body: Box<dyn Read + Send> = if head {
            Box::new(io::empty())
        } else {
            Box::new(file.take(length))
        };
        let mut reply = Reply::stream_len(status, body, length as usize)
            .with_header("Content-Type", content_type)
            .with_header("Cache-Control", "private, no-store")
            .with_header("Accept-Ranges", "bytes")
            .with_header("X-Content-Type-Options", "nosniff");
        if status == 206 {
            reply = reply.with_header("Content-Range", &format!("bytes {start}-{end}/{total}"));
        }
        Ok(reply)
    }

    fn read_state(&self, id: &str) -> Result<PublicationState, StoreError> {
        read_json_bounded(&self.staging().join(id).join("publication.json"))
    }

    fn ensure_layout(&self) -> Result<(), StoreError> {
        create_private_dir(&self.cfg.root)?;
        create_private_dir(&self.channels())?;
        create_private_dir(&self.builds())?;
        create_private_dir(&self.staging())?;
        Ok(())
    }

    fn channels(&self) -> PathBuf {
        self.cfg.root.join("channels")
    }
    fn builds(&self) -> PathBuf {
        self.cfg.root.join("builds")
    }
    fn staging(&self) -> PathBuf {
        self.cfg.root.join("staging")
    }

    fn collect_old_builds(&self) -> Result<(), StoreError> {
        let mut protected = std::collections::BTreeSet::new();
        for entry in fs::read_dir(self.channels())
            .map_err(|e| StoreError::internal("listing channels", e))?
        {
            let entry = entry.map_err(|e| StoreError::internal("reading channel entry", e))?;
            if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                if let Ok(value) = read_json_bounded::<serde_json::Value>(&entry.path()) {
                    if let Some(commit) = value.get("commit").and_then(|v| v.as_str()) {
                        protected.insert(commit.to_string());
                    }
                }
            }
        }
        let mut builds = Vec::new();
        for entry in
            fs::read_dir(self.builds()).map_err(|e| StoreError::internal("listing builds", e))?
        {
            let entry = entry.map_err(|e| StoreError::internal("reading build entry", e))?;
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                let modified = entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::UNIX_EPOCH);
                builds.push((modified, entry));
            }
        }
        builds.sort_by_key(|(modified, _)| std::cmp::Reverse(*modified));
        for (_, entry) in builds.into_iter().skip(self.cfg.retain_builds) {
            let name = entry.file_name().to_string_lossy().to_string();
            if !protected.contains(&name) {
                fs::remove_dir_all(entry.path())
                    .map_err(|e| StoreError::internal("removing expired build", e))?;
            }
        }
        Ok(())
    }
}

fn publication_identity(auth: &AuthContext) -> Result<PublicationIdentity, StoreError> {
    match &auth.principal {
        Principal::GitHubActions(p) => Ok(PublicationIdentity {
            repository_id: p.repository_id.clone(),
            workflow_ref: p.workflow_ref.clone(),
            run_id: p.run_id.clone(),
            run_attempt: p.run_attempt.clone(),
            commit: p.commit.clone(),
        }),
        _ => Err(StoreError::new(403, "GitHub OIDC identity required")),
    }
}

fn require_same_identity(
    expected: &PublicationIdentity,
    got: &PublicationIdentity,
) -> Result<(), StoreError> {
    if expected == got {
        Ok(())
    } else {
        Err(StoreError::new(
            403,
            "publication belongs to another workflow run",
        ))
    }
}

fn validate_begin(request: &BeginPublication, max_size: u64) -> Result<(), StoreError> {
    if request.schema != 1
        || request.sequence == 0
        || request.release.is_empty()
        || request.published_at.is_empty()
    {
        return Err(StoreError::new(400, "invalid publication metadata"));
    }
    validate_commit(&request.commit)?;
    validate_segment(&request.channel, "channel")?;
    if request.targets.is_empty() || request.targets.len() > MAX_TARGETS {
        return Err(StoreError::new(400, "invalid target count"));
    }
    for (target, spec) in &request.targets {
        validate_target(target)?;
        if spec.size == 0 || spec.size > max_size || !valid_sha256(&spec.sha256) {
            return Err(StoreError::new(
                400,
                format!("invalid declaration for target {target}"),
            ));
        }
    }
    Ok(())
}

fn channel_manifest(request: &BeginPublication) -> serde_json::Value {
    let targets: serde_json::Map<String, serde_json::Value> = request
        .targets
        .iter()
        .map(|(target, spec)| {
            (
                target.clone(),
                serde_json::json!({
                    "artifact": format!("../builds/{}/{}", request.commit, artifact_name(target)),
                    "sha256": spec.sha256,
                    "size": spec.size
                }),
            )
        })
        .collect();
    serde_json::json!({
        "schema": 1,
        "channel": request.channel,
        "release": request.release,
        "commit": request.commit,
        "sequence": request.sequence,
        "published_at": request.published_at,
        "targets": targets
    })
}

fn copy_hashed(
    input: &mut dyn Read,
    output: &mut File,
    expected: u64,
) -> Result<(u64, String), StoreError> {
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    while total < expected {
        let want = usize::try_from((expected - total).min(buffer.len() as u64)).unwrap();
        let read = input
            .read(&mut buffer[..want])
            .map_err(|e| StoreError::internal("reading upload", e))?;
        if read == 0 {
            break;
        }
        output
            .write_all(&buffer[..read])
            .map_err(|e| StoreError::internal("writing upload", e))?;
        hash.update(&buffer[..read]);
        total += read as u64;
    }
    Ok((total, hex(&hash.finalize())))
}

fn hash_file(path: &Path) -> Result<(u64, String), StoreError> {
    let mut file = File::open(path).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => StoreError::new(409, "publication is incomplete"),
        _ => StoreError::internal("opening staged artifact", e),
    })?;
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|e| StoreError::internal("hashing artifact", e))?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
        total += read as u64;
    }
    Ok((total, hex(&hash.finalize())))
}

fn read_control(body: &mut dyn Read, length: Option<usize>) -> Result<Vec<u8>, StoreError> {
    if length
        .map(|n| n as u64)
        .is_none_or(|n| n > MAX_CONTROL_BODY)
    {
        return Err(StoreError::new(411, "bounded Content-Length required"));
    }
    let mut bytes = Vec::with_capacity(length.unwrap());
    body.take(MAX_CONTROL_BODY + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| StoreError::internal("reading control request", e))?;
    if bytes.len() as u64 > MAX_CONTROL_BODY {
        return Err(StoreError::new(413, "request too large"));
    }
    Ok(bytes)
}

fn read_json_bounded<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, StoreError> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => StoreError::new(404, "Not Found"),
            _ => StoreError::internal("opening metadata", e),
        })?
        .take(MAX_CONTROL_BODY + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| StoreError::internal("reading metadata", e))?;
    if bytes.len() as u64 > MAX_CONTROL_BODY {
        return Err(StoreError::new(500, "stored metadata too large"));
    }
    serde_json::from_slice(&bytes).map_err(|e| StoreError::internal("parsing stored metadata", e))
}

fn write_json_atomic(path: &Path, value: &impl Serialize) -> Result<(), StoreError> {
    let parent = path
        .parent()
        .ok_or_else(|| StoreError::new(500, "metadata has no parent"))?;
    let temp = parent.join(format!(
        ".{}.{}.incoming",
        path.file_name().unwrap().to_string_lossy(),
        uuid::Uuid::new_v4().simple()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options
        .open(&temp)
        .map_err(|e| StoreError::internal("creating metadata", e))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|e| StoreError::internal("setting metadata permissions", e))?;
    serde_json::to_writer_pretty(&mut file, value)
        .map_err(|e| StoreError::internal("serializing metadata", e))?;
    file.write_all(b"\n")
        .map_err(|e| StoreError::internal("writing metadata", e))?;
    file.sync_all()
        .map_err(|e| StoreError::internal("syncing metadata", e))?;
    fs::rename(&temp, path).map_err(|e| StoreError::internal("committing metadata", e))?;
    sync_dir(parent)
}

fn create_private_dir(path: &Path) -> Result<(), StoreError> {
    fs::create_dir_all(path).map_err(|e| StoreError::internal("creating release directory", e))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|e| StoreError::internal("setting release directory permissions", e))
}

fn sync_dir(path: &Path) -> Result<(), StoreError> {
    File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|e| StoreError::internal("syncing release directory", e))
}

fn parse_range(raw: &str, total: u64) -> Result<(u64, u64), StoreError> {
    let value = raw
        .strip_prefix("bytes=")
        .ok_or_else(|| StoreError::new(416, "invalid range"))?;
    if value.contains(',') || total == 0 {
        return Err(StoreError::new(416, "invalid range"));
    }
    let (left, right) = value
        .split_once('-')
        .ok_or_else(|| StoreError::new(416, "invalid range"))?;
    let (start, end) = if left.is_empty() {
        let suffix: u64 = right
            .parse()
            .map_err(|_| StoreError::new(416, "invalid range"))?;
        if suffix == 0 {
            return Err(StoreError::new(416, "invalid range"));
        }
        (total.saturating_sub(suffix), total - 1)
    } else {
        let start: u64 = left
            .parse()
            .map_err(|_| StoreError::new(416, "invalid range"))?;
        let end = if right.is_empty() {
            total - 1
        } else {
            right
                .parse()
                .map_err(|_| StoreError::new(416, "invalid range"))?
        };
        (start, end.min(total - 1))
    };
    if start >= total || start > end {
        return Err(StoreError::new(416, "invalid range"));
    }
    Ok((start, end))
}

fn split_path(rest: &str) -> Vec<&str> {
    rest.trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect()
}

fn validate_target(value: &str) -> Result<(), StoreError> {
    validate_segment(value, "target")?;
    if !value.contains('-') {
        return Err(StoreError::new(400, "invalid target"));
    }
    Ok(())
}

fn validate_commit(value: &str) -> Result<(), StoreError> {
    if (value.len() == 40 || value.len() == 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(StoreError::new(400, "invalid commit"))
    }
}

fn validate_segment(value: &str, what: &str) -> Result<(), StoreError> {
    if value.is_empty()
        || value.len() > 160
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        Err(StoreError::new(400, format!("invalid {what}")))
    } else {
        Ok(())
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn artifact_name(target: &str) -> String {
    format!("coil-{target}.tar.gz")
}

fn header<'a>(headers: &'a [tiny_http::Header], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn json_reply(value: serde_json::Value) -> Reply {
    Reply::new(200, serde_json::to_vec(&value).unwrap())
        .with_header("Content-Type", "application/json")
        .with_header("Cache-Control", "private, no-store")
        .with_header("X-Content-Type-Options", "nosniff")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn publisher(commit: &str, run: &str) -> AuthContext {
        AuthContext {
            principal: Principal::GitHubActions(crate::oidc::GitHubPrincipal {
                policy: "coil-nightly".into(),
                repository_id: "123".into(),
                repository_owner_id: "456".into(),
                workflow_ref: "jimmyhmiller/coil/.github/workflows/nightly.yml@refs/heads/main"
                    .into(),
                run_id: run.into(),
                run_attempt: "1".into(),
                commit: commit.into(),
            }),
            scopes: vec!["coil:nightly:publish".into()],
        }
    }

    fn test_store() -> (ReleaseStore, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "gatekeeper-release-store-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let store = ReleaseStore::new(ReleaseStoreConfig {
            root: root.clone(),
            read_scope: "coil:read".into(),
            publish_scope: "coil:nightly:publish".into(),
            max_artifact_bytes: 1024 * 1024,
            retain_builds: 3,
        })
        .unwrap();
        (store, root)
    }

    #[test]
    fn ranges_cover_closed_open_and_suffix_forms() {
        assert_eq!(parse_range("bytes=2-5", 10).unwrap(), (2, 5));
        assert_eq!(parse_range("bytes=7-", 10).unwrap(), (7, 9));
        assert_eq!(parse_range("bytes=-3", 10).unwrap(), (7, 9));
        assert!(parse_range("bytes=10-", 10).is_err());
        assert!(parse_range("bytes=1-2,4-5", 10).is_err());
    }

    #[test]
    fn publication_validation_rejects_paths_and_oversize_artifacts() {
        let mut targets = BTreeMap::new();
        targets.insert(
            "../mac".into(),
            ArtifactSpec {
                sha256: "0".repeat(64),
                size: 1,
            },
        );
        let request = BeginPublication {
            schema: 1,
            channel: "nightly".into(),
            release: "nightly-1".into(),
            commit: "0".repeat(40),
            sequence: 1,
            published_at: "2026-09-12T00:00:00Z".into(),
            targets,
        };
        assert!(validate_begin(&request, 1024).is_err());
    }

    #[test]
    fn publication_is_invisible_until_complete_and_completion_is_idempotent() {
        let (store, root) = test_store();
        let commit = "1".repeat(40);
        let bytes = b"complete toolchain archive";
        let hash = hex(&Sha256::digest(bytes));
        let request = serde_json::json!({
            "schema": 1,
            "channel": "nightly",
            "release": "nightly-test",
            "commit": commit,
            "sequence": 1,
            "published_at": "2026-09-12T00:00:00Z",
            "targets": {
                "aarch64-apple-darwin": { "sha256": hash, "size": bytes.len() }
            }
        });
        let auth = publisher(&commit, "77");
        let begun = store
            .begin(&auth, &serde_json::to_vec(&request).unwrap())
            .unwrap();
        let id = begun["publication"].as_str().unwrap();
        assert!(!root.join("channels/nightly.json").exists());
        store
            .upload(
                &auth,
                id,
                "aarch64-apple-darwin",
                Some(bytes.len()),
                &mut io::Cursor::new(bytes),
            )
            .unwrap();
        assert!(!root.join("channels/nightly.json").exists());
        store.complete(&auth, id).unwrap();
        store.complete(&auth, id).unwrap();
        let channel: serde_json::Value =
            read_json_bounded(&root.join("channels/nightly.json")).unwrap();
        assert_eq!(channel["commit"], commit);
        assert_eq!(
            fs::read(root.join(format!("builds/{commit}/coil-aarch64-apple-darwin.tar.gz")))
                .unwrap(),
            bytes
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn another_workflow_run_cannot_continue_publication() {
        let (store, root) = test_store();
        let commit = "2".repeat(40);
        let request = serde_json::json!({
            "schema": 1,
            "channel": "nightly",
            "release": "nightly-test",
            "commit": commit,
            "sequence": 1,
            "published_at": "2026-09-12T00:00:00Z",
            "targets": { "linux-x86_64": { "sha256": "0".repeat(64), "size": 1 } }
        });
        let begun = store
            .begin(
                &publisher(&commit, "one"),
                &serde_json::to_vec(&request).unwrap(),
            )
            .unwrap();
        let id = begun["publication"].as_str().unwrap();
        let error = store
            .upload(
                &publisher(&commit, "two"),
                id,
                "linux-x86_64",
                Some(1),
                &mut io::Cursor::new(b"x"),
            )
            .unwrap_err();
        assert_eq!(error.status, 403);
        fs::remove_dir_all(root).unwrap();
    }
}
