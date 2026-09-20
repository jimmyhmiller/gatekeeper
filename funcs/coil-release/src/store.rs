//! Transactional, filesystem-backed release publication and private download.
//!
//! A publication declares immutable target sizes and hashes, streams each body
//! into a staging directory, then atomically replaces a small channel document
//! only after every target has been revalidated. Readers therefore observe the
//! previous complete build or the next complete build, never a partial mix.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use gatekeeper_fn::Response;

use crate::caller::{Caller, GitHubClaims, Settings};

const MAX_CONTROL_BODY: u64 = 256 * 1024;
const MAX_TARGETS: usize = 16;
/// Serializes every mutation of the store.
///
/// This is an `flock` on a file in the store root rather than a process-global
/// `Mutex` because this code lives in a dylib the gate may unload and reload: a
/// mutex belongs to one loaded image, so a reload between two requests would
/// hand them different locks. A file lock is held by the process, outlives any
/// image, and the kernel drops it if we die holding it.
struct StoreLock(File);

impl StoreLock {
    fn acquire(path: &Path) -> Result<Self, StoreError> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)
            .map_err(|e| StoreError::internal("opening store lock", e))?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| StoreError::internal("securing store lock", e))?;
        // SAFETY: a valid fd we own for the lifetime of `file`.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(StoreError::internal(
                "locking store",
                io::Error::last_os_error(),
            ));
        }
        Ok(StoreLock(file))
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        // SAFETY: same fd, still open; the close in `File::drop` would release
        // the lock anyway, so a failure here is not actionable.
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[derive(Clone)]
pub struct ReleaseStore {
    cfg: Settings,
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

/// The run that owns an open publication, persisted beside it so a resumed
/// upload can be checked against whoever opened the transaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PublicationIdentity(GitHubClaims);

/// One request, as this store needs to see it. A struct rather than six more
/// parameters on `handle`, for the same reason the gate groups its own: that is
/// how a call site starts passing the wrong string to the wrong argument.
pub struct Incoming<'a> {
    pub method: &'a str,
    /// Path after the route prefix, already normalized by the gate.
    pub rest: &'a str,
    /// Raw query string, without the leading `?`.
    pub query: &'a str,
    pub headers: &'a [(String, String)],
    /// The declared `Content-Length`, checked against what actually arrives.
    pub body_length: Option<u64>,
    pub body: &'a mut dyn Read,
}

/// What a channel currently publishes.
#[derive(Debug, Clone)]
struct ChannelHead {
    commit: String,
    sequence: u64,
}

/// The channel's ordering rule, stated once. A publication may replace the head
/// only by naming the head's own commit — completion is idempotent — or by
/// advancing the sequence. `promote_channel` enforces this and `preflight`
/// reports it, so the two can never disagree about what would be accepted.
fn advances_channel(head: Option<&ChannelHead>, commit: &str, sequence: u64) -> bool {
    match head {
        None => true,
        Some(head) => head.commit == commit || sequence > head.sequence,
    }
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
    fn reply(self) -> Response {
        Response::status(self.status, self.message)
            .header("Cache-Control", "private, no-store")
            .header("X-Content-Type-Options", "nosniff")
    }
}

impl ReleaseStore {
    pub fn new(cfg: Settings) -> Result<Self, String> {
        let store = Self { cfg };
        store.ensure_layout().map_err(|e| e.message)?;
        Ok(store)
    }

    pub fn handle(&self, auth: &Caller, request: Incoming<'_>) -> Response {
        let Incoming { method, rest, query, headers, body_length, body } = request;
        let result = match split_path(rest).as_slice() {
            ["publications", "preflight"] if method == "GET" => self
                .require(auth, &self.cfg.publish_scope)
                .and_then(|_| self.preflight(query))
                .map(json_reply),
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

    fn require(&self, auth: &Caller, scope: &str) -> Result<(), StoreError> {
        if auth.allows(scope) {
            Ok(())
        } else {
            Err(StoreError::new(403, "Forbidden"))
        }
    }

    /// Answer, before a build spends two hours earning a 409, whether publishing
    /// `commit` to `channel` at `sequence` would do anything.
    ///
    /// Three answers, deliberately not two. `current` means the channel already
    /// publishes this commit and the run has nothing to do; `conflict` means the
    /// publication could never be accepted. Collapsing them into one boolean
    /// would turn a misordered channel into a silently green build that never
    /// publishes again.
    fn preflight(&self, query: &str) -> Result<serde_json::Value, StoreError> {
        let params = parse_query(query);
        let channel = params
            .get("channel")
            .ok_or_else(|| StoreError::new(400, "preflight needs a channel"))?;
        let commit = params
            .get("commit")
            .ok_or_else(|| StoreError::new(400, "preflight needs a commit"))?;
        let sequence: u64 = params
            .get("sequence")
            .ok_or_else(|| StoreError::new(400, "preflight needs a sequence"))?
            .parse()
            .map_err(|_| StoreError::new(400, "preflight sequence must be a number"))?;
        validate_segment(channel, "channel")?;
        validate_commit(commit)?;
        let _guard = StoreLock::acquire(&self.lock_path())?;
        let head = self.read_head(channel)?;
        let (verdict, reason) = if head.as_ref().is_some_and(|h| h.commit == *commit) {
            (
                "current",
                format!("channel {channel} already publishes commit {commit}"),
            )
        } else if self.builds().join(commit).exists() {
            (
                "conflict",
                format!("commit {commit} is already published and builds are immutable"),
            )
        } else if !advances_channel(head.as_ref(), commit, sequence) {
            let at = head.as_ref().map(|h| h.sequence).unwrap_or(0);
            (
                "conflict",
                format!("sequence {sequence} does not advance channel {channel} at {at}"),
            )
        } else {
            ("publish", format!("channel {channel} has no build of commit {commit}"))
        };
        Ok(serde_json::json!({
            "channel": channel,
            "commit": commit,
            "verdict": verdict,
            "reason": reason
        }))
    }

    fn begin(&self, auth: &Caller, bytes: &[u8]) -> Result<serde_json::Value, StoreError> {
        let request: BeginPublication = serde_json::from_slice(bytes)
            .map_err(|e| StoreError::new(400, format!("invalid publication: {e}")))?;
        validate_begin(&request, self.cfg.max_artifact_bytes)?;
        let identity = publication_identity(auth)?;
        if identity.0.commit != request.commit {
            return Err(StoreError::new(
                403,
                "OIDC commit does not match publication",
            ));
        }
        let _guard = StoreLock::acquire(&self.lock_path())?;
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
        auth: &Caller,
        id: &str,
        target: &str,
        body_length: Option<u64>,
        body: &mut dyn Read,
    ) -> Result<serde_json::Value, StoreError> {
        validate_segment(id, "publication id")?;
        validate_target(target)?;
        let identity = publication_identity(auth)?;
        let _guard = StoreLock::acquire(&self.lock_path())?;
        let state = self.read_state(id)?;
        require_same_identity(&state.identity, &identity)?;
        let spec = state
            .request
            .targets
            .get(target)
            .ok_or_else(|| StoreError::new(404, "undeclared target"))?;
        if body_length != Some(spec.size) {
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

    fn complete(&self, auth: &Caller, id: &str) -> Result<serde_json::Value, StoreError> {
        validate_segment(id, "publication id")?;
        let identity = publication_identity(auth)?;
        let _guard = StoreLock::acquire(&self.lock_path())?;
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
        let head = self.read_head(&request.channel)?;
        if !advances_channel(head.as_ref(), &request.commit, request.sequence) {
            return Err(StoreError::new(409, "channel sequence must increase"));
        }
        write_json_atomic(
            &self.channels().join(format!("{}.json", request.channel)),
            manifest,
        )
    }

    /// The identity of what a channel currently publishes, or None if it has
    /// never published. Both the ordering rule and preflight read it here so
    /// they cannot disagree about what the head is.
    fn read_head(&self, channel: &str) -> Result<Option<ChannelHead>, StoreError> {
        let path = self.channels().join(format!("{channel}.json"));
        if !path.exists() {
            return Ok(None);
        }
        let current: serde_json::Value = read_json_bounded(&path)?;
        Ok(Some(ChannelHead {
            commit: current
                .get("commit")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            sequence: current.get("sequence").and_then(|v| v.as_u64()).unwrap_or(0),
        }))
    }

    fn channel(&self, file: &str, head: bool) -> Result<Response, StoreError>  {
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
        headers: &[(String, String)],
    ) -> Result<Response, StoreError>  {
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
    ) -> Result<Response, StoreError>  {
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
        // The length is declared, not chunked: a client resuming a download or
        // asking HEAD for a size needs a real Content-Length.
        let mut reply = Response::stream_len(status, body, length)
            .header("Content-Type", content_type)
            .header("Cache-Control", "private, no-store")
            .header("Accept-Ranges", "bytes")
            .header("X-Content-Type-Options", "nosniff");
        if status == 206 {
            reply = reply.header("Content-Range", format!("bytes {start}-{end}/{total}"));
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
    fn lock_path(&self) -> PathBuf {
        self.cfg.root.join(".lock")
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

/// A publication is bound to the workflow run that opened it. The claims come
/// from the gate, which verified the OIDC token — the function trusts them for
/// exactly that reason and would have no way to check them itself.
fn publication_identity(auth: &Caller) -> Result<PublicationIdentity, StoreError> {
    match auth.github() {
        Some(claims) => Ok(PublicationIdentity(claims.clone())),
        None => Err(StoreError::new(403, "GitHub OIDC identity required")),
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

fn read_control(body: &mut dyn Read, length: Option<u64>) -> Result<Vec<u8>, StoreError> {
    let Some(declared) = length.filter(|n| *n <= MAX_CONTROL_BODY) else {
        return Err(StoreError::new(411, "bounded Content-Length required"));
    };
    let mut bytes = Vec::with_capacity(declared as usize);
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

/// Parse a flat `a=b&c=d` query. Percent-decoding is deliberately absent: every
/// value this route accepts is validated to a restricted alphabet anyway, and a
/// decoder here would only widen what reaches those validators.
fn parse_query(query: &str) -> BTreeMap<&str, &str> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .filter(|(key, value)| !key.is_empty() && !value.is_empty())
        .collect()
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

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn json_reply(value: serde_json::Value) -> Response {
    Response::new(200, serde_json::to_vec(&value).unwrap())
        .header("Content-Type", "application/json")
        .header("Cache-Control", "private, no-store")
        .header("X-Content-Type-Options", "nosniff")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn publisher(commit: &str, run: &str) -> Caller {
        Caller {
            principal: "github-actions".into(),
            scopes: vec!["coil:nightly:publish".into()],
            claims: Some(GitHubClaims {
                repository_id: "123".into(),
                workflow_ref: "jimmyhmiller/coil/.github/workflows/nightly.yml@refs/heads/main"
                    .into(),
                run_id: run.into(),
                run_attempt: "1".into(),
                commit: commit.into(),
            }),
        }
    }

    fn test_store() -> (ReleaseStore, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "gatekeeper-release-store-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let store = ReleaseStore::new(Settings {
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
                Some(bytes.len() as u64),
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

    /// Publish one commit at `sequence`, then read preflight's verdict for
    /// `(commit, sequence)` back out of the full request path.
    fn published_store() -> (ReleaseStore, PathBuf, String) {
        let (store, root) = test_store();
        let commit = "3".repeat(40);
        let bytes = b"published toolchain";
        let request = serde_json::json!({
            "schema": 1,
            "channel": "nightly",
            "release": "nightly-test",
            "commit": commit,
            "sequence": 100,
            "published_at": "2026-09-12T00:00:00Z",
            "targets": {
                "aarch64-apple-darwin": {
                    "sha256": hex(&Sha256::digest(bytes)), "size": bytes.len()
                }
            }
        });
        let auth = publisher(&commit, "88");
        let begun = store
            .begin(&auth, &serde_json::to_vec(&request).unwrap())
            .unwrap();
        let id = begun["publication"].as_str().unwrap().to_string();
        store
            .upload(
                &auth,
                &id,
                "aarch64-apple-darwin",
                Some(bytes.len() as u64),
                &mut io::Cursor::new(bytes),
            )
            .unwrap();
        store.complete(&auth, &id).unwrap();
        (store, root, commit)
    }

    fn verdict(store: &ReleaseStore, auth: &Caller, commit: &str, sequence: u64) -> String {
        let reply = store.handle(
            auth,
            Incoming {
                method: "GET",
                rest: "/publications/preflight",
                query: &format!("channel=nightly&commit={commit}&sequence={sequence}"),
                headers: &[],
                body_length: None,
                body: &mut io::empty(),
            },
        );
        assert_eq!(reply.status_code(), 200);
        let body: serde_json::Value = serde_json::from_slice(reply.body_bytes()).unwrap();
        body["verdict"].as_str().unwrap().to_string()
    }

    #[test]
    fn preflight_separates_nothing_to_do_from_cannot_publish() {
        let (store, root, published) = published_store();
        let auth = publisher(&published, "99");
        // The commit the channel already publishes: the run has nothing to do.
        assert_eq!(verdict(&store, &auth, &published, 101), "current");
        // A newer commit that advances the channel: build it.
        let next = "4".repeat(40);
        assert_eq!(verdict(&store, &auth, &next, 101), "publish");
        // A newer commit that does not advance the channel could never be
        // completed, so it must be loud rather than another quiet skip.
        assert_eq!(verdict(&store, &auth, &next, 100), "conflict");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn preflight_agrees_with_the_completion_it_predicts() {
        let (store, root, published) = published_store();
        let commit = "5".repeat(40);
        let auth = publisher(&commit, "99");
        assert_eq!(verdict(&store, &auth, &commit, 100), "conflict");
        // The rule preflight reported is the one completion enforces.
        let request = serde_json::json!({
            "schema": 1,
            "channel": "nightly",
            "release": "nightly-test",
            "commit": commit,
            "sequence": 100,
            "published_at": "2026-09-12T00:00:00Z",
            "targets": { "aarch64-apple-darwin": { "sha256": hex(&Sha256::digest(b"x")), "size": 1 } }
        });
        let begun = store
            .begin(&auth, &serde_json::to_vec(&request).unwrap())
            .unwrap();
        let id = begun["publication"].as_str().unwrap().to_string();
        store
            .upload(&auth, &id, "aarch64-apple-darwin", Some(1), &mut io::Cursor::new(b"x"))
            .unwrap();
        let error = store.complete(&auth, &id).unwrap_err();
        assert_eq!(error.status, 409);
        assert_eq!(error.message, "channel sequence must increase");
        assert_ne!(published, commit);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn preflight_needs_the_publish_scope_and_a_complete_question() {
        let (store, root) = test_store();
        let commit = "6".repeat(40);
        let mut reader = publisher(&commit, "1");
        reader.scopes = vec!["coil:read".into()];
        let ask = |auth: &Caller, query: &str| {
            store
                .handle(
                    auth,
                    Incoming {
                        method: "GET",
                        rest: "/publications/preflight",
                        query,
                        headers: &[],
                        body_length: None,
                        body: &mut io::empty(),
                    },
                )
                .status_code()
        };
        let full = format!("channel=nightly&commit={commit}&sequence=1");
        assert_eq!(ask(&reader, &full), 403);
        assert_eq!(ask(&publisher(&commit, "1"), &full), 200);
        // A question the store cannot answer completely is refused, never guessed.
        assert_eq!(ask(&publisher(&commit, "1"), &format!("channel=nightly&commit={commit}")), 400);
        assert_eq!(ask(&publisher(&commit, "1"), "channel=nightly&commit=nope&sequence=1"), 400);
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
