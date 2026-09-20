# Coil release store

Accepts immutable build artifacts from one authorized GitHub Actions workflow
and serves the current channel to authenticated clients.

This is a Gatekeeper **function** — a dylib the gate loads. It used to be a
native route target compiled into the gate, because function routes buffered
request bodies and a toolchain artifact is far too large to hold in memory. ABI
v4 removed that constraint (`stream_request` plus `Request::reader()`), so the
gate no longer contains anything about Coil, and a new version of this store
ships by dropping a `.so` in place — no rebuild of the gate, no restart.

## Building and deploying

```sh
cargo build --release -p coil-release-fn
install -m 0644 target/release/libcoil_release_fn.so /opt/functions/
```

The route is `reloadable`, so the gate picks up the new image on the next
request; in-flight requests finish against the image they started on.

## Configuration

```toml
[github_oidc]
audience = "https://computer.jimmyhmiller.com/coil/releases"

[[github_oidc.policy]]
name = "coil-nightly"
repository_id = "1319615009"
repository_owner_id = "6071338"
ref = "refs/heads/main"
workflow_ref = "jimmyhmiller/coil/.github/workflows/nightly.yml@refs/heads/main"
environment = "nightly-release"
event_names = ["schedule", "workflow_dispatch"]
scopes = ["coil:nightly:publish"]

[[route]]
path = "/coil/v1"
any_scopes = ["coil:read", "coil:nightly:publish"]
function = { library = "/opt/functions/libcoil_release_fn.so", stream_request = true, settings = { root = "/var/lib/gatekeeper/releases/coil", read_scope = "coil:read", publish_scope = "coil:nightly:publish", max_artifact_bytes = 536870912, retain_builds = 14 } }
```

`settings` is this function's own configuration; the gate carries the table
through without interpreting a field. `any_scopes` lets the gate admit either
kind of caller and leaves the per-endpoint distinction — reader or publisher —
to this function, which makes it from `Request::auth()`. A `scopes` list would
instead demand every named scope at once.

The release route cannot be public. The existing bootstrap, browser-session,
and device credentials have Gatekeeper's legacy administrator authority and can
read it. A GitHub identity is scoped and can only publish when every configured
claim matches. It cannot use `/describe`, registration, or unrelated private
routes.

The service account must own `root`. The function creates the directory and its
`channels`, `builds`, and `staging` children with mode `0700`; stored files use
mode `0600`. Under systemd, include the root beneath the service's writable
`StateDirectory`.

## Publication protocol

The workflow requests a GitHub OIDC JWT with the configured audience and sends
it as `Authorization: Bearer …` on every publication request.

### Preflight

A build is immutable and the toolchain does not compile byte-identically twice,
so a run whose commit the channel already publishes has nothing it *can* publish:
completion would reject it. Ask before building:

```text
GET /coil/v1/publications/preflight?channel=nightly&commit=<sha>&sequence=<n>
```

```json
{
  "channel": "nightly",
  "commit": "0123456789012345678901234567890123456789",
  "verdict": "current",
  "reason": "channel nightly already publishes commit 0123456789012345678901234567890123456789"
}
```

Three verdicts, deliberately not a boolean:

| `verdict`  | Meaning                                                      | The build should |
|------------|--------------------------------------------------------------|------------------|
| `publish`  | The channel has no build of this commit and the sequence advances. | Build and publish. |
| `current`  | The channel already publishes this commit.                    | Stop; it is green and there is no work. |
| `conflict` | This publication could never be accepted.                     | Fail loudly. |

Collapsing `current` and `conflict` into one "skip" would turn a misordered
channel into a build that goes green forever and never publishes again. The
ordering rule `conflict` reports is the same one completion enforces; a test
pins them together.

Preflight needs the publish scope and refuses an incomplete question rather than
guessing at a missing `channel`, `commit` or `sequence`. It is read-only: it
opens no publication and changes nothing.

### Publishing

Begin with `POST /coil/v1/publications` and a bounded JSON body:

```json
{
  "schema": 1,
  "channel": "nightly",
  "release": "0.1.0-nightly.20260912+g0123456",
  "commit": "0123456789012345678901234567890123456789",
  "sequence": 42,
  "published_at": "2026-09-12T06:00:00Z",
  "targets": {
    "aarch64-apple-darwin": {
      "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
      "size": 98234123
    }
  }
}
```

The response contains a random `publication` identifier. Upload each declared
target with a known and exactly matching `Content-Length`:

```text
PUT /coil/v1/publications/<publication>/<target>
```

Finish with:

```text
POST /coil/v1/publications/<publication>/complete
```

The publication is bound to repository, workflow, run ID, run attempt, and
commit from the OIDC token. A different job cannot continue it. Completion
rehashes every artifact, commits the SHA-addressed build, and atomically replaces
the channel document. A publication may replace the head only by naming the
head's own commit — repeating completion for the identical publication is safe —
or by advancing the sequence. Republishing a commit with *different* artifacts is
refused: a build is immutable once published.

Mutations are serialized by an `flock` on `<root>/.lock` rather than a
process-global mutex, because this code lives in a dylib the gate may swap: a
mutex belongs to one loaded image, so a reload between two requests would hand
them different locks. The kernel releases a file lock even if the holder dies.

## Downloads

Authenticated clients read:

```text
GET  /coil/v1/channels/nightly.json
HEAD /coil/v1/builds/<commit>/coil-<target>.tar.gz
GET  /coil/v1/builds/<commit>/coil-<target>.tar.gz
```

Artifacts support one standard byte range, including open-ended and suffix
ranges. Responses are `private, no-store` and never expose directory listings.
Artifact paths in the channel document are relative to the channel URL and
remain on the same origin.

## Recovery and retention

Staging files never become readable through the build endpoint. A failure before
channel replacement leaves the previous channel current. An interrupted build
directory is discarded and reconstructed from the still-present staging hard
links when completion is retried.

After a successful promotion, Gatekeeper retains the newest configured number
of builds and always protects every build referenced by a channel document.
Abandoned staging metadata is deliberately retained for idempotent recovery;
an age-bounded staging collector can be added once operational retention needs
are known.
