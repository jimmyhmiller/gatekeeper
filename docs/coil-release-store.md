# Private release store

Gatekeeper can accept immutable build artifacts from one authorized GitHub
Actions workflow and serve the current channel to authenticated clients. The
store is a native route target because proxy, static, and function routes buffer
bodies; release uploads and downloads remain bounded-memory streams.

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
release_store = { root = "/var/lib/gatekeeper/releases/coil", read_scope = "coil:read", publish_scope = "coil:nightly:publish", max_artifact_bytes = 536870912, retain_builds = 14 }
```

The release route cannot be public. The existing bootstrap, browser-session,
and device credentials have Gatekeeper's legacy administrator authority and can
read it. A GitHub identity is scoped and can only publish when every configured
claim matches. It cannot use `/describe`, registration, or unrelated private
routes.

The service account must own `root`. Gatekeeper creates the directory and its
`channels`, `builds`, and `staging` children with mode `0700`; stored files use
mode `0600`. Under systemd, include the root beneath the service's writable
`StateDirectory`.

## Publication protocol

The workflow requests a GitHub OIDC JWT with the configured audience and sends
it as `Authorization: Bearer …` on every publication request.

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
the channel document. A channel sequence must increase; repeating completion
for the identical publication is safe.

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
