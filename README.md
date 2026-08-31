> This is experimental software. It probably doesn't work.

# gatekeeper

A small, fail-closed HTTP front gate. Put it in front of your services so a
single shared-secret token gates every request — and so you **can't accidentally
expose something you didn't mean to**.

The core property: **a route is private unless it explicitly sets `public =
true`.** Forgetting the flag fails safe (the route stays private). Tools like
Caddy/nginx are the opposite — auth is opt-in per route, so a forgotten directive
exposes a service. This makes the unsafe direction the one you have to ask for.

It's deliberately small: synchronous, thread-per-request (`tiny_http`), ~6 source
files, no async runtime. The whole request path — match route, normalize path,
check token, serve/proxy — is linear and auditable.

## Quick start

```toml
# gatekeeper.toml
bind = "0.0.0.0:443"
tls_cert = "/etc/gatekeeper/cert.pem"   # see "TLS and certificates" below
tls_key  = "/etc/gatekeeper/key.pem"
unmatched_status = 404            # or 403

[[route]]
path = "/blog"
static = "./site"
public = true                     # explicit opt-in to public

[[route]]
path = "/metrics"
proxy = "127.0.0.1:5557"          # 'public' omitted -> PRIVATE (default-deny)
```

```sh
export GATEKEEPER_TOKEN=$(head -c 32 /dev/urandom | base64)
gatekeeper --config gatekeeper.toml
```

- Public:  `curl https://computer.jimmyhmiller.com/blog/`
- Private: `curl -H "Authorization: Bearer $GATEKEEPER_TOKEN" https://computer.jimmyhmiller.com/metrics`
  (or a `gatekeeper=<token>` cookie for browsers)

## Config reference

Top level:

| key                | default        | meaning |
|--------------------|----------------|---------|
| `bind`             | `0.0.0.0:443`  | listen address |
| `tls_cert`/`tls_key` | none         | PEM files; set **both** for HTTPS, omit both for plain HTTP |
| `unmatched_status` | `404`          | response for a path matching no route (`404` hides existence; `403` says forbidden). Either way: denied. |
| `[[route]]`        | —              | one or more routes |

Per route:

| key      | meaning |
|----------|---------|
| `path`     | path prefix, e.g. `/blog`. Must start with `/`, no trailing `/`. |
| `static`   | serve this directory (exactly one of `static`/`proxy`/`function`) |
| `proxy`    | reverse-proxy to this `host:port` (exactly one target kind) |
| `function` | invoke a native function dylib in process (exactly one target kind) — see [Serverless functions](#serverless-functions) |
| `dashboard` | serve the built-in index of everything this gate exposes (exactly one target kind) — see [The dashboard](#the-dashboard) |
| `public`   | `true` = no auth. **Default `false`.** |

The **token is never in the config file** — it comes from `$GATEKEEPER_TOKEN` or
`--token-file <path>`. Boot fails if any private route exists and no token is set.

## A private file drop

You do not need anything new for this: `static` is already a route target and
routes are already private by default. A folder that only you can read is one
config block.

```toml
[[route]]
path = "/files"
static = "/srv/files"
# 'public' omitted -> PRIVATE, like everything else
```

The one gap is that static serving deliberately has **no autoindex** — a
directory maps to `index.html` and 404s without one. Sensible for a website,
useless for a drop folder, where seeing what is in it is the entire point.

`bin/gkfiles` fills that gap from outside the gate, so the gate stays unchanged.
It writes the `index.html` pages that make the folder browsable, and nothing
else:

```sh
gkfiles index     # regenerate the listings once
gkfiles watch     # keep regenerating as the folder changes
gkfiles status    # what is in the drop folder
```

Run `watch` from a systemd unit and dropping a file with `scp` is the whole
workflow. It only ever writes `index.html`; your files are the source of truth,
and it rewrites a page only when the content actually changed, so it does not
churn mtimes.

Two things to know. The folder must be readable by the user the gate runs as,
which for a home directory usually means it is not — put it somewhere like
`/srv` and give the group read access. And the MIME table in `serve.rs` is
short, so anything it does not recognise is served `application/octet-stream`
and downloads rather than rendering, which is usually what you want from a
drop folder anyway.

## The dashboard

Point a route at `dashboard = true` and it serves a human-readable index of
everything the gate exposes: every configured route and whether it is public,
every function's endpoints (pulled from their own `#[describe]`, with a
copyable `curl` per endpoint), the reserved built-ins, the scheduled jobs, and
your enrolled passkeys and device tokens.

```toml
[[route]]
path = "/"
dashboard = true
public = true
```

**Public, but it does not leak anything.** The page is a static shell; every
value it displays is fetched from `/describe`, which is private. Signed out you
get a sign-in prompt and nothing else — no route names, no endpoint list. That
matters because `unmatched_status = 404` exists specifically to hide the
existence of services, and a public index of every route would have quietly
undone it.

Signed in it is the fastest way to answer "what is actually running here, and
which of it is exposed". It is the same information as the boot exposure report
and `/describe`, in the form you want when you are looking at a browser rather
than a terminal.

## Serverless functions

Besides serving static files and proxying to a long-running upstream, a route can
invoke a **Rust function compiled as a dynamic library**, loaded into the gate on
first request and kept warm after. No port to manage, no separate process, no
service to keep running — you write a handler, the gate runs it behind the same
default-deny auth.

The app shouldn't have to worry about any of this, so it doesn't. You write one
function against the `gatekeeper-fn` crate:

```rust
// funcs/hello/src/lib.rs  (crate-type = ["cdylib"])
use gatekeeper_fn::{handler, Request, Response};

#[handler]
fn app(req: Request) -> Response {
    match req.path() {
        "/health" => Response::text("ok"),
        _ => Response::json(r#"{"hello":"world"}"#),
    }
}
```

```sh
cargo build -p hello-fn --release
```

and point a route at the resulting dylib:

```toml
[[route]]
path = "/api"
function = "target/release/libhello_fn.so"   # .dylib on macOS, .dll on Windows
# 'public' omitted -> PRIVATE, like any other route (default-deny holds)
```

The string form is a hot-reloadable, request-scoped function. A function that
owns background threads or other process-lifetime state must declare the
service lifecycle:

```toml
[[route]]
path = "/agents"
function = { library = "/opt/functions/libcoil_agent_harness.dylib", lifecycle = "service" }
# private by default
```

Service functions are loaded once and pinned until Gatekeeper exits. Replacing
their file does not reload or unmap the running image; restart Gatekeeper to
deploy a new version. This prevents background work from continuing in an
unmapped library. Ordinary string-form functions retain automatic hot reload.

`req.path()` is the path **after** the route prefix (so `/api/health` arrives as
`/health`), already normalized and traversal-checked by the gate. You get
`method()`, `query()`, `headers()`/`header(name)`, and `body()`/`text()`;
`Response` has `text`/`json`/`html`/`status`/`new`, a `header(...)` builder, and
`Response::stream(status, reader)` for incremental bodies such as SSE. A stream
reader is pulled only as the client can accept bytes, and is dropped on EOF,
read error, or client disconnect.

```rust
Response::stream(200, event_reader)
    .header("Content-Type", "text/event-stream")
    .header("Cache-Control", "no-cache")
```

Streaming is ABI v3: `GkResponse` identifies a buffered or streaming body, and
the gate calls `gk_stream_read` repeatedly before calling `gk_stream_free`
exactly once. The response envelope itself is still released immediately with
`gk_free`. This split lets the function retain only stream state while the gate
owns HTTP framing, chunking, backpressure, and disconnect detection. An
in-flight stream holds the loaded library alive, including across an ordinary
function hot reload.

Gatekeeper remains backward-compatible with ABI v2 functions. It reads their
original buffered-response layout and does not require the v3 stream symbols;
existing deployed functions therefore keep working unchanged. New SDK builds
emit ABI v3 so they can opt into streaming. Versions other than 2 and 3 are
rejected before any request or response structure is accessed.

### How it works (and why it's safe to run in process)

The `#[handler]` macro generates a tiny C-ABI surface (`gk_handle`, `gk_free`,
`gk_stream_read`, `gk_stream_free`, and `gk_abi_version`) — defined in the
`gatekeeper-abi` crate, the *entire* contract
across the boundary. The gate `dlopen`s the dylib, **checks its ABI version and
refuses to call a mismatch**, marshals the request into `#[repr(C)]` structs,
calls the handler, copies the response out, and frees it back through the dylib's
own deallocator (each side frees only what it allocated — no shared allocator
assumption).

- **A panic in your handler becomes a 500, not a crash.** The SDK catches the
  unwind on the function side so it never crosses the C ABI; the gate stays up.
  (Verified by a test that panics on purpose and asserts the gate survives.)
- **A failed load fails closed** (502), like an unreachable proxy upstream.
- The unsafe marshalling/free path is covered by an integration test run under
  valgrind: **0 errors, 0 bytes definitely lost** across many invocations.

Functions are *trusted native code* you deploy yourself — the same trust level as
a proxy upstream. The gate does not sandbox arbitrary dylibs; don't point a
`function` route at code you wouldn't run.

### The crates

| crate                  | who depends on it | what it is |
|------------------------|-------------------|------------|
| `gatekeeper-abi`       | gate **and** function | the `#[repr(C)]` request/response + ABI version. Tiny, no deps. |
| `gatekeeper-fn`        | your function     | the `Request`/`Response` types + `#[handler]` macro. The only crate your app needs. |
| `gatekeeper-fn-macro`  | (re-exported)     | the proc-macro behind `#[handler]`. |

`funcs/hello` is a complete worked example. After `cargo build -p hello-fn`, run
the gate with a route pointing at `target/debug/libhello_fn.so` and `curl` it.

### Adding functions live (no restart)

Routes are **hot-reloaded on `SIGHUP`** along with the cert. To add (or change, or
remove) a function without dropping a connection:

```sh
cp libfoo_fn.so /somewhere/the/gate/can/read/   # drop the dylib in
$EDITOR gatekeeper.toml                          # add a [[route]] function = "..."
systemctl reload gatekeeper                       # or: kill -HUP $(pidof gatekeeper)
```

The router and auth are rebuilt and swapped in atomically; the process PID is
unchanged and in-flight requests finish on the old routing. The function dylib
cache **persists** across reloads, so already-loaded functions are not
re-`dlopen`ed.

**Fail-safe, same as the cert reload:** if the new config is invalid, or it now
has a private route but no token is available, the reload is *refused* and the
gate keeps serving the previous config — a botched edit can neither take the gate
down nor accidentally drop auth.

### Self-describing API: `/describe`

The gate serves a built-in, **private** (token-required) meta route that returns a
JSON catalog of every route and — for function routes — each function's own
description of its endpoints:

```sh
curl -H "Authorization: Bearer $GATEKEEPER_TOKEN" https://host/describe
```

```json
{
  "gatekeeper": { "describe_path": "/describe", "abi_version": 2 },
  "routes": [
    { "path": "/analytics", "access": "private", "kind": "function",
      "description": {
        "name": "analytics",
        "endpoints": [
          { "path": "/timeline", "methods": ["GET"],
            "summary": "per-page view series over time, for line graphs",
            "params": [ { "name": "days", "type": "int", "required": false,
                          "default": "(all time)", "description": "window: last N days" } ],
            "example": "/timeline?days=7&n=3", "returns": "{ series: [...] }" } ] } }
  ]
}
```

A function describes itself with a `#[describe]` in the SDK, right next to its
handler — so the catalog stays accurate as you add endpoints (rebuild the dylib,
`mv` it in, done; no gate change):

```rust
use gatekeeper_fn::{describe, Description, Endpoint, Param};

#[describe]
fn describe() -> Description {
    Description::new("analytics", "Website-visit analytics")
        .endpoint(
            Endpoint::get("/timeline", "per-page views over time")
                .param(Param::int("days", "window: last N days").default("(all time)"))
                .example("/timeline?days=7")
                .returns("{ series: [...] }"),
        )
}
```

`#[describe]` is **required** — the gate refuses to load a function dylib that
doesn't export `gk_describe` (added in ABI v2), exactly as it refuses one missing
`gk_handle`. So the catalog can never contain an undocumented function. The symbol
is only *called* when serving the catalog.

## Passkeys

The shared token is a **machine** credential: one string, valid from anywhere,
and whoever holds it is you. Passkeys add the **human** credential next to it.
A passkey is bound to this origin, so it cannot be phished or replayed to
another host, and its private key lives in the Secure Enclave rather than in
your shell history.

Turn it on with a `[passkey]` block. **Absent, the whole feature is off** and
none of the routes below exist — the same opt-in shape as `public = true`.

```toml
[passkey]
rp_id  = "computer.jimmyhmiller.com"      # bare domain: no scheme, port, or path
origin = "https://computer.jimmyhmiller.com"
user_name = "jimmyhmiller"
state_dir = "/var/lib/gatekeeper"         # must be writable by the service
session_ttl_secs = 43200                  # 12h browser session
# apple_app_ids = ["TEAMID.com.example.App"]   # see "Native apps" below
```

Under `ProtectSystem=strict` the service cannot write anywhere by default, so
`state_dir` needs a systemd `StateDirectory=`:

```ini
# /etc/systemd/system/gatekeeper.service.d/30-state.conf
[Service]
StateDirectory=gatekeeper
```

Boot validates the relationship between `rp_id` and `origin` (https, and the
origin host must be the RP ID or a subdomain of it), because getting that wrong
produces a login page that fails only in the browser with an opaque exception.

### Enrolling: registration is private

Registration is **not** a public route. `/register` and everything under it
requires the same auth as any other private route, so an unauthenticated caller
has no path to enrolling a credential. Bootstrapping goes:

1. Open `/login` and use **"Use the bootstrap token instead"**. This verifies
   the shared token and mints a **session** — the raw token never lands in the
   browser's cookie jar, which the documented `gatekeeper=<token>` cookie could
   not avoid.
2. You are now authenticated, so `/register` loads. Name the passkey, click
   **Add a passkey**, approve with Touch ID.
3. From then on `/login` signs you in with the passkey, and `/register` can add
   more or revoke any of them.

The token keeps working on every private route as break-glass, so a lost passkey
never locks you out.

### Rate limiting the public endpoints

Adding passkeys put a credential check on a public path for the first time
(`/login/token`), and constant-time comparison stops a token being recovered
byte-by-byte but does nothing about unlimited guesses. So four reserved paths
are rate limited per client, and nothing else is:

| path | budget |
|------|--------|
| `/login/token` | 10 per 5 min, its own bucket |
| `/login/verify`, `/login/challenge`, `/login/device/start` | 30 per min, shared |

Over budget is `429` with `Retry-After`. A successful sign-in clears that
client's budget, so the credential limit is really "failures in a row".

**The bootstrap token has its own bucket on purpose.** Sharing one with the
passkey path would mean fat-fingering the token ten times also locks you out of
your passkey, which is the stronger credential and the one that should still
work — and it would hand an attacker a cheap denial of service: trip the shared
bucket deliberately and the real user cannot get in either way.

The client is the TCP peer address. `X-Forwarded-For` is deliberately **not**
consulted: gatekeeper terminates TLS itself, so the peer is the client, and
trusting a client-supplied header would make the limiter bypassable by setting
it. There are also hard ceilings on in-flight ceremonies and device requests,
which catch the case per-client limiting cannot see: many clients each staying
under the limit.

### Signing out

**Signing out** is `/logout` (linked from `/register`). It expires both the
passkey session and the break-glass `gatekeeper=<token>` cookie and redirects to
`/login`. There is no session table to delete, because sessions are signed
rather than stored, so this is purely cookie expiry. It is public on purpose: if
signing out required being signed in, a stale or half-broken cookie would be
impossible to clear.

**Sign out everywhere** is the button at the bottom of `/register`. Being
signed rather than stored is what keeps sessions cheap, but it also means an
individual session cannot be revoked. Rotating the signing key is the kill
switch: every outstanding session on every device dies at once, including the
one that pressed the button. Device tokens and the bootstrap token are
unaffected, so your CLI and cron jobs keep working.

### The command line

A CLI cannot run a WebAuthn ceremony — passkeys need a browser or platform
authenticator to sign the challenge. `bin/gatekeeper-login` therefore runs a
**device-authorization flow**, the same shape `gh` and `docker` use:

```sh
$ gatekeeper-login

  Your code:  MC5R-LHJF
  Open:       https://computer.jimmyhmiller.com/login?code=MC5R-LHJF

Waiting for you to approve it with your passkey...
Logged in. Token stored in ~/.config/gatekeeper/token
```

You approve the code in a browser with your passkey; the CLI collects a
**device token** of its own, stored 0600. Then:

```sh
curl -H "Authorization: Bearer $(gatekeeper-login --print)" https://host/analytics/summary
```

Device tokens are stored hashed, listed at `/register`, and revocable
individually — which is the practical win over one shared secret. Also
`--status`, `--logout`, `--host`.

### Native apps

A signed macOS/iOS app uses the *same* endpoints via
`ASAuthorizationPlatformPublicKeyCredentialProvider`, sharing the same passkey
as Safari through iCloud Keychain. The only server-side piece is the
associated-domains file, which Apple requires be public:

```toml
apple_app_ids = ["TEAMID.com.example.App"]
```

That, and only that, makes the gate serve
`/.well-known/apple-app-site-association`. With the list empty the file is not
served at all and the route does not exist. The app needs the matching
`webcredentials:<rp_id>` entitlement.

(Registration uses `start_passkey_registration`, which hints
`residentKey: discouraged`. Apple's platform authenticator creates a
discoverable, iCloud-synced credential anyway, and the assertion sends
`allowCredentials`, so both the browser and a native app complete the ceremony
without relying on discoverability.)

### What this adds to the exposure surface

Exactly one thing: `/login` and its ceremony endpoints are public, because you
cannot authenticate in order to earn the ability to authenticate. Every reserved
built-in and its access now appears in the boot exposure report:

```
  BUILT-IN routes (reserved; config cannot override these):
    private  /describe                 ->  self-describing API catalog
    PUBLIC   /login                    ->  passkey sign-in page
    PUBLIC   /login/challenge          ->  begin a passkey assertion
    ...
    private  /login/device/approve     ->  CLI device flow: approve a code
    private  /register                 ->  enroll and revoke passkeys
```

Built-ins were previously invisible to that report, which was survivable while
`/describe` was the only one and it was private. It stops being survivable the
moment a public built-in exists, so the report now covers every path the gate
answers on, from either source. The set of public built-ins is also pinned by a
test, so widening it has to be a deliberate edit.

Reserved paths are matched **before** the configured router, so no `[[route]]`
can shadow the login page or re-point registration.

`[passkey]` is read at startup only: the engine holds live ceremonies and
pending device codes, and its identity is what browsers bound their credentials
to. A `SIGHUP` with a changed `[passkey]` logs that a restart is needed rather
than silently ignoring the edit. Routes, token, and cert still hot-reload.

## TLS and certificates

For a public `https://` domain, browsers require a certificate signed by a
trusted Certificate Authority. **Let's Encrypt** is a free CA that issues one
after you prove you control the domain; the result is two PEM files (a
certificate chain and a private key) that gatekeeper's `tls_cert`/`tls_key`
point at.

gatekeeper terminates TLS with rustls but does **not** do ACME in-process (that
would roughly double the dependency tree and re-add an async runtime). Instead an
external tool gets and auto-renews the cert, and gatekeeper **hot-reloads it on
`SIGHUP`** — no restart, no dropped connections.

### One-time setup with acme.sh (zero extra Rust deps)

[`acme.sh`](https://github.com/acmesh-official/acme.sh) is a small, widely-used
shell ACME client that installs its own renewal cron.

```sh
# install
curl https://get.acme.sh | sh -s email=jimmyhmiller@gmail.com

# issue a cert for the domain (standalone briefly binds :80 to prove control;
# alternatively use a DNS challenge — see acme.sh docs)
acme.sh --issue --standalone -d computer.jimmyhmiller.com

# install the cert to a stable path AND tell acme.sh to SIGHUP gatekeeper after
# every renewal, so the new cert is picked up live:
acme.sh --install-cert -d computer.jimmyhmiller.com \
  --fullchain-file /etc/gatekeeper/cert.pem \
  --key-file       /etc/gatekeeper/key.pem \
  --reloadcmd      "kill -HUP \$(pidof gatekeeper)"
```

Then in `gatekeeper.toml`:

```toml
bind = "0.0.0.0:443"
tls_cert = "/etc/gatekeeper/cert.pem"
tls_key  = "/etc/gatekeeper/key.pem"
```

Let's Encrypt certs last 90 days; acme.sh's cron renews them automatically and
the `--reloadcmd` SIGHUPs gatekeeper, which re-reads the files in place. On boot
gatekeeper prints its PID and the exact reload command.

**Fail-safe:** if a reload finds a missing or invalid cert, gatekeeper logs the
error and **keeps serving the current cert** rather than going down — a botched
renewal can't take the site offline.

### Without a public CA

If you don't have a public domain — e.g. you're behind a Cloudflare Tunnel,
Tailscale, or a reverse proxy that already does TLS — omit `tls_cert`/`tls_key`
and run gatekeeper as plain HTTP on localhost. The terminator in front handles
certificates.

## The safety guarantees

1. **Default-deny.** `public` defaults false. Unmatched paths are denied. A
   private route with no/invalid token → 401.
2. **No path-trick bypass.** Request paths are percent-decoded and walked
   component-by-component; any `..` (encoded or not) → **400**, before routing.
   Prefix matching only at `/` boundaries, so `/admin` never matches
   `/administrator`. Case-sensitive. Static serving additionally canonicalizes
   and confirms the file stays within the served root (catches symlink escapes).
3. **Longest-prefix wins**, so a public subpath can sit under a private parent
   (`/admin/docs` public under `/admin` private) — the more specific route wins.
4. **Constant-time token check** (`subtle`), so the token can't be recovered by
   timing. Header (`Authorization: Bearer`) takes precedence over cookie; a
   present-but-wrong header is not silently bypassed by a good cookie. With
   passkeys on there are three credential kinds (shared token, device token,
   passkey session) and every one of them is checked without short-circuiting,
   so the response time reveals neither which kind matched nor how many device
   tokens exist.
5. **Loud exposure report at every boot** listing every public and private route,
   so you can eyeball "did I mean to make these public?". Use `--check` to print
   it and validate the config without binding.

These are enforced in one place (`Router::decide`) and verified by a property
test (`tests/safety.rs`) that asserts, over thousands of generated configs and
paths, that **no private route is ever allowed without a valid token**.

Adding passkeys did not widen that core. `Router::decide` still asks one yes/no
question; all `auth::Verifier` does is give that question three ways to answer
yes instead of one. `tests/safety.rs` is unchanged and still proves the
property.

## CLI

```
gatekeeper --config <file> [--token-file <file>] [--check]

  --config       config TOML (default ./gatekeeper.toml)
  --token-file   read shared token from a file (else $GATEKEEPER_TOKEN)
  --check        validate config + print exposure report, then exit
```

## Not included (by design)

General request rate limiting, per-route tokens, request logging to a sink,
OIDC/accounts, multi-user, in-process ACME. (Passkeys **are** included — see
above — but for a single user; per-device tokens are the closest thing to
multiple tokens. Rate limiting is now present, but *only* on the four public
authentication endpoints, and it should stay that narrow.) Add a tunnel or a terminator in front if you need
more. This stays a small, legible gate. (Config **is** hot-reloaded on `SIGHUP` —
see [Adding functions live](#adding-functions-live-no-restart).)
