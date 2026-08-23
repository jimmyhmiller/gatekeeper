//! gatekeeper — a fail-closed HTTP front gate.
//!
//! Sits in front of your services and checks a shared-secret token on every
//! request. A route is **private unless it sets `public = true`** in the config,
//! so you can't accidentally expose something: forgetting the flag fails safe.
//!
//! Synchronous, thread-per-request (`tiny_http`). Optional TLS via rustls when
//! `tls_cert`/`tls_key` are configured; otherwise plain HTTP (for use behind a
//! TLS terminator or on localhost).

use std::path::PathBuf;
use std::sync::Arc;

use gatekeeper::auth::{Authenticator, Verifier};
use gatekeeper::config::{self, Config, Target};
use gatekeeper::function::FunctionRegistry;
use gatekeeper::login;
use gatekeeper::passkey::PasskeyEngine;
use gatekeeper::proxy;
use gatekeeper::reply::Reply;
use gatekeeper::route::{Match, Router};
use gatekeeper::schedule::Scheduler;
use gatekeeper::serve;

/// Reserved built-in meta route: a JSON catalog of every route and each
/// function's self-description. Private. Defined in `login::RESERVED` along
/// with every other built-in, so the boot exposure report can enumerate them.
use gatekeeper::login::DESCRIBE_PATH;

struct Args {
    config: PathBuf,
    token_file: Option<PathBuf>,
    check: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut config = PathBuf::from("gatekeeper.toml");
    let mut token_file = None;
    let mut check = false;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--config" | "-c" => {
                config = it.next().ok_or("--config needs a path")?.into();
            }
            "--token-file" => {
                token_file = Some(it.next().ok_or("--token-file needs a path")?.into());
            }
            "--check" => check = true,
            "-h" | "--help" => {
                println!(
                    "gatekeeper --config <file> [--token-file <file>] [--check]\n\
                     \n  --config       config TOML (default ./gatekeeper.toml)\
                     \n  --token-file   read shared token from a file (else $GATEKEEPER_TOKEN)\
                     \n  --check        validate config + print exposure report, then exit"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(Args { config, token_file, check })
}

/// The hot-swappable part of a worker's view: routing table, auth, and the
/// unmatched status. Rebuilt from the config on SIGHUP and swapped in atomically
/// so route/token changes take effect without a restart. The function dylib
/// cache is deliberately NOT here — it lives in [`Gate`] and persists across
/// reloads so already-loaded dylibs are not re-`dlopen`ed.
struct Routing {
    router: Router,
    /// All credential kinds in one place: bootstrap token, device tokens, and
    /// passkey sessions. Widening authentication happens HERE and nowhere near
    /// `Router::decide`, which still just asks "was auth ok?".
    verifier: Verifier,
    unmatched_status: u16,
}

/// Everything a worker needs to handle a request, shared across threads. The
/// `routing` is swappable on reload; `functions` persists.
struct Gate {
    /// Current routing/auth, swapped wholesale on SIGHUP (config reload).
    routing: std::sync::Mutex<Arc<Routing>>,
    /// Lazily-loaded cache of function dylibs (the serverless backend). Shared
    /// across reloads: reloading the config does not drop loaded functions.
    functions: FunctionRegistry,
    /// Runs scheduled `[[job]]`s on their intervals. Persists across reloads;
    /// its `reload` is called with the new job set on each SIGHUP.
    scheduler: Scheduler,
    /// The passkey subsystem, or `None` when `[passkey]` is absent from the
    /// config (in which case none of the login/register routes exist at all).
    /// Like `functions`, it lives here rather than in `Routing` so a SIGHUP
    /// does not drop in-flight ceremonies or pending device codes.
    passkeys: Option<Arc<PasskeyEngine>>,
}

impl Gate {
    /// Snapshot the current routing for a request. Cheap `Arc` clone so a
    /// concurrent reload swapping in a new `Routing` never tears a request.
    fn routing(&self) -> Arc<Routing> {
        Arc::clone(&self.routing.lock().unwrap())
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("gatekeeper: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    let cfg = Config::load(&args.config).map_err(|e| e.to_string())?;

    // Source the token. Fail closed: if any route is private, a token is
    // mandatory. (A config with only public routes can run without one.)
    let token = config::load_token(args.token_file.as_deref()).map_err(|e| e.to_string())?;
    if cfg.has_private_route() && token.is_none() {
        return Err(
            "config has private routes but no token configured \
             (set GATEKEEPER_TOKEN or --token-file)"
                .into(),
        );
    }

    // Build the passkey subsystem before anything binds, so a bad `[passkey]`
    // block (unwritable state dir, rp_id that can never match the origin) is a
    // startup error rather than a login page that mysteriously never works.
    // Absent config -> None -> not a single login route exists.
    let passkeys = match &cfg.passkey {
        Some(pk) => Some(Arc::new(PasskeyEngine::new(pk)?)),
        None => None,
    };

    print_exposure_report(&cfg, token.is_some(), passkeys.as_deref());

    if args.check {
        println!("\n--check: config valid. Not binding.");
        return Ok(());
    }

    let gate = Arc::new(Gate {
        routing: std::sync::Mutex::new(Arc::new(build_routing(
            &cfg,
            token.as_deref(),
            passkeys.clone(),
        ))),
        functions: FunctionRegistry::new(),
        scheduler: Scheduler::new(),
        passkeys,
    });
    // Start the scheduled jobs (if any). Re-applied on every config reload.
    gate.scheduler.reload(&cfg.job);

    // Bind the listening socket ONCE. We keep our own handle so we can rebuild
    // the tiny_http Server (with a freshly-loaded cert) on SIGHUP without ever
    // closing the socket — that's what makes cert reload zero-downtime.
    let listener = std::net::TcpListener::bind(&cfg.bind)
        .map_err(|e| format!("binding {}: {e}", cfg.bind))?;

    let server = build_server(&listener, &cfg)?;
    // The current Server lives behind a Mutex so the SIGHUP handler can swap it.
    let current: Arc<std::sync::Mutex<Arc<tiny_http::Server>>> =
        Arc::new(std::sync::Mutex::new(Arc::new(server)));

    println!(
        "\ngatekeeper listening on {} ({})",
        cfg.bind,
        if cfg.tls_enabled() { "HTTPS" } else { "HTTP" }
    );
    println!(
        "  reload (cert + routes): send SIGHUP (kill -HUP {}) or `systemctl reload gatekeeper`",
        std::process::id()
    );

    // SIGHUP -> reload the config: rebuild the Server with the (possibly renewed)
    // cert AND rebuild the routing table + auth from the config file, swapping
    // both in. The old Server is unblocked so its workers release it; in-flight
    // requests finish. Loaded function dylibs persist across the reload.
    install_reload_handler(
        Arc::clone(&current),
        Arc::clone(&gate),
        listener,
        args.config.clone(),
        args.token_file.clone(),
    );

    // A small fixed pool of workers. Each re-reads the current Server every
    // iteration (cheap Arc clone) and uses recv_timeout so a swap is picked up
    // promptly even on an idle connection.
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(2, 16);
    let mut handles = Vec::new();
    for _ in 0..workers {
        let current = Arc::clone(&current);
        let gate = Arc::clone(&gate);
        handles.push(std::thread::spawn(move || loop {
            let server = { Arc::clone(&*current.lock().unwrap()) };
            match server.recv_timeout(std::time::Duration::from_millis(500)) {
                Ok(Some(req)) => handle(&gate, req),
                Ok(None) => {} // timeout or unblocked: loop, re-read current server
                Err(e) => {
                    eprintln!("gatekeeper: recv error: {e}");
                    break;
                }
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

/// Build the hot-swappable [`Routing`] from a config and optional token. Used at
/// boot and on every reload, so route/auth construction is identical both times.
fn build_routing(
    cfg: &Config,
    token: Option<&str>,
    passkeys: Option<Arc<PasskeyEngine>>,
) -> Routing {
    Routing {
        router: Router::new(cfg.route.clone()),
        verifier: Verifier::new(token.map(Authenticator::new), passkeys),
        unmatched_status: cfg.unmatched_status,
    }
}

/// Spawn a thread that watches for SIGHUP and, on each, **reloads the config**:
/// it re-reads the config file and token, then rebuilds (a) the TLS Server from
/// the same socket with the current certificate and (b) the routing table + auth,
/// swapping both in atomically. This is what makes adding/changing routes (and
/// rotating the token, and renewing the cert) take effect with no restart.
///
/// Fail-safe at every step: if the config is invalid, the token is now missing
/// for a private route, or the cert can't be read, we log and keep serving the
/// *current* state rather than going down. A botched edit can't take the gate
/// offline or accidentally drop auth.
///
/// Loaded function dylibs are NOT touched here — they live in the `Gate` and stay
/// resident across reloads, so a reload never re-`dlopen`s a warm function.
fn install_reload_handler(
    current: Arc<std::sync::Mutex<Arc<tiny_http::Server>>>,
    gate: Arc<Gate>,
    listener: std::net::TcpListener,
    config_path: PathBuf,
    token_file: Option<PathBuf>,
) {
    use std::sync::atomic::{AtomicBool, Ordering};
    let flag = Arc::new(AtomicBool::new(false));
    // signal_hook flips the flag from the real signal handler; we poll it.
    if signal_hook::flag::register(signal_hook::consts::SIGHUP, Arc::clone(&flag)).is_err() {
        eprintln!("gatekeeper: warning: could not install SIGHUP handler; reload disabled");
        return;
    }
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if !flag.swap(false, Ordering::SeqCst) {
            continue;
        }
        reload_once(&current, &gate, &listener, &config_path, token_file.as_deref());
    });
}

/// Perform one reload cycle. Separated out so the logic is linear and each
/// failure mode logs + bails without partially applying a reload.
fn reload_once(
    current: &Arc<std::sync::Mutex<Arc<tiny_http::Server>>>,
    gate: &Arc<Gate>,
    listener: &std::net::TcpListener,
    config_path: &std::path::Path,
    token_file: Option<&std::path::Path>,
) {
    // 1. Re-read + validate the config. Invalid -> keep current, don't apply.
    let cfg = match Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("gatekeeper: reload: config invalid, keeping current config: {e}");
            return;
        }
    };

    // 2. Re-source the token and re-check the fail-closed invariant. If the new
    //    config has a private route but no token is available, refuse the reload
    //    rather than swap in routing that would 401 everything (or worse).
    let token = match config::load_token(token_file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("gatekeeper: reload: reading token failed, keeping current config: {e}");
            return;
        }
    };
    if cfg.has_private_route() && token.is_none() {
        eprintln!(
            "gatekeeper: reload: new config has private routes but no token configured; \
             keeping current config (set GATEKEEPER_TOKEN or --token-file)"
        );
        return;
    }

    // 3. Rebuild the TLS server (picks up a renewed cert). Bad cert -> keep
    //    current cert AND skip the routing swap, so a half-applied reload can't
    //    happen. We rebuild the server even for plain HTTP (cheap) so a cert
    //    *added* to the config takes effect.
    let new_server = match build_server(listener, &cfg) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("gatekeeper: reload: building server failed, keeping current: {e}");
            return;
        }
    };

    // 4. Apply: swap routing first, then the server. Both are independent atomic
    //    swaps; workers snapshot each per-request, so the worst interleaving is a
    //    single request seeing new routing with the old server (or vice versa) —
    //    both valid states, never a torn one.
    // The passkey engine is NOT rebuilt on reload: it holds live ceremonies and
    // pending device codes, and its identity (rp_id/origin) is what browsers
    // bound their credentials to. Changing `[passkey]` therefore needs a real
    // restart, and we say so loudly rather than silently ignoring the edit.
    let passkey_changed = match (&cfg.passkey, gate.passkeys.as_ref()) {
        (Some(new), Some(live)) => {
            new.rp_id != live.config().rp_id || new.origin != live.config().origin
        }
        (Some(_), None) | (None, Some(_)) => true,
        (None, None) => false,
    };
    if passkey_changed {
        eprintln!(
            "gatekeeper: reload: [passkey] changed but passkeys are bound at startup; \
             the RUNNING passkey config is unchanged. Restart to apply it."
        );
    }
    let new_routing = Arc::new(build_routing(&cfg, token.as_deref(), gate.passkeys.clone()));
    {
        let mut guard = gate.routing.lock().unwrap();
        *guard = new_routing;
    }
    {
        let mut guard = current.lock().unwrap();
        let old = std::mem::replace(&mut *guard, Arc::new(new_server));
        drop(guard);
        old.unblock(); // release workers blocked on the old Server
    }

    // Re-apply scheduled jobs: stale job threads stop, the new set starts.
    gate.scheduler.reload(&cfg.job);

    print_exposure_report(&cfg, token.is_some(), gate.passkeys.as_deref());
    println!("gatekeeper: reloaded config (SIGHUP) — routes + cert applied");
}

/// Build a tiny_http Server bound to a *clone* of `listener`'s socket, with TLS
/// if the config has a cert/key. Cloning the fd lets us build a fresh Server on
/// the same bound socket without closing it.
fn build_server(
    listener: &std::net::TcpListener,
    cfg: &Config,
) -> Result<tiny_http::Server, String> {
    let sock = listener
        .try_clone()
        .map_err(|e| format!("cloning listener socket: {e}"))?;
    let ssl = match (&cfg.tls_cert, &cfg.tls_key) {
        (Some(cert), Some(key)) => {
            let certificate = std::fs::read(cert)
                .map_err(|e| format!("reading tls_cert {}: {e}", cert.display()))?;
            let private_key = std::fs::read(key)
                .map_err(|e| format!("reading tls_key {}: {e}", key.display()))?;
            Some(tiny_http::SslConfig {
                certificate,
                private_key,
            })
        }
        _ => None,
    };
    tiny_http::Server::from_listener(sock, ssl).map_err(|e| format!("starting server: {e}"))
}

/// Handle a single request: match route, enforce auth on private routes, then
/// serve static or proxy. Anything unexpected fails closed.
fn handle(gate: &Gate, mut request: tiny_http::Request) {
    // tiny_http's url() is the path+query. Split the query off for routing;
    // keep the full thing for proxying.
    let raw_url = request.url().to_string();
    let (path, query) = raw_url.split_once('?').unwrap_or((raw_url.as_str(), ""));
    let query = query.to_string();

    // Snapshot the current routing for the whole request. A concurrent reload
    // swaps in a fresh Arc<Routing>; we hold our snapshot so the decision is
    // consistent even if a SIGHUP lands mid-request.
    let routing = gate.routing();

    // Built-in reserved routes: the API catalog, and (when `[passkey]` is
    // configured) the login, registration, and device-flow endpoints. These are
    // matched BEFORE the configured router so no `[[route]]` can shadow the
    // login page or re-point registration. Each one's access comes from the
    // single table in `login::RESERVED`, which is also what the boot exposure
    // report prints. Normalize first so `/login/` and any encoding resolve the
    // same way the router would.
    if let Some(norm) = Router::normalize(path) {
        if let Some(reserved) = login::lookup(&norm) {
            // A path is only live if this configuration actually serves it:
            // without `[passkey]` only `/describe` exists, and the Apple file
            // only exists when app ids are configured.
            let live = login::active(gate.passkeys.as_deref())
                .iter()
                .any(|r| r.path == reserved.path);
            if live {
                // Same gate as any private route, evaluated the same way.
                let authed = routing.verifier.check_headers(request.headers());
                if !reserved.public && !authed {
                    let reply = if reserved.path == DESCRIBE_PATH {
                        // Unlike a normal private route's bare 401, the
                        // discovery endpoint explains HOW to authenticate
                        // (never the token itself) so a caller knows what next.
                        describe_auth_help()
                    } else {
                        Reply::status(401, "Unauthorized")
                            .with_header("WWW-Authenticate", "Bearer")
                    };
                    let _ = reply.respond(request);
                    return;
                }
                let reply = if reserved.path == DESCRIBE_PATH {
                    describe_catalog(gate, &routing)
                } else {
                    // `live` implies the engine exists for every non-describe
                    // reserved path, because `active()` filters on exactly that.
                    let engine = gate
                        .passkeys
                        .as_ref()
                        .expect("non-describe reserved path implies a passkey engine");
                    let method = request.method().as_str().to_string();
                    let mut body = Vec::new();
                    let _ = request.as_reader().read_to_end(&mut body);
                    login::handle(engine, &routing.verifier, &method, &norm, &body)
                };
                let _ = reply.respond(request);
                return;
            }
        }
    }

    let reply = match routing.router.resolve(path) {
        Match::BadPath => Reply::status(400, "Bad Request"),
        Match::NoRoute => Reply::status(routing.unmatched_status, "Not Found"),
        Match::Route { route, rest, .. } => {
            // The safety gate: private routes require a valid token.
            if !route.public {
                let ok = routing.verifier.check_headers(request.headers());
                if !ok {
                    let r = Reply::status(401, "Unauthorized")
                        .with_header("WWW-Authenticate", "Bearer");
                    let _ = r.respond(request);
                    return;
                }
            }
            match route.target() {
                Target::Static(dir) => serve::serve(&dir, &rest),
                Target::Proxy(upstream) => {
                    // Read the request body to forward it (bounded by tiny_http).
                    let mut body = Vec::new();
                    let _ = request.as_reader().read_to_end(&mut body);
                    let method = request.method().as_str().to_string();
                    // Proxy the full URL (path + query) so upstreams see queries.
                    proxy::forward(&upstream, &method, &raw_url, request.headers(), &body)
                }
                Target::Function(lib) => {
                    // Read the body, then invoke the dylib in process. `rest` is
                    // the path after the route prefix (already normalized); the
                    // function sees that plus the query separately.
                    let mut body = Vec::new();
                    let _ = request.as_reader().read_to_end(&mut body);
                    let method = request.method().as_str().to_string();
                    gate.functions.invoke(
                        &lib,
                        &method,
                        &rest,
                        &query,
                        request.headers(),
                        &body,
                    )
                }
            }
        }
    };
    let _ = reply.respond(request);
}

/// Print, at every boot, exactly what is and isn't exposed — so a human can
/// eyeball "did I mean to make these public?".
fn print_exposure_report(
    cfg: &Config,
    token_configured: bool,
    passkeys: Option<&PasskeyEngine>,
) {
    let line = "=".repeat(60);
    println!("\n{line}\nGATEKEEPER EXPOSURE REPORT\n{line}");
    if !cfg.tls_enabled() {
        println!("  TLS: OFF (plain HTTP — use only behind a terminator or on localhost)");
    } else {
        println!("  TLS: on");
    }
    println!(
        "  Auth token: {}",
        if token_configured { "configured" } else { "NONE" }
    );
    println!("  Unmatched requests -> {}", cfg.unmatched_status);

    let public: Vec<_> = cfg.route.iter().filter(|r| r.public).collect();
    let private: Vec<_> = cfg.route.iter().filter(|r| !r.public).collect();

    println!("\n  PUBLIC routes (no auth):");
    if public.is_empty() {
        println!("    (none)");
    }
    for r in &public {
        println!("    {}  ->  {}", r.path, target_desc(r));
    }

    println!("\n  PRIVATE routes (token required):");
    if private.is_empty() {
        println!("    (none)");
    }
    for r in &private {
        println!("    {}  ->  {}", r.path, target_desc(r));
    }

    // Built-in routes were previously invisible here, which was survivable while
    // `/describe` was the only one and it was private. It stops being
    // survivable the moment a PUBLIC built-in exists, so the report now covers
    // every path the gate answers on, from either source.
    let builtins = login::active(passkeys);
    println!("\n  BUILT-IN routes (reserved; config cannot override these):");
    for r in &builtins {
        println!(
            "    {:<8} {}  ->  {}",
            if r.public { "PUBLIC" } else { "private" },
            r.path,
            r.desc
        );
    }

    println!("\n  PASSKEYS:");
    match passkeys {
        None => println!("    off (no [passkey] section) — no login or register routes exist"),
        Some(p) => {
            let c = p.config();
            println!("    rp_id {}  origin {}", c.rp_id, c.origin);
            println!("    state {}", c.state_dir.display());
            println!(
                "    session TTL {}s, {} enrolled, {} device token(s) issued",
                c.session_ttl_secs,
                p.credential_count(),
                p.device_summary().len()
            );
            if p.credential_count() == 0 {
                println!(
                    "    NOTE: none enrolled yet — sign in at /login with the bootstrap \
                     token, then enroll at /register"
                );
            }
            match p.apple_app_site_association() {
                Some(_) => println!("    apple app ids: {}", c.apple_app_ids.join(", ")),
                None => println!("    apple app ids: (none) — associated-domains file not served"),
            }
        }
    }

    println!("\n  SCHEDULED jobs:");
    if cfg.job.is_empty() {
        println!("    (none)");
    }
    for j in &cfg.job {
        let when = if j.run_at_start {
            format!("every {} (and at start)", j.every)
        } else {
            format!("every {}", j.every)
        };
        println!("    {}  ->  `{}`  [{}]", j.name, j.command.join(" "), when);
    }
    println!("{line}");
}

fn target_desc(r: &config::Route) -> String {
    match (&r.static_dir, &r.proxy, &r.function) {
        (Some(d), _, _) => format!("static {}", d.display()),
        (_, Some(u), _) => format!("proxy {u}"),
        (_, _, Some(l)) => format!("function {}", l.display()),
        _ => "(invalid)".into(),
    }
}

/// Build the `/describe` catalog: a JSON object listing every route
/// (path, access, target) and, for function routes, the function's own
/// self-description (endpoints/params/examples) fetched via `gk_describe`.
///
/// This is the one place the gate's knowledge (routes, public/private, from the
/// toml) is joined with each function's knowledge (its endpoints, from the
/// dylib). Function descriptions are embedded under their route so a caller sees
/// the full path: route prefix + the function's sub-paths.
fn describe_catalog(gate: &Gate, routing: &Routing) -> Reply {
    use serde_json::{json, Value};

    let mut routes = Vec::new();
    for r in routing.router.routes() {
        let access = if r.public { "public" } else { "private" };
        let mut entry = json!({
            "path": r.path,
            "access": access,
            "target": target_desc(r),
        });

        // For a function route, fetch and embed its self-description. The
        // function's endpoint paths are RELATIVE to this route's prefix, so we
        // also surface the prefix to make the full path obvious.
        if let Some(lib) = &r.function {
            entry["kind"] = json!("function");
            match gate.functions.describe(lib) {
                Ok(desc_json) => {
                    // The function returned JSON text; embed it parsed if valid,
                    // else surface the raw string so nothing is silently lost.
                    match serde_json::from_str::<Value>(&desc_json) {
                        Ok(v) => entry["description"] = v,
                        Err(_) => entry["description_raw"] = json!(desc_json),
                    }
                }
                Err(e) => entry["description_error"] = json!(e),
            }
        } else if r.static_dir.is_some() {
            entry["kind"] = json!("static");
        } else if r.proxy.is_some() {
            entry["kind"] = json!("proxy");
        }
        routes.push(entry);
    }

    let catalog = json!({
        "gatekeeper": {
            "describe_path": DESCRIBE_PATH,
            "abi_version": gatekeeper_abi::GK_ABI_VERSION,
        },
        "routes": routes,
    });

    let body = serde_json::to_vec_pretty(&catalog).unwrap_or_else(|_| b"{}".to_vec());
    Reply::new(200, body).with_header("Content-Type", "application/json")
}

/// The 401 body for an unauthenticated request to `/describe`: a JSON object that
/// explains HOW to authenticate (never the token value itself), so a caller hitting
/// the discovery endpoint without credentials learns what to do next.
fn describe_auth_help() -> Reply {
    use serde_json::json;
    let help = json!({
        "error": "unauthorized",
        "message": "This endpoint requires a shared-secret token. Present it one of two ways:",
        "auth": {
            "scheme": "shared-secret bearer token",
            "header": "Authorization: Bearer <token>",
            "cookie": "gatekeeper=<token>",
            "precedence": "the Authorization header is checked first; if present it is used and the cookie is NOT consulted",
            "note": "the token is a single shared secret for ALL private routes; it is provisioned out-of-band and is never returned by this API"
        },
        "example": "curl -H 'Authorization: Bearer <token>' https://<host>/describe"
    });
    let body = serde_json::to_vec_pretty(&help).unwrap_or_else(|_| b"{}".to_vec());
    Reply::new(401, body)
        .with_header("Content-Type", "application/json")
        .with_header("WWW-Authenticate", "Bearer")
}
