//! GitHub Actions OIDC verification.
//!
//! A GitHub job presents its short-lived JWT directly. Gatekeeper validates
//! the issuer's discovery document and JWKS, standard JWT time/audience/issuer
//! claims, then exact immutable repository and workflow policy. A match yields
//! scopes; it never turns a GitHub token into a general Gatekeeper login.

use std::io::Read;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

use crate::config::{GitHubOidcConfig, GitHubOidcPolicy};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubPrincipal {
    pub policy: String,
    pub repository_id: String,
    pub repository_owner_id: String,
    pub workflow_ref: String,
    pub run_id: String,
    pub run_attempt: String,
    pub commit: String,
}

#[derive(Debug, Clone, Deserialize)]
struct Claims {
    iss: String,
    aud: Audience,
    exp: u64,
    iat: u64,
    #[serde(default)]
    nbf: Option<u64>,
    repository_id: String,
    repository_owner_id: String,
    r#ref: String,
    workflow_ref: String,
    #[serde(default)]
    job_workflow_ref: Option<String>,
    #[serde(default)]
    environment: Option<String>,
    event_name: String,
    run_id: String,
    run_attempt: String,
    sha: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn contains(&self, wanted: &str) -> bool {
        match self {
            Audience::One(v) => v == wanted,
            Audience::Many(v) => v.iter().any(|x| x == wanted),
        }
    }
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
}

struct CachedKeys {
    fetched: Instant,
    jwks: jsonwebtoken::jwk::JwkSet,
}

pub struct GitHubOidcVerifier {
    cfg: GitHubOidcConfig,
    keys: Mutex<Option<CachedKeys>>,
}

impl GitHubOidcVerifier {
    pub fn new(cfg: GitHubOidcConfig) -> Self {
        Self {
            cfg,
            keys: Mutex::new(None),
        }
    }

    pub fn verify(&self, token: &str) -> Result<(GitHubPrincipal, Vec<String>), String> {
        if token.len() > 16 * 1024 {
            return Err("OIDC token is too large".into());
        }
        let header = decode_header(token).map_err(|_| "malformed OIDC token".to_string())?;
        if header.alg != Algorithm::RS256 {
            return Err("OIDC token must use RS256".into());
        }
        let kid = header.kid.ok_or("OIDC token has no kid")?;

        let mut refreshed = false;
        loop {
            let jwk = self.key(&kid, refreshed)?;
            if let Some(jwk) = jwk {
                let key = DecodingKey::from_jwk(&jwk)
                    .map_err(|_| "OIDC signing key is unsupported".to_string())?;
                let mut validation = Validation::new(Algorithm::RS256);
                validation.set_issuer(&[self.cfg.issuer.as_str()]);
                validation.set_audience(&[self.cfg.audience.as_str()]);
                validation.validate_nbf = true;
                validation.leeway = 30;
                let data = decode::<Claims>(token, &key, &validation)
                    .map_err(|_| "OIDC token validation failed".to_string())?;
                return self.authorize(data.claims);
            }
            if refreshed {
                return Err("OIDC token references an unknown signing key".into());
            }
            refreshed = true;
        }
    }

    fn authorize(&self, c: Claims) -> Result<(GitHubPrincipal, Vec<String>), String> {
        // jsonwebtoken validates these too; retaining them in Claims and checking
        // audience explicitly makes an accidental validation reconfiguration fail closed.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before Unix epoch")?
            .as_secs();
        if c.iss != self.cfg.issuer
            || !c.aud.contains(&self.cfg.audience)
            || c.exp == 0
            || c.iat > now.saturating_add(30)
            || c.iat > c.exp
            || c.exp.saturating_sub(c.iat) > 15 * 60
        {
            return Err("OIDC standard claims are invalid".into());
        }
        if matches!(c.nbf, Some(0)) {
            return Err("OIDC nbf is invalid".into());
        }
        let policy = self
            .cfg
            .policy
            .iter()
            .find(|p| policy_matches(p, &c))
            .ok_or("OIDC identity is valid but not authorized")?;
        if c.sha.len() != 40 || !c.sha.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("OIDC commit SHA is invalid".into());
        }
        Ok((
            GitHubPrincipal {
                policy: policy.name.clone(),
                repository_id: c.repository_id,
                repository_owner_id: c.repository_owner_id,
                workflow_ref: c.workflow_ref,
                run_id: c.run_id,
                run_attempt: c.run_attempt,
                commit: c.sha,
            },
            policy.scopes.clone(),
        ))
    }

    fn key(&self, kid: &str, force: bool) -> Result<Option<jsonwebtoken::jwk::Jwk>, String> {
        let ttl = Duration::from_secs(self.cfg.cache_ttl_secs);
        {
            let cache = self.keys.lock().map_err(|_| "OIDC key cache poisoned")?;
            if !force {
                if let Some(cached) = cache.as_ref() {
                    if cached.fetched.elapsed() < ttl {
                        return Ok(cached.jwks.find(kid).cloned());
                    }
                }
            }
        }
        let jwks = self.fetch_keys()?;
        let result = jwks.find(kid).cloned();
        *self.keys.lock().map_err(|_| "OIDC key cache poisoned")? = Some(CachedKeys {
            fetched: Instant::now(),
            jwks,
        });
        Ok(result)
    }

    fn fetch_keys(&self) -> Result<jsonwebtoken::jwk::JwkSet, String> {
        let discovery_url = self.cfg.discovery_url.clone().unwrap_or_else(|| {
            format!(
                "{}/.well-known/openid-configuration",
                self.cfg.issuer.trim_end_matches('/')
            )
        });
        let discovery_response = ureq::get(&discovery_url)
            .timeout(Duration::from_secs(10))
            .call()
            .map_err(|e| format!("fetching OIDC discovery failed: {e}"))?;
        let discovery: Discovery = parse_bounded_json(discovery_response, "OIDC discovery")?;
        if discovery.issuer != self.cfg.issuer || !discovery.jwks_uri.starts_with("https://") {
            return Err("OIDC discovery issuer/JWKS URL is invalid".into());
        }
        let jwks_response = ureq::get(&discovery.jwks_uri)
            .timeout(Duration::from_secs(10))
            .call()
            .map_err(|e| format!("fetching OIDC keys failed: {e}"))?;
        parse_bounded_json(jwks_response, "OIDC keys")
    }
}

fn parse_bounded_json<T: serde::de::DeserializeOwned>(
    response: ureq::Response,
    what: &str,
) -> Result<T, String> {
    const LIMIT: u64 = 1024 * 1024;
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("reading {what} failed: {e}"))?;
    if bytes.len() as u64 > LIMIT {
        return Err(format!("{what} is too large"));
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("parsing {what} failed: {e}"))
}

fn policy_matches(p: &GitHubOidcPolicy, c: &Claims) -> bool {
    p.repository_id == c.repository_id
        && p.repository_owner_id == c.repository_owner_id
        && p.r#ref == c.r#ref
        && (p.workflow_ref == c.workflow_ref
            || c.job_workflow_ref.as_deref() == Some(p.workflow_ref.as_str()))
        && p.environment
            .as_deref()
            .is_none_or(|x| c.environment.as_deref() == Some(x))
        && (p.event_names.is_empty() || p.event_names.iter().any(|x| x == &c.event_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> GitHubOidcPolicy {
        GitHubOidcPolicy {
            name: "coil-nightly".into(),
            repository_id: "123".into(),
            repository_owner_id: "456".into(),
            r#ref: "refs/heads/main".into(),
            workflow_ref: "jimmyhmiller/coil/.github/workflows/nightly.yml@refs/heads/main".into(),
            environment: Some("nightly-release".into()),
            event_names: vec!["schedule".into(), "workflow_dispatch".into()],
            scopes: vec!["coil:nightly:publish".into()],
        }
    }

    fn claims() -> Claims {
        Claims {
            iss: "https://token.actions.githubusercontent.com".into(),
            aud: Audience::One("https://computer.example/coil/releases".into()),
            exp: u64::MAX,
            iat: u64::MAX - 60,
            nbf: None,
            repository_id: "123".into(),
            repository_owner_id: "456".into(),
            r#ref: "refs/heads/main".into(),
            workflow_ref: policy().workflow_ref,
            job_workflow_ref: None,
            environment: Some("nightly-release".into()),
            event_name: "schedule".into(),
            run_id: "77".into(),
            run_attempt: "1".into(),
            sha: "0123456789012345678901234567890123456789".into(),
        }
    }

    #[test]
    fn exact_policy_matches() {
        assert!(policy_matches(&policy(), &claims()));
    }

    #[test]
    fn wrong_repo_ref_workflow_environment_and_event_each_fail() {
        let p = policy();
        let mut cases = Vec::new();
        let mut c = claims();
        c.repository_id = "999".into();
        cases.push(c);
        let mut c = claims();
        c.r#ref = "refs/heads/feature".into();
        cases.push(c);
        let mut c = claims();
        c.workflow_ref = "other.yml@refs/heads/main".into();
        cases.push(c);
        let mut c = claims();
        c.environment = Some("other".into());
        cases.push(c);
        let mut c = claims();
        c.event_name = "pull_request".into();
        cases.push(c);
        assert!(cases.iter().all(|c| !policy_matches(&p, c)));
    }
}
