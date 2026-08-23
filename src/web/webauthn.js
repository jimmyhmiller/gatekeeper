// Shared WebAuthn plumbing for the gatekeeper login and register pages.
//
// The wire format is base64url on both sides (that is how webauthn-rs
// serializes challenges and credential ids), but the browser API wants and
// returns ArrayBuffers. These four helpers are the whole translation layer.
// Written by hand rather than using PublicKeyCredential.parseCreationOptionsFromJSON
// so this works on every browser that supports passkeys at all, not just the
// ones that shipped the JSON helpers.

function b64urlToBytes(s) {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Decode the id-shaped fields of a challenge in place.
function decodeOptions(publicKey) {
  publicKey.challenge = b64urlToBytes(publicKey.challenge);
  if (publicKey.user && publicKey.user.id) {
    publicKey.user.id = b64urlToBytes(publicKey.user.id);
  }
  for (const list of [publicKey.excludeCredentials, publicKey.allowCredentials]) {
    if (list) for (const c of list) c.id = b64urlToBytes(c.id);
  }
  return publicKey;
}

// Encode a PublicKeyCredential back to the JSON shape webauthn-rs expects.
function encodeCredential(cred) {
  const r = cred.response;
  const out = {
    id: cred.id,
    rawId: bytesToB64url(cred.rawId),
    type: cred.type,
    extensions: cred.getClientExtensionResults(),
    response: { clientDataJSON: bytesToB64url(r.clientDataJSON) },
  };
  if (r.attestationObject) {
    out.response.attestationObject = bytesToB64url(r.attestationObject);
  } else {
    out.response.authenticatorData = bytesToB64url(r.authenticatorData);
    out.response.signature = bytesToB64url(r.signature);
    out.response.userHandle = r.userHandle ? bytesToB64url(r.userHandle) : null;
  }
  return out;
}

async function postJSON(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  let data = null;
  try { data = await res.json(); } catch (e) { data = null; }
  if (!res.ok) {
    throw new Error((data && data.error) || res.status + " " + res.statusText);
  }
  return data;
}
