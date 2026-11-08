//! A small ACME (RFC 8555) service so tools like certbot, acme.sh, Caddy and Traefik
//! can obtain and renew certificates from this authority on their own.

use crate::ca;
use crate::model::*;
use crate::server::{Request, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
struct Ident {
    kind: String,
    value: String,
}

#[derive(Clone, Debug)]
struct Challenge {
    id: String,
    kind: String,
    token: String,
    status: String,
    validated: Option<i64>,
    error: Option<Value>,
}

#[derive(Clone, Debug)]
struct Authz {
    id: String,
    account: String,
    ident: Ident,
    wildcard: bool,
    status: String,
    expires: i64,
    challenges: Vec<Challenge>,
}

#[derive(Clone, Debug)]
struct Order {
    id: String,
    account: String,
    expires: i64,
    identifiers: Vec<Ident>,
    authz: Vec<String>,
    cert_id: Option<String>,
    error: Option<Value>,
    processing: bool,
}

#[derive(Default)]
struct Inner {
    nonces: HashSet<String>,
    nonce_order: VecDeque<String>,
    orders: HashMap<String, Order>,
    authz: HashMap<String, Authz>,
}

#[derive(Default)]
pub struct AcmeState {
    inner: Mutex<Inner>,
}

pub struct AcmeSummary {
    pub orders: usize,
    pub pending: usize,
}

impl AcmeState {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn new_nonce(&self) -> String {
        let n = URL_SAFE_NO_PAD.encode(random_bytes(16));
        let mut g = self.lock();
        g.nonces.insert(n.clone());
        g.nonce_order.push_back(n.clone());
        while g.nonce_order.len() > 20_000 {
            if let Some(old) = g.nonce_order.pop_front() {
                g.nonces.remove(&old);
            }
        }
        n
    }

    fn take_nonce(&self, n: &str) -> bool {
        self.lock().nonces.remove(n)
    }

    pub fn summary(&self) -> AcmeSummary {
        let g = self.lock();
        AcmeSummary {
            orders: g.orders.len(),
            pending: g.orders.values().filter(|o| o.cert_id.is_none() && o.error.is_none()).count(),
        }
    }
}

struct Problem {
    status: u16,
    kind: &'static str,
    detail: String,
}

fn problem(status: u16, kind: &'static str, detail: impl Into<String>) -> Problem {
    Problem { status, kind, detail: detail.into() }
}

fn b64d(s: &str) -> Result<Vec<u8>, Problem> {
    URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|_| problem(400, "malformed", "invalid base64url"))
}

fn jwk_str<'a>(jwk: &'a Value, k: &str) -> Result<&'a str, Problem> {
    jwk.get(k).and_then(|v| v.as_str()).ok_or_else(|| problem(400, "malformed", format!("jwk is missing \"{k}\"")))
}

pub fn thumbprint(jwk: &Value) -> Result<String, String> {
    let s = |k: &str| jwk.get(k).and_then(|v| v.as_str()).map(String::from).ok_or(format!("jwk missing {k}"));
    let canonical = match jwk.get("kty").and_then(|v| v.as_str()) {
        Some("EC") => format!(r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#, s("crv")?, s("x")?, s("y")?),
        Some("RSA") => format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, s("e")?, s("n")?),
        Some("OKP") => format!(r#"{{"crv":"{}","kty":"OKP","x":"{}"}}"#, s("crv")?, s("x")?),
        _ => return Err("unsupported key type".into()),
    };
    Ok(URL_SAFE_NO_PAD.encode(ring::digest::digest(&ring::digest::SHA256, canonical.as_bytes())))
}

fn verify_signature(alg: &str, jwk: &Value, input: &[u8], sig: &[u8]) -> Result<(), Problem> {
    use ring::signature as s;
    let bad = || problem(400, "badSignatureAlgorithm", format!("unsupported or mismatched algorithm {alg}"));
    let kty = jwk.get("kty").and_then(|v| v.as_str()).unwrap_or("");
    let res = match (alg, kty) {
        ("ES256", "EC") | ("ES384", "EC") => {
            let mut pt = vec![4u8];
            pt.extend(b64d(jwk_str(jwk, "x")?)?);
            pt.extend(b64d(jwk_str(jwk, "y")?)?);
            let a: &dyn s::VerificationAlgorithm = if alg == "ES256" { &s::ECDSA_P256_SHA256_FIXED } else { &s::ECDSA_P384_SHA384_FIXED };
            s::UnparsedPublicKey::new(a, pt).verify(input, sig)
        }
        ("RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512", "RSA") => {
            let n = b64d(jwk_str(jwk, "n")?)?;
            let e = b64d(jwk_str(jwk, "e")?)?;
            let params: &s::RsaParameters = match alg {
                "RS256" => &s::RSA_PKCS1_2048_8192_SHA256,
                "RS384" => &s::RSA_PKCS1_2048_8192_SHA384,
                "RS512" => &s::RSA_PKCS1_2048_8192_SHA512,
                "PS256" => &s::RSA_PSS_2048_8192_SHA256,
                "PS384" => &s::RSA_PSS_2048_8192_SHA384,
                _ => &s::RSA_PSS_2048_8192_SHA512,
            };
            s::RsaPublicKeyComponents { n: &n, e: &e }.verify(params, input, sig)
        }
        ("EdDSA", "OKP") => {
            let x = b64d(jwk_str(jwk, "x")?)?;
            s::UnparsedPublicKey::new(&s::ED25519, x).verify(input, sig)
        }
        _ => return Err(bad()),
    };
    res.map_err(|_| problem(400, "malformed", "JWS signature is invalid"))
}

struct Jws {
    payload: Vec<u8>,
    post_as_get: bool,
    jwk: Value,
    account: Option<String>,
}

fn url_path(u: &str) -> &str {
    let rest = u.split_once("://").map(|(_, r)| r).unwrap_or(u);
    let p = rest.find('/').map(|i| &rest[i..]).unwrap_or("/");
    p.split('?').next().unwrap_or(p)
}

pub struct Ctx<'a> {
    pub shared: &'a Arc<Shared>,
    pub acme: &'a Arc<AcmeState>,
    pub base: String,
}

impl Ctx<'_> {
    fn url(&self, p: &str) -> String {
        format!("{}/acme/{}", self.base, p)
    }

    fn finish(&self, r: Response) -> Response {
        r.header("Replay-Nonce", &self.acme.new_nonce())
            .header("Link", &format!("<{}>;rel=\"index\"", self.url("directory")))
            .header("Cache-Control", "no-store")
    }

    fn err(&self, p: Problem) -> Response {
        let body = json!({"type": format!("urn:ietf:params:acme:error:{}", p.kind), "detail": p.detail, "status": p.status});
        self.finish(Response::new(p.status, "application/problem+json", body.to_string().into_bytes()))
    }

    fn json(&self, status: u16, v: Value) -> Response {
        self.finish(Response::new(status, "application/json", serde_json::to_vec_pretty(&v).unwrap_or_default()))
    }

    fn parse(&self, req: &Request, allow_jwk: bool) -> Result<Jws, Problem> {
        let body: Value = serde_json::from_slice(&req.body).map_err(|_| problem(400, "malformed", "request body must be a JWS"))?;
        let prot_b64 = body.get("protected").and_then(|v| v.as_str()).ok_or_else(|| problem(400, "malformed", "missing protected header"))?;
        let payload_b64 = body.get("payload").and_then(|v| v.as_str()).ok_or_else(|| problem(400, "malformed", "missing payload"))?;
        let sig_b64 = body.get("signature").and_then(|v| v.as_str()).ok_or_else(|| problem(400, "malformed", "missing signature"))?;
        let prot: Value = serde_json::from_slice(&b64d(prot_b64)?).map_err(|_| problem(400, "malformed", "protected header is not JSON"))?;
        let nonce = prot.get("nonce").and_then(|v| v.as_str()).unwrap_or("");
        if !self.acme.take_nonce(nonce) {
            return Err(problem(400, "badNonce", "nonce is unknown or already used; get a fresh one"));
        }
        let url = prot.get("url").and_then(|v| v.as_str()).unwrap_or("");
        if url_path(url) != req.path {
            return Err(problem(401, "unauthorized", format!("JWS url {url} does not match the request")));
        }
        let alg = prot.get("alg").and_then(|v| v.as_str()).unwrap_or("");
        let (jwk, account) = match (prot.get("jwk"), prot.get("kid").and_then(|v| v.as_str())) {
            (Some(jwk), None) => {
                if !allow_jwk {
                    return Err(problem(400, "malformed", "this request must use \"kid\""));
                }
                (jwk.clone(), None)
            }
            (None, Some(kid)) => {
                let id = url_path(kid).rsplit('/').next().unwrap_or("").to_string();
                let st = self.shared.store();
                let acct = st.acme_accounts.iter().find(|a| a.id == id).ok_or_else(|| problem(400, "accountDoesNotExist", "unknown account"))?;
                if acct.status != "valid" {
                    return Err(problem(401, "unauthorized", "account is deactivated"));
                }
                (acct.jwk.clone(), Some(id))
            }
            _ => return Err(problem(400, "malformed", "exactly one of jwk or kid is required")),
        };
        let input = format!("{prot_b64}.{payload_b64}");
        verify_signature(alg, &jwk, input.as_bytes(), &b64d(sig_b64)?)?;
        let payload = b64d(payload_b64)?;
        if let Some(id) = &account {
            let mut st = self.shared.store();
            if let Some(a) = st.acme_accounts.iter_mut().find(|a| &a.id == id) {
                a.last_seen = now();
            }
        }
        Ok(Jws { post_as_get: payload_b64.is_empty(), payload, jwk, account })
    }

    fn payload_json(j: &Jws) -> Result<Value, Problem> {
        if j.payload.is_empty() {
            return Ok(json!({}));
        }
        serde_json::from_slice(&j.payload).map_err(|_| problem(400, "malformed", "payload is not JSON"))
    }

    fn auto_approve(&self) -> bool {
        self.shared.store().settings.server.acme_auto_approve
    }
}

fn order_status(inner: &Inner, o: &Order) -> &'static str {
    if o.cert_id.is_some() {
        return "valid";
    }
    if o.error.is_some() {
        return "invalid";
    }
    if o.processing {
        return "processing";
    }
    let st: Vec<&str> = o.authz.iter().filter_map(|a| inner.authz.get(a)).map(|a| a.status.as_str()).collect();
    if st.iter().any(|s| *s == "invalid" || *s == "deactivated" || *s == "revoked") {
        "invalid"
    } else if o.expires < now() {
        "invalid"
    } else if !st.is_empty() && st.iter().all(|s| *s == "valid") {
        "ready"
    } else {
        "pending"
    }
}

fn order_json(cx: &Ctx, inner: &Inner, o: &Order) -> Value {
    let mut v = json!({
        "status": order_status(inner, o),
        "expires": rfc3339(o.expires),
        "identifiers": o.identifiers.iter().map(|i| json!({"type": i.kind, "value": i.value})).collect::<Vec<_>>(),
        "authorizations": o.authz.iter().map(|a| cx.url(&format!("authz/{a}"))).collect::<Vec<_>>(),
        "finalize": cx.url(&format!("order/{}/finalize", o.id)),
    });
    if let Some(c) = &o.cert_id {
        v["certificate"] = json!(cx.url(&format!("cert/{c}")));
    }
    if let Some(e) = &o.error {
        v["error"] = e.clone();
    }
    v
}

fn chall_json(cx: &Ctx, c: &Challenge) -> Value {
    let mut v = json!({"type": c.kind, "url": cx.url(&format!("chall/{}", c.id)), "token": c.token, "status": c.status});
    if let Some(t) = c.validated {
        v["validated"] = json!(rfc3339(t));
    }
    if let Some(e) = &c.error {
        v["error"] = e.clone();
    }
    v
}

fn authz_json(cx: &Ctx, a: &Authz) -> Value {
    let mut v = json!({
        "identifier": {"type": a.ident.kind, "value": a.ident.value},
        "status": a.status,
        "expires": rfc3339(a.expires),
        "challenges": a.challenges.iter().map(|c| chall_json(cx, c)).collect::<Vec<_>>(),
    });
    if a.wildcard {
        v["wildcard"] = json!(true);
    }
    v
}

fn account_json(cx: &Ctx, a: &AcmeAccount) -> Value {
    json!({"status": a.status, "contact": a.contact, "orders": cx.url(&format!("acct/{}/orders", a.id)), "createdAt": rfc3339(a.created)})
}

/// Entry point for everything under /acme/.
pub fn handle(cx: &Ctx, req: &Request) -> Response {
    let sub = req.path.trim_start_matches("/acme/").to_string();
    let parts: Vec<&str> = sub.split('/').collect();
    let r = match (req.method.as_str(), parts.as_slice()) {
        ("GET", ["directory"]) | ("GET", [""]) => Ok(directory(cx)),
        ("HEAD", ["new-nonce"]) => Ok(cx.finish(Response::new(200, "text/plain", vec![]))),
        ("GET", ["new-nonce"]) => Ok(cx.finish(Response::new(204, "text/plain", vec![]))),
        ("POST", ["new-account"]) => new_account(cx, req),
        ("POST", ["acct", id]) => account(cx, req, id),
        ("POST", ["acct", id, "orders"]) => account_orders(cx, req, id),
        ("POST", ["new-order"]) => new_order(cx, req),
        ("POST", ["order", id]) => get_order(cx, req, id),
        ("POST", ["order", id, "finalize"]) => finalize(cx, req, id),
        ("POST", ["authz", id]) => get_authz(cx, req, id),
        ("POST", ["chall", id]) => challenge(cx, req, id),
        ("POST", ["cert", id]) => certificate(cx, req, id),
        ("POST", ["revoke-cert"]) => revoke(cx, req),
        ("POST", ["key-change"]) => Err(problem(501, "malformed", "key rollover is not supported; create a new account instead")),
        (_, _) => Err(problem(404, "malformed", "no such ACME resource")),
    };
    r.unwrap_or_else(|p| cx.err(p))
}

fn directory(cx: &Ctx) -> Response {
    cx.json(
        200,
        json!({
            "newNonce": cx.url("new-nonce"),
            "newAccount": cx.url("new-account"),
            "newOrder": cx.url("new-order"),
            "revokeCert": cx.url("revoke-cert"),
            "keyChange": cx.url("key-change"),
            "meta": {"website": format!("{}/", cx.base), "externalAccountRequired": false}
        }),
    )
}

fn new_account(cx: &Ctx, req: &Request) -> Result<Response, Problem> {
    let j = cx.parse(req, true)?;
    let p = Ctx::payload_json(&j)?;
    let tp = thumbprint(&j.jwk).map_err(|e| problem(400, "badPublicKey", e))?;
    let mut st = cx.shared.store();
    if let Some(a) = st.acme_accounts.iter().find(|a| a.thumbprint == tp).cloned() {
        drop(st);
        return Ok(cx.json(200, account_json(cx, &a)).header("Location", &cx.url(&format!("acct/{}", a.id))));
    }
    if p.get("onlyReturnExisting").and_then(|v| v.as_bool()).unwrap_or(false) {
        return Err(problem(400, "accountDoesNotExist", "no account exists for this key"));
    }
    let contact: Vec<String> = p.get("contact").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
    let acct = AcmeAccount { id: random_id(8), jwk: j.jwk.clone(), thumbprint: tp, contact: contact.clone(), created: now(), status: "valid".into(), last_seen: now(), orders: 0 };
    st.acme_accounts.push(acct.clone());
    let who = if contact.is_empty() { "no contact".to_string() } else { contact.join(", ") };
    st.log(LogKind::Info, "acme", format!("New ACME account {} ({who}) from {}", acct.id, req.remote));
    cx.shared.save(&st);
    drop(st);
    Ok(cx.json(201, account_json(cx, &acct)).header("Location", &cx.url(&format!("acct/{}", acct.id))))
}

fn account(cx: &Ctx, req: &Request, id: &str) -> Result<Response, Problem> {
    let j = cx.parse(req, false)?;
    if j.account.as_deref() != Some(id) {
        return Err(problem(401, "unauthorized", "not your account"));
    }
    let p = Ctx::payload_json(&j)?;
    let mut st = cx.shared.store();
    let a = st.acme_accounts.iter_mut().find(|a| a.id == id).ok_or_else(|| problem(404, "accountDoesNotExist", "unknown account"))?;
    if let Some(c) = p.get("contact").and_then(|v| v.as_array()) {
        a.contact = c.iter().filter_map(|x| x.as_str().map(String::from)).collect();
    }
    if p.get("status").and_then(|v| v.as_str()) == Some("deactivated") {
        a.status = "deactivated".into();
    }
    let out = a.clone();
    cx.shared.save(&st);
    drop(st);
    Ok(cx.json(200, account_json(cx, &out)))
}

fn account_orders(cx: &Ctx, req: &Request, id: &str) -> Result<Response, Problem> {
    let j = cx.parse(req, false)?;
    if j.account.as_deref() != Some(id) {
        return Err(problem(401, "unauthorized", "not your account"));
    }
    let g = cx.acme.lock();
    let urls: Vec<String> = g.orders.values().filter(|o| o.account == id).map(|o| cx.url(&format!("order/{}", o.id))).collect();
    drop(g);
    Ok(cx.json(200, json!({ "orders": urls })))
}

fn new_order(cx: &Ctx, req: &Request) -> Result<Response, Problem> {
    let j = cx.parse(req, false)?;
    let account = j.account.clone().unwrap_or_default();
    let p = Ctx::payload_json(&j)?;
    let ids = p.get("identifiers").and_then(|v| v.as_array()).ok_or_else(|| problem(400, "malformed", "identifiers are required"))?;
    if ids.is_empty() || ids.len() > 100 {
        return Err(problem(400, "malformed", "between 1 and 100 identifiers are allowed"));
    }
    let auto = cx.auto_approve();
    let mut idents = vec![];
    for i in ids {
        let kind = i.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let value = i.get("value").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
        match kind.as_str() {
            "dns" => {
                if ca::classify_name(&value) != Ok(ca::NameKind::Dns) {
                    return Err(problem(400, "rejectedIdentifier", format!("\"{value}\" is not a valid DNS name")));
                }
                if value.starts_with("*.") && !auto {
                    return Err(problem(400, "rejectedIdentifier", "wildcards need DNS validation, which this server only allows in auto-approve mode"));
                }
            }
            "ip" => {
                if value.parse::<std::net::IpAddr>().is_err() {
                    return Err(problem(400, "rejectedIdentifier", format!("\"{value}\" is not an IP address")));
                }
            }
            _ => return Err(problem(400, "unsupportedIdentifier", format!("identifier type \"{kind}\" is not supported"))),
        }
        idents.push(Ident { kind, value });
    }
    let t = now();
    let mut g = cx.acme.lock();
    let mut authz_ids = vec![];
    for i in &idents {
        let wildcard = i.value.starts_with("*.");
        let base = Ident { kind: i.kind.clone(), value: i.value.trim_start_matches("*.").to_string() };
        let token = URL_SAFE_NO_PAD.encode(random_bytes(24));
        let mut kinds = vec![];
        if !wildcard {
            kinds.push("http-01");
        }
        if auto {
            kinds.push("dns-01");
            kinds.push("tls-alpn-01");
        }
        let challenges = kinds
            .into_iter()
            .map(|k| Challenge { id: random_id(10), kind: k.into(), token: token.clone(), status: "pending".into(), validated: None, error: None })
            .collect();
        let a = Authz { id: random_id(10), account: account.clone(), ident: base, wildcard, status: "pending".into(), expires: t + 7 * 86_400, challenges };
        authz_ids.push(a.id.clone());
        g.authz.insert(a.id.clone(), a);
    }
    let o = Order { id: random_id(10), account: account.clone(), expires: t + 7 * 86_400, identifiers: idents.clone(), authz: authz_ids, cert_id: None, error: None, processing: false };
    let body = order_json(cx, &g, &o);
    let oid = o.id.clone();
    g.orders.insert(o.id.clone(), o);
    // Forget orders older than two weeks.
    let cutoff = t - 7 * 86_400;
    g.orders.retain(|_, o| o.expires > cutoff);
    let live: HashSet<String> = g.orders.values().flat_map(|o| o.authz.clone()).collect();
    g.authz.retain(|k, _| live.contains(k));
    drop(g);
    {
        let mut st = cx.shared.store();
        if let Some(a) = st.acme_accounts.iter_mut().find(|a| a.id == account) {
            a.orders += 1;
        }
        let names: Vec<String> = idents.iter().map(|i| i.value.clone()).collect();
        st.log(LogKind::Info, "acme", format!("ACME order for {} (account {account})", names.join(", ")));
    }
    cx.shared.poke();
    Ok(cx.json(201, body).header("Location", &cx.url(&format!("order/{oid}"))))
}

fn get_order(cx: &Ctx, req: &Request, id: &str) -> Result<Response, Problem> {
    let j = cx.parse(req, false)?;
    let g = cx.acme.lock();
    let o = g.orders.get(id).ok_or_else(|| problem(404, "malformed", "no such order"))?;
    if Some(&o.account) != j.account.as_ref() {
        return Err(problem(401, "unauthorized", "not your order"));
    }
    let v = order_json(cx, &g, o);
    drop(g);
    Ok(cx.json(200, v))
}

fn get_authz(cx: &Ctx, req: &Request, id: &str) -> Result<Response, Problem> {
    let j = cx.parse(req, false)?;
    let mut g = cx.acme.lock();
    let a = g.authz.get_mut(id).ok_or_else(|| problem(404, "malformed", "no such authorization"))?;
    if Some(&a.account) != j.account.as_ref() {
        return Err(problem(401, "unauthorized", "not your authorization"));
    }
    if !j.post_as_get {
        if let Ok(p) = Ctx::payload_json(&j) {
            if p.get("status").and_then(|v| v.as_str()) == Some("deactivated") {
                a.status = "deactivated".into();
            }
        }
    }
    let v = authz_json(cx, a);
    drop(g);
    Ok(cx.json(200, v))
}

fn challenge(cx: &Ctx, req: &Request, id: &str) -> Result<Response, Problem> {
    let j = cx.parse(req, false)?;
    let auto = cx.auto_approve();
    let mut g = cx.acme.lock();
    let authz_id = g
        .authz
        .values()
        .find(|a| a.challenges.iter().any(|c| c.id == id))
        .map(|a| a.id.clone())
        .ok_or_else(|| problem(404, "malformed", "no such challenge"))?;
    let a = g.authz.get_mut(&authz_id).unwrap();
    if Some(&a.account) != j.account.as_ref() {
        return Err(problem(401, "unauthorized", "not your challenge"));
    }
    let ident = a.ident.clone();
    let c = a.challenges.iter_mut().find(|c| c.id == id).unwrap();
    let mut start: Option<(String, String)> = None;
    if !j.post_as_get && c.status == "pending" {
        if auto {
            c.status = "valid".into();
            c.validated = Some(now());
        } else {
            c.status = "processing".into();
            start = Some((c.kind.clone(), c.token.clone()));
        }
    }
    let v = chall_json(cx, c);
    let became_valid = c.status == "valid";
    if became_valid && a.status == "pending" {
        a.status = "valid".into();
    }
    let account = a.account.clone();
    drop(g);
    if became_valid && auto && !j.post_as_get {
        cx.shared.store().log(LogKind::Info, "acme", format!("Auto-approved {} for account {account}", ident.value));
    }
    if let Some((kind, token)) = start {
        let thumb = thumbprint(&j.jwk).unwrap_or_default();
        let acme = cx.acme.clone();
        let shared = cx.shared.clone();
        let (aid, cid) = (authz_id.clone(), id.to_string());
        std::thread::spawn(move || validate(acme, shared, aid, cid, kind, ident, token, thumb));
    }
    Ok(cx.json(200, v).header("Link", &format!("<{}>;rel=\"up\"", cx.url(&format!("authz/{authz_id}")))))
}

#[allow(clippy::too_many_arguments)]
fn validate(acme: Arc<AcmeState>, shared: Arc<Shared>, authz_id: String, chall_id: String, kind: String, ident: Ident, token: String, thumb: String) {
    let expected = format!("{token}.{thumb}");
    let mut result: Result<(), String> = Err("not attempted".into());
    if kind == "http-01" {
        for attempt in 0..3 {
            if attempt > 0 {
                std::thread::sleep(std::time::Duration::from_secs(3));
            }
            result = http01(&ident.value, &token, &expected);
            if result.is_ok() {
                break;
            }
        }
    } else {
        result = Err(format!("{kind} validation is only available in auto-approve mode"));
    }
    let mut g = acme.lock();
    if let Some(a) = g.authz.get_mut(&authz_id) {
        if let Some(c) = a.challenges.iter_mut().find(|c| c.id == chall_id) {
            match &result {
                Ok(()) => {
                    c.status = "valid".into();
                    c.validated = Some(now());
                    a.status = "valid".into();
                }
                Err(msg) => {
                    c.status = "invalid".into();
                    c.error = Some(json!({"type": "urn:ietf:params:acme:error:incorrectResponse", "detail": msg, "status": 403}));
                    a.status = "invalid".into();
                }
            }
        }
    }
    drop(g);
    let mut st = shared.store();
    match result {
        Ok(()) => st.log(LogKind::Success, "acme", format!("Validated {} (http-01)", ident.value)),
        Err(m) => st.log(LogKind::Warn, "acme", format!("Validation failed for {}: {m}", ident.value)),
    }
    drop(st);
    shared.poke();
}

fn http01(host: &str, token: &str, expected: &str) -> Result<(), String> {
    use std::net::ToSocketAddrs;
    let addr_host = if host.contains(':') { format!("[{host}]:80") } else { format!("{host}:80") };
    let addrs: Vec<_> = addr_host.to_socket_addrs().map_err(|e| format!("could not resolve {host}: {e}"))?.collect();
    let addr = addrs.first().ok_or(format!("no address for {host}"))?;
    let mut s = std::net::TcpStream::connect_timeout(addr, std::time::Duration::from_secs(5)).map_err(|e| format!("could not connect to {host}:80 ({e})"))?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(8))).ok();
    let req = format!("GET /.well-known/acme-challenge/{token} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: LabCert-ACME/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut buf = vec![];
    let _ = s.take(65_536).read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    let (head, body) = text.split_once("\r\n\r\n").ok_or("the reply was not HTTP")?;
    let status = head.split_whitespace().nth(1).unwrap_or("");
    if status != "200" {
        return Err(format!("{host} answered with HTTP {status} instead of the challenge"));
    }
    let chunked = head.to_lowercase().contains("transfer-encoding: chunked");
    let body = if chunked { body.lines().nth(1).unwrap_or("") } else { body };
    if body.trim() == expected {
        Ok(())
    } else {
        Err(format!("{host} answered with the wrong challenge text"))
    }
}

fn finalize(cx: &Ctx, req: &Request, id: &str) -> Result<Response, Problem> {
    let j = cx.parse(req, false)?;
    let p = Ctx::payload_json(&j)?;
    let csr_der = b64d(p.get("csr").and_then(|v| v.as_str()).ok_or_else(|| problem(400, "malformed", "csr is required"))?)?;
    let (order, account) = {
        let mut g = cx.acme.lock();
        let o = g.orders.get(id).cloned().ok_or_else(|| problem(404, "malformed", "no such order"))?;
        if Some(&o.account) != j.account.as_ref() {
            return Err(problem(401, "unauthorized", "not your order"));
        }
        if order_status(&g, &o) != "ready" {
            return Err(problem(403, "orderNotReady", format!("order is {}, not ready", order_status(&g, &o))));
        }
        g.orders.get_mut(id).unwrap().processing = true;
        (o, j.account.clone().unwrap_or_default())
    };
    let fail = |cx: &Ctx, p: Problem| {
        let mut g = cx.acme.lock();
        if let Some(o) = g.orders.get_mut(id) {
            o.processing = false;
        }
        p
    };
    let csr = ca::parse_csr(&csr_der).map_err(|e| fail(cx, problem(400, "badCSR", e)))?;
    let wanted: HashSet<String> = order.identifiers.iter().map(|i| i.value.to_lowercase()).collect();
    let mut names: HashSet<String> = csr.sans.iter().map(|s| s.to_lowercase()).collect();
    if !csr.common_name.is_empty() {
        names.insert(csr.common_name.to_lowercase());
    }
    if names.is_empty() || !names.is_subset(&wanted) {
        return Err(fail(cx, problem(400, "badCSR", "the CSR names do not match the order")));
    }
    let issued = {
        let mut st = cx.shared.store();
        let ca_id = st.settings.server.acme_ca.clone().filter(|c| st.authority(c).is_some()).or_else(|| st.default_ca_id());
        let days = st.settings.server.acme_days.max(1);
        let r = match ca_id {
            Some(ca_id) => st.sign_csr(&csr, &ca_id, Profile::Server, days, &[], false, Source::Acme, &format!("ACME account {account}")),
            None => Err("no authority is set up".into()),
        };
        if r.is_ok() {
            cx.shared.save(&st);
        }
        r
    };
    let cert_id = issued.map_err(|e| fail(cx, problem(500, "serverInternal", e)))?;
    let mut g = cx.acme.lock();
    let o = g.orders.get_mut(id).unwrap();
    o.cert_id = Some(cert_id);
    o.processing = false;
    let o = o.clone();
    let v = order_json(cx, &g, &o);
    drop(g);
    cx.shared.poke();
    Ok(cx.json(200, v).header("Location", &cx.url(&format!("order/{id}"))))
}

fn certificate(cx: &Ctx, req: &Request, id: &str) -> Result<Response, Problem> {
    let j = cx.parse(req, false)?;
    let st = cx.shared.store();
    let c = st.cert(id).ok_or_else(|| problem(404, "malformed", "no such certificate"))?;
    let acct = j.account.clone().unwrap_or_default();
    if c.requested_by != format!("ACME account {acct}") {
        return Err(problem(401, "unauthorized", "not your certificate"));
    }
    let body = c.cert_pem.trim().to_string() + "\n" + &st.chain_pem(&c.ca_id, false);
    drop(st);
    Ok(cx.finish(Response::new(200, "application/pem-certificate-chain", body.into_bytes())))
}

fn revoke(cx: &Ctx, req: &Request) -> Result<Response, Problem> {
    let j = cx.parse(req, true)?;
    let p = Ctx::payload_json(&j)?;
    let der = b64d(p.get("certificate").and_then(|v| v.as_str()).ok_or_else(|| problem(400, "malformed", "certificate is required"))?)?;
    let reason = p.get("reason").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
    let fp = ca::fingerprint(&der, false);
    let mut st = cx.shared.store();
    let c = st.certs.iter().find(|c| c.fingerprint == fp).cloned().ok_or_else(|| problem(404, "malformed", "certificate was not issued here"))?;
    let allowed = match &j.account {
        Some(a) => c.requested_by == format!("ACME account {a}"),
        None => {
            // Signed with the certificate's own key: compare the JWK with the certificate's public key.
            let d = ca::cert_details_der(&der).ok();
            d.is_some() && jwk_matches_cert(&j.jwk, &der)
        }
    };
    if !allowed {
        return Err(problem(403, "unauthorized", "you may not revoke this certificate"));
    }
    if c.revoked.is_some() {
        return Err(problem(400, "alreadyRevoked", "certificate is already revoked"));
    }
    st.revoke(&c.id, Reason::from_code(reason)).map_err(|e| problem(500, "serverInternal", e))?;
    cx.shared.save(&st);
    drop(st);
    cx.shared.poke();
    Ok(cx.finish(Response::new(200, "text/plain", vec![])))
}

fn jwk_matches_cert(jwk: &Value, der: &[u8]) -> bool {
    use x509_parser::prelude::*;
    let Ok((_, c)) = parse_x509_certificate(der) else { return false };
    let raw = c.public_key().subject_public_key.data.to_vec();
    match jwk.get("kty").and_then(|v| v.as_str()) {
        Some("EC") => {
            let (Some(x), Some(y)) = (jwk.get("x").and_then(|v| v.as_str()), jwk.get("y").and_then(|v| v.as_str())) else { return false };
            let mut pt = vec![4u8];
            pt.extend(URL_SAFE_NO_PAD.decode(x).unwrap_or_default());
            pt.extend(URL_SAFE_NO_PAD.decode(y).unwrap_or_default());
            pt == raw
        }
        Some("OKP") => jwk.get("x").and_then(|v| v.as_str()).map(|x| URL_SAFE_NO_PAD.decode(x).unwrap_or_default() == raw).unwrap_or(false),
        Some("RSA") => {
            let n = jwk.get("n").and_then(|v| v.as_str()).map(|x| URL_SAFE_NO_PAD.decode(x).unwrap_or_default()).unwrap_or_default();
            !n.is_empty() && raw.windows(n.len()).any(|w| w == n.as_slice())
        }
        _ => false,
    }
}
