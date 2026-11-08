//! Built-in HTTP/HTTPS service: hands out the root certificate and revocation lists,
//! accepts signing requests with enrollment tokens, and hosts the ACME service.

use crate::acme::{self, AcmeState};
use crate::ca;
use crate::model::*;
use base64::Engine;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub struct Request {
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub remote: SocketAddr,
    pub tls: bool,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
    pub fn q(&self, name: &str) -> Option<&str> {
        self.query.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
    pub fn base_url(&self, fallback_port: u16) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        let host = self.header("host").map(String::from).unwrap_or_else(|| format!("{}:{fallback_port}", ca::host_name()));
        format!("{scheme}://{host}")
    }
}

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, ctype: &str, body: Vec<u8>) -> Response {
        Response { status, headers: vec![("Content-Type".into(), ctype.into())], body }
    }
    pub fn header(mut self, k: &str, v: &str) -> Response {
        self.headers.push((k.into(), v.into()));
        self
    }
    fn text(status: u16, s: impl Into<String>) -> Response {
        Response::new(status, "text/plain; charset=utf-8", s.into().into_bytes())
    }
    fn json(status: u16, v: serde_json::Value) -> Response {
        Response::new(status, "application/json", serde_json::to_vec_pretty(&v).unwrap_or_default())
    }
    fn download(ctype: &str, name: &str, body: Vec<u8>) -> Response {
        Response::new(200, ctype, body).header("Content-Disposition", &format!("attachment; filename=\"{name}\""))
    }
}

fn reason_phrase(s: u16) -> &'static str {
    match s {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        411 => "Length Required",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        _ => "Status",
    }
}

fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                if let Some(v) = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    out.push(v);
                    i += 2;
                } else {
                    out.push(b'%');
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn read_request<S: Read>(s: &mut S, remote: SocketAddr, tls: bool) -> Result<Request, (u16, String)> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let n = s.read(&mut chunk).map_err(|e| (400, e.to_string()))?;
        if n == 0 {
            return Err((400, "connection closed".into()));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p;
        }
        if buf.len() > 64 * 1024 {
            return Err((413, "headers too large".into()));
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let first = lines.next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("").to_uppercase();
    let target = parts.next().unwrap_or("/").to_string();
    let mut headers = vec![];
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_lowercase(), v.trim().to_string()));
        }
    }
    let (path, qs) = target.split_once('?').map(|(a, b)| (a.to_string(), b.to_string())).unwrap_or((target.clone(), String::new()));
    let query = qs
        .split('&')
        .filter(|x| !x.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (url_decode(k), url_decode(v))
        })
        .collect();
    let mut body = buf[header_end + 4..].to_vec();
    let len: usize = headers.iter().find(|(k, _)| k == "content-length").and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
    if headers.iter().any(|(k, v)| k == "transfer-encoding" && v.to_lowercase().contains("chunked")) {
        return Err((411, "chunked uploads are not supported; send Content-Length".into()));
    }
    if len > 2 * 1024 * 1024 {
        return Err((413, "body too large".into()));
    }
    while body.len() < len {
        let n = s.read(&mut chunk).map_err(|e| (400, e.to_string()))?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(len);
    Ok(Request { method, path: url_decode(&path), query, headers, body, remote, tls })
}

fn write_response<S: Write>(s: &mut S, r: &Response, head_only: bool) -> std::io::Result<()> {
    let mut out = format!("HTTP/1.1 {} {}\r\n", r.status, reason_phrase(r.status));
    for (k, v) in &r.headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str(&format!("Content-Length: {}\r\nServer: LabCert\r\nConnection: close\r\n\r\n", r.body.len()));
    s.write_all(out.as_bytes())?;
    if !head_only {
        s.write_all(&r.body)?;
    }
    s.flush()
}

// ---------------------------------------------------------------------------

pub struct Server {
    stop: Arc<AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
    pub http_addr: Option<SocketAddr>,
    pub https_addr: Option<SocketAddr>,
    pub started: i64,
    pub requests: Arc<AtomicU64>,
}

struct Ctx {
    shared: Arc<Shared>,
    acme: Arc<AcmeState>,
    requests: Arc<AtomicU64>,
    http_port: u16,
    https_port: u16,
}

fn tls_config(st: &mut Store) -> Res<Arc<rustls::ServerConfig>> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let id = st.ensure_server_cert()?;
    let c = st.cert(&id).ok_or("server certificate missing")?;
    let mut chain = vec![CertificateDer::from(ca::pem_to_der(&c.cert_pem)?)];
    for a in st.ca_chain(&c.ca_id) {
        chain.push(CertificateDer::from(ca::pem_to_der(&a.cert_pem)?));
    }
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ca::pem_to_der(c.key_pem.as_deref().unwrap_or(""))?));
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| e.to_string())?;
    Ok(Arc::new(cfg))
}

impl Server {
    pub fn start(shared: Arc<Shared>, acme: Arc<AcmeState>) -> Res<Server> {
        let (cfg, tls) = {
            let mut st = shared.store();
            let cfg = st.settings.server.clone();
            if !cfg.http_on && !cfg.https_on {
                return Err("Turn on at least one of the plain (HTTP) or secure (HTTPS) addresses.".into());
            }
            let tls = if cfg.https_on {
                let t = tls_config(&mut st);
                shared.save(&st);
                Some(t?)
            } else {
                None
            };
            (cfg, tls)
        };
        let bind = if cfg.bind.trim().is_empty() { "0.0.0.0".to_string() } else { cfg.bind.trim().to_string() };
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicU64::new(0));
        let ctx = Arc::new(Ctx { shared: shared.clone(), acme, requests: requests.clone(), http_port: cfg.http_port, https_port: cfg.https_port });
        let mut threads = vec![];
        let mut http_addr = None;
        let mut https_addr = None;
        let mut listeners = vec![];
        if cfg.http_on {
            let l = TcpListener::bind(format!("{bind}:{}", cfg.http_port)).map_err(|e| format!("Could not open port {} ({e}). Is another program using it?", cfg.http_port))?;
            http_addr = l.local_addr().ok();
            listeners.push((l, None));
        }
        if let Some(tls) = tls {
            let l = TcpListener::bind(format!("{bind}:{}", cfg.https_port)).map_err(|e| format!("Could not open port {} ({e}). Is another program using it?", cfg.https_port))?;
            https_addr = l.local_addr().ok();
            listeners.push((l, Some(tls)));
        }
        for (l, tls) in listeners {
            let stop = stop.clone();
            let ctx = ctx.clone();
            threads.push(std::thread::spawn(move || accept_loop(l, tls, stop, ctx)));
        }
        {
            let mut st = shared.store();
            let mut parts = vec![];
            if let Some(a) = http_addr {
                parts.push(format!("HTTP port {}", a.port()));
            }
            if let Some(a) = https_addr {
                parts.push(format!("HTTPS port {}", a.port()));
            }
            st.log(LogKind::Success, "server", format!("Network service started ({})", parts.join(", ")));
            shared.save(&st);
        }
        Ok(Server { stop, threads, http_addr, https_addr, started: now(), requests })
    }

    pub fn stop(self, shared: &Shared) {
        self.stop.store(true, Ordering::SeqCst);
        for t in self.threads {
            let _ = t.join();
        }
        let mut st = shared.store();
        st.log(LogKind::Info, "server", "Network service stopped");
        shared.save(&st);
    }
}

fn accept_loop(l: TcpListener, tls: Option<Arc<rustls::ServerConfig>>, stop: Arc<AtomicBool>, ctx: Arc<Ctx>) {
    let _ = l.set_nonblocking(true);
    while !stop.load(Ordering::SeqCst) {
        match l.accept() {
            Ok((s, addr)) => {
                let tls = tls.clone();
                let ctx = ctx.clone();
                std::thread::spawn(move || handle_conn(s, addr, tls, ctx));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(25)),
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

fn handle_conn(s: TcpStream, addr: SocketAddr, tls: Option<Arc<rustls::ServerConfig>>, ctx: Arc<Ctx>) {
    let _ = s.set_nonblocking(false);
    let _ = s.set_read_timeout(Some(Duration::from_secs(15)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(15)));
    let _ = s.set_nodelay(true);
    match tls {
        Some(cfg) => {
            let Ok(conn) = rustls::ServerConnection::new(cfg) else { return };
            let mut stream = rustls::StreamOwned::new(conn, s);
            serve(&mut stream, addr, true, &ctx);
            stream.conn.send_close_notify();
            let _ = stream.flush();
        }
        None => {
            let mut s = s;
            serve(&mut s, addr, false, &ctx);
        }
    }
}

fn serve<S: Read + Write>(s: &mut S, addr: SocketAddr, tls: bool, ctx: &Ctx) {
    let req = match read_request(s, addr, tls) {
        Ok(r) => r,
        Err((code, msg)) => {
            if code != 400 || msg != "connection closed" {
                let _ = write_response(s, &Response::text(code, msg), false);
            }
            return;
        }
    };
    ctx.requests.fetch_add(1, Ordering::Relaxed);
    let resp = route(ctx, &req);
    let _ = write_response(s, &resp, req.method == "HEAD");
    ctx.shared.http(HttpLog { ts: now(), remote: addr.ip().to_string(), method: req.method.clone(), path: req.path.clone(), status: resp.status, tls });
}

fn route(ctx: &Ctx, req: &Request) -> Response {
    let base = req.base_url(if req.tls { ctx.https_port } else { ctx.http_port });
    let p = req.path.as_str();
    if p.starts_with("/acme/") || p == "/acme" {
        let on = ctx.shared.store().settings.server.acme_on;
        if !on {
            return Response::text(404, "ACME is turned off in LabCert (Server page).");
        }
        let cx = acme::Ctx { shared: &ctx.shared, acme: &ctx.acme, base };
        return acme::handle(&cx, req);
    }
    if req.method == "POST" {
        return match p {
            "/api/enroll" | "/api/sign" => enroll(ctx, req, &base),
            _ => Response::text(405, "Only the enrollment and ACME addresses accept uploads."),
        };
    }
    if req.method != "GET" && req.method != "HEAD" {
        return Response::text(405, "method not allowed");
    }
    let mut st = ctx.shared.store();
    if st.refresh_crls() {
        ctx.shared.save(&st);
    }
    let default = st.default_ca_id();
    let root = default.as_deref().and_then(|d| st.root_of(d)).map(|a| a.id.clone());
    let pick = |name: &str, fallback: &Option<String>| -> Option<String> {
        if name.is_empty() { fallback.clone() } else { Some(name.to_string()) }
    };
    let segs: Vec<&str> = p.trim_start_matches('/').split('/').collect();
    match segs.as_slice() {
        [""] | ["index.html"] => Response::new(200, "text/html; charset=utf-8", landing(&st, &base, req.tls, ctx).into_bytes()),
        ["favicon.ico"] => Response::new(204, "image/x-icon", vec![]),
        ["api", "health"] => Response::json(200, serde_json::json!({"status": "ok", "authorities": st.authorities.len(), "time": rfc3339(now())})),
        ["api", "request", id] => poll(&st, id, &base),
        ["ca.crt"] | ["ca.cer"] | ["ca.der"] | ["ca.pem"] | ["ca.mobileconfig"] | ["chain.pem"] => {
            let Some(r) = root.clone() else { return Response::text(404, "No authority has been created yet.") };
            ca_file(&st, &r, segs[0], default.as_deref())
        }
        ["ca", file] => {
            let (id, ext) = file.rsplit_once('.').unwrap_or((file, "crt"));
            match st.authority(id) {
                Some(_) => ca_file(&st, id, &format!("ca.{ext}"), Some(id)),
                None => Response::text(404, "unknown authority"),
            }
        }
        ["crl.pem"] | ["crl.crl"] => crl_file(&st, default.as_deref(), segs[0].ends_with(".pem")),
        ["crl", file] => {
            let (id, ext) = file.rsplit_once('.').unwrap_or((file, "crl"));
            crl_file(&st, pick(id, &default).as_deref(), ext == "pem")
        }
        ["certs"] if st.settings.server.publish_certs => {
            let list: Vec<serde_json::Value> = st
                .certs
                .iter()
                .filter(|c| c.revoked.is_none() && c.not_after > now())
                .map(|c| serde_json::json!({"name": c.common_name, "serial": c.serial, "expires": rfc3339(c.not_after), "url": format!("{base}/certs/{}.crt", c.serial)}))
                .collect();
            Response::json(200, serde_json::json!({ "certificates": list }))
        }
        ["certs", file] if st.settings.server.publish_certs => {
            let serial = file.trim_end_matches(".crt").trim_end_matches(".pem");
            match st.certs.iter().find(|c| c.serial == serial) {
                Some(c) => Response::download("application/x-pem-file", &format!("{serial}.crt"), (c.cert_pem.trim().to_string() + "\n" + &st.chain_pem(&c.ca_id, false)).into_bytes()),
                None => Response::text(404, "unknown certificate"),
            }
        }
        _ => {
            drop(st);
            Response::text(404, "Not found. Open / for the list of addresses.")
        }
    }
}

fn ca_file(st: &Store, id: &str, file: &str, chain_from: Option<&str>) -> Response {
    let Some(a) = st.authority(id) else { return Response::text(404, "unknown authority") };
    let fname = a.name.replace(|c: char| !c.is_ascii_alphanumeric(), "-");
    match file {
        "ca.pem" => Response::download("application/x-pem-file", &format!("{fname}.pem"), a.cert_pem.clone().into_bytes()),
        "ca.cer" | "ca.der" => Response::download("application/pkix-cert", &format!("{fname}.cer"), ca::pem_to_der(&a.cert_pem).unwrap_or_default()),
        "chain.pem" => Response::download("application/x-pem-file", "chain.pem", st.chain_pem(chain_from.unwrap_or(id), true).into_bytes()),
        "ca.mobileconfig" => {
            let der = ca::pem_to_der(&a.cert_pem).unwrap_or_default();
            let b64 = base64::engine::general_purpose::STANDARD.encode(der);
            let uuid1 = uuidish();
            let uuid2 = uuidish();
            let name = xml_escape(&a.name);
            let body = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>PayloadContent</key><array><dict>
<key>PayloadCertificateFileName</key><string>{fname}.cer</string>
<key>PayloadContent</key><data>{b64}</data>
<key>PayloadDescription</key><string>Adds the {name} root certificate</string>
<key>PayloadDisplayName</key><string>{name}</string>
<key>PayloadIdentifier</key><string>lan.labcert.root.{uuid1}</string>
<key>PayloadType</key><string>com.apple.security.root</string>
<key>PayloadUUID</key><string>{uuid1}</string>
<key>PayloadVersion</key><integer>1</integer>
</dict></array>
<key>PayloadDisplayName</key><string>{name} (local network)</string>
<key>PayloadIdentifier</key><string>lan.labcert.profile.{uuid2}</string>
<key>PayloadRemovalDisallowed</key><false/>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadUUID</key><string>{uuid2}</string>
<key>PayloadVersion</key><integer>1</integer>
</dict></plist>
"#
            );
            Response::download("application/x-apple-aspen-config", &format!("{fname}.mobileconfig"), body.into_bytes())
        }
        _ => Response::download("application/x-x509-ca-cert", &format!("{fname}.crt"), ca::pem_to_der(&a.cert_pem).unwrap_or_default()),
    }
}

fn uuidish() -> String {
    let h = random_id(16).to_uppercase();
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn crl_file(st: &Store, id: Option<&str>, pem_out: bool) -> Response {
    let Some(a) = id.and_then(|i| st.authority(i)) else { return Response::text(404, "unknown authority") };
    let Some(crl) = &a.crl_pem else { return Response::text(404, "no revocation list yet") };
    if pem_out {
        Response::download("application/x-pem-file", &format!("{}.crl.pem", a.id), crl.clone().into_bytes())
    } else {
        Response::new(200, "application/pkix-crl", ca::pem_to_der(crl).unwrap_or_default())
    }
}

fn enroll(ctx: &Ctx, req: &Request, base: &str) -> Response {
    let secret = req
        .q("token")
        .map(String::from)
        .or_else(|| req.header("authorization").and_then(|h| h.strip_prefix("Bearer ").map(|s| s.trim().to_string())))
        .unwrap_or_default();
    let mut st = ctx.shared.store();
    if !st.settings.server.enroll_on {
        return Response::json(403, serde_json::json!({"error": "Enrollment is turned off"}));
    }
    let Some(ti) = st.tokens.iter().position(|t| !secret.is_empty() && t.secret == secret) else {
        st.log(LogKind::Warn, "enroll", format!("Rejected enrollment from {} (unknown token)", req.remote.ip()));
        return Response::json(401, serde_json::json!({"error": "Unknown enrollment token"}));
    };
    let tok = st.tokens[ti].clone();
    if !tok.usable() {
        return Response::json(401, serde_json::json!({"error": "This token is expired, disabled or used up"}));
    }
    let csr = match ca::parse_csr(&req.body) {
        Ok(c) => c,
        Err(e) => return Response::json(400, serde_json::json!({"error": e})),
    };
    let ca_id = tok.ca_id.clone().filter(|c| st.authority(c).is_some()).or_else(|| st.default_ca_id());
    let Some(ca_id) = ca_id else { return Response::json(500, serde_json::json!({"error": "No authority is set up"})) };
    st.tokens[ti].uses += 1;
    let from = req.remote.ip().to_string();
    if tok.auto_approve {
        let r = st.sign_csr(&csr, &ca_id, tok.profile, tok.validity_days.max(1), &[], true, Source::Enrollment, &format!("Token \"{}\" from {from}", tok.label));
        let out = match r {
            Ok(id) => {
                let c = st.cert(&id).unwrap();
                let body = c.cert_pem.trim().to_string() + "\n" + &st.chain_pem(&c.ca_id, false);
                Response::new(200, "application/pem-certificate-chain", body.into_bytes()).header("X-Certificate-Id", &id)
            }
            Err(e) => Response::json(400, serde_json::json!({"error": e})),
        };
        ctx.shared.save(&st);
        drop(st);
        ctx.shared.poke();
        return out;
    }
    let id = random_id(12);
    st.requests.push(PendingRequest {
        id: id.clone(),
        received: now(),
        from_addr: from.clone(),
        token_label: tok.label.clone(),
        csr_pem: csr.pem.clone(),
        subject: csr.subject.clone(),
        sans: csr.sans.clone(),
        key_desc: csr.key.desc.clone(),
        profile: tok.profile,
        validity_days: tok.validity_days.max(1),
        ca_id: Some(ca_id),
        status: RequestStatus::Pending,
        cert_id: None,
        note: String::new(),
    });
    st.log(LogKind::Info, "enroll", format!("Request for \"{}\" from {from} is waiting for approval", if csr.common_name.is_empty() { csr.sans.join(", ") } else { csr.common_name.clone() }));
    ctx.shared.save(&st);
    drop(st);
    ctx.shared.poke();
    Response::json(202, serde_json::json!({"id": id, "status": "pending", "poll": format!("{base}/api/request/{id}")}))
}

fn poll(st: &Store, id: &str, base: &str) -> Response {
    let Some(r) = st.requests.iter().find(|r| r.id == id) else { return Response::json(404, serde_json::json!({"error": "unknown request"})) };
    match r.status {
        RequestStatus::Pending => Response::json(202, serde_json::json!({"id": id, "status": "pending", "poll": format!("{base}/api/request/{id}")})).header("Retry-After", "30"),
        RequestStatus::Rejected => Response::json(403, serde_json::json!({"id": id, "status": "rejected", "note": r.note})),
        RequestStatus::Issued => match r.cert_id.as_deref().and_then(|c| st.cert(c)) {
            Some(c) => Response::new(200, "application/pem-certificate-chain", (c.cert_pem.trim().to_string() + "\n" + &st.chain_pem(&c.ca_id, false)).into_bytes()),
            None => Response::json(410, serde_json::json!({"error": "certificate was deleted"})),
        },
    }
}

fn html_escape(s: &str) -> String {
    xml_escape(s)
}

fn landing(st: &Store, base: &str, tls: bool, ctx: &Ctx) -> String {
    let s = &st.settings.server;
    let host = base.split("://").nth(1).unwrap_or("").split(':').next().unwrap_or("").to_string();
    let https_base = format!("https://{}:{}", if host.is_empty() { ca::host_name() } else { host.clone() }, ctx.https_port);
    let http_base = format!("http://{}:{}", if host.is_empty() { ca::host_name() } else { host.clone() }, ctx.http_port);
    let acme_base = if s.https_on { https_base.clone() } else { http_base.clone() };
    let mut roots = String::new();
    for a in st.authorities.iter().filter(|a| a.is_root()) {
        roots.push_str(&format!(
            r#"<div class="ca"><div class="ca-name">{}</div><div class="muted">Valid until {} &middot; SHA-256 {}</div>
<div class="btns"><a class="btn" href="/ca/{id}.crt">Windows / Android (.crt)</a><a class="btn" href="/ca/{id}.pem">Linux / macOS (.pem)</a><a class="btn" href="/ca/{id}.mobileconfig">iPhone / iPad profile</a></div></div>"#,
            html_escape(&a.name),
            fmt_date(a.not_after),
            &a.fingerprint,
            id = a.id
        ));
    }
    if roots.is_empty() {
        roots = "<p class=\"muted\">No authority has been created yet. Open LabCert on the server computer and create one.</p>".into();
    }
    let mut crls = String::new();
    for a in &st.authorities {
        crls.push_str(&format!("<li>{} &mdash; <a href=\"/crl/{id}.crl\">/crl/{id}.crl</a> (<a href=\"/crl/{id}.pem\">PEM</a>)</li>", html_escape(&a.name), id = a.id));
    }
    let acme = if s.acme_on {
        format!(
            r#"<h2>2. Automatic certificates (ACME)</h2>
<p>Any ACME client can get and renew certificates here, the same way it would with Let's Encrypt. {mode}</p>
<div class="code">{acme_base}/acme/directory</div>
<details><summary>Examples</summary>
<div class="code">certbot certonly --standalone --server {acme_base}/acme/directory -d myhost.lan</div>
<div class="code">acme.sh --issue --standalone --server {acme_base}/acme/directory --ca-bundle root.pem -d myhost.lan</div>
<div class="code">Caddyfile:  tls {{ ca {acme_base}/acme/directory  ca_root /path/to/root.pem }}</div>
<p class="muted">The client must trust the root certificate above to talk to the secure address (certbot: REQUESTS_CA_BUNDLE=root.pem).</p></details>"#,
            mode = if s.acme_auto_approve { "This server is in <b>lab mode</b>: requests are approved without a domain check." } else { "Ownership is checked with the http-01 challenge on port 80." }
        )
    } else {
        String::new()
    };
    let enroll = if s.enroll_on {
        format!(
            r#"<h2>3. Request a certificate with a token</h2>
<p>Ask the LabCert administrator for an enrollment token, then send a signing request:</p>
<div class="code">openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout host.key -subj "/CN=myhost.lan" -addext "subjectAltName=DNS:myhost.lan" -out host.csr</div>
<div class="code">curl --data-binary @host.csr "{http_base}/api/enroll?token=YOUR_TOKEN" -o host.crt</div>
<p class="muted">If the token needs approval, the reply contains an address to check later.</p>"#
        )
    } else {
        String::new()
    };
    let secure_note = if tls { "" } else { "<p class=\"muted\">Tip: once the root certificate is trusted, you can use the secure address too.</p>" };
    format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>LabCert — local certificates</title>
<style>
body{{margin:0;font-family:Segoe UI,system-ui,sans-serif;background:#0f1720;color:#dce4ee}}
.wrap{{max-width:860px;margin:0 auto;padding:32px 20px 60px}}
.top{{display:flex;align-items:center;gap:14px}}
.logo{{width:42px;height:42px;border-radius:10px;background:linear-gradient(135deg,#2bb5a0,#2a7fd4)}}
h1{{font-size:26px;margin:0}} h2{{font-size:18px;margin:34px 0 8px;color:#fff}}
.muted{{color:#8a9bb0;font-size:13px}}
.ca{{background:#1b2735;border:1px solid #263445;border-radius:12px;padding:16px;margin:10px 0;word-break:break-all}}
.ca-name{{font-weight:600;font-size:16px;margin-bottom:4px}}
.btns{{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}}
.btn{{background:#2bb5a0;color:#06231e;text-decoration:none;padding:8px 14px;border-radius:8px;font-weight:600;font-size:14px}}
.code{{background:#0a1118;border:1px solid #263445;border-radius:8px;padding:10px 12px;font-family:Consolas,monospace;font-size:13px;margin:8px 0;word-break:break-all}}
a{{color:#5fd4c0}} li{{margin:4px 0}} summary{{cursor:pointer;color:#5fd4c0;margin:8px 0}}
ol li{{margin:6px 0}}
</style></head><body><div class="wrap">
<div class="top"><div class="logo"></div><div><h1>Local network certificates</h1><div class="muted">Served by LabCert on {host}</div></div></div>
<h2>1. Trust this network's authority</h2>
<p>Install the root certificate once on each device. After that, every certificate issued here is accepted without warnings.</p>
{roots}
<details><summary>How to install it</summary><ol>
<li><b>Windows:</b> open the .crt file &rarr; Install Certificate &rarr; Local Machine &rarr; "Trusted Root Certification Authorities".</li>
<li><b>macOS:</b> open the .pem in Keychain Access &rarr; System &rarr; double-click it &rarr; Trust &rarr; "Always Trust".</li>
<li><b>iPhone / iPad:</b> download the profile &rarr; Settings &rarr; Profile Downloaded &rarr; Install; then Settings &rarr; General &rarr; About &rarr; Certificate Trust Settings &rarr; turn it on.</li>
<li><b>Android:</b> Settings &rarr; Security &rarr; Encryption &amp; credentials &rarr; Install a certificate &rarr; CA certificate.</li>
<li><b>Linux (Debian/Ubuntu):</b> copy the .pem to /usr/local/share/ca-certificates/labcert.crt and run <code>sudo update-ca-certificates</code>.</li>
<li><b>Firefox:</b> Settings &rarr; Privacy &amp; Security &rarr; Certificates &rarr; View Certificates &rarr; Authorities &rarr; Import.</li>
</ol></details>
{secure_note}
{acme}
{enroll}
<h2>Revocation lists</h2><ul>{crls}</ul>
<p class="muted">Health check: <a href="/api/health">/api/health</a></p>
</div></body></html>"#
    )
}
