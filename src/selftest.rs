//! `--selftest`: exercises the authority, exports, enrollment and ACME end to end.
//! `--demo`: fills an empty data folder with sample data (for trying the app out).

use crate::acme::{thumbprint, AcmeState};
use crate::ca::{self, CaSpec, DnSpec, Export, IssueSpec};
use crate::model::*;
use crate::server::Server;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use std::io::{Read, Write};
use std::sync::Arc;

fn spec(name: &str, kt: KeyType, years: u32, depth: Option<u8>, s: &Settings) -> CaSpec {
    CaSpec { name: name.into(), dn: DnSpec::from_settings(name, s), key_type: kt, years, path_len: depth }
}

fn leaf(ca_id: &str, cn: &str, sans: &[&str], profile: Profile, kt: KeyType, days: u32, s: &Settings) -> IssueSpec {
    IssueSpec {
        ca_id: ca_id.into(),
        dn: DnSpec::from_settings(cn, s),
        sans: sans.iter().map(|x| x.to_string()).collect(),
        cn_as_san: true,
        profile,
        key_type: kt,
        days,
        source: Source::Manual,
        requested_by: String::new(),
        notes: String::new(),
    }
}

pub fn seed_demo(shared: &Shared) {
    let mut st = shared.store();
    if !st.authorities.is_empty() {
        return;
    }
    let s = st.settings.clone();
    let root = st.create_root(&spec("Home Lab Root CA", KeyType::EcdsaP384, 10, Some(1), &s), ca::generate_key(KeyType::EcdsaP384).unwrap()).unwrap();
    let inter = st.create_intermediate(&root, &spec("Home Lab Issuing CA", KeyType::EcdsaP256, 5, Some(0), &s), ca::generate_key(KeyType::EcdsaP256).unwrap()).unwrap();
    let items: [(&str, &[&str], Profile, u32); 7] = [
        ("nas.home.lan", &["192.168.1.20", "nas"], Profile::Server, 397),
        ("homeassistant.home.lan", &["192.168.1.30"], Profile::Server, 365),
        ("router.home.lan", &["192.168.1.1"], Profile::Server, 20),
        ("*.k8s.home.lan", &[], Profile::Server, 90),
        ("grafana.home.lan", &[], Profile::Server, 365),
        ("alice@home.lan", &[], Profile::Email, 730),
        ("printer.home.lan", &["192.168.1.45"], Profile::Server, 825),
    ];
    let mut ids = vec![];
    for (cn, sans, pr, days) in items {
        let id = st.issue(leaf(&inter, cn, sans, pr, KeyType::EcdsaP256, days, &s), ca::generate_key(KeyType::EcdsaP256).unwrap()).unwrap();
        ids.push(id);
    }
    let _ = st.revoke(&ids[4], Reason::KeyCompromise);
    st.tokens.push(Token { id: random_id(6), label: "Office laptops".into(), secret: "demo-token".into(), created: now(), profile: Profile::Client, validity_days: 365, ..Default::default() });
    shared.save(&st);
}

fn check(ok: bool, what: &str, fails: &mut u32) {
    println!("{} {what}", if ok { "ok  " } else { "FAIL" });
    if !ok {
        *fails += 1;
    }
}

fn http(addr: &str, method: &str, path: &str, ctype: &str, body: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut s = std::net::TcpStream::connect(addr).expect("connect");
    let req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    s.write_all(req.as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut buf = vec![];
    s.read_to_end(&mut buf).unwrap();
    let pos = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(buf.len());
    let head = String::from_utf8_lossy(&buf[..pos]).to_string();
    let status = head.split_whitespace().nth(1).and_then(|x| x.parse().ok()).unwrap_or(0);
    let headers = head.lines().skip(1).filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_string())).collect();
    (status, headers, buf.get(pos + 4..).unwrap_or(&[]).to_vec())
}

fn hdr(h: &[(String, String)], k: &str) -> String {
    h.iter().find(|(x, _)| x == k).map(|(_, v)| v.clone()).unwrap_or_default()
}

/// Minimal ACME client used to test the service.
struct Client {
    addr: String,
    base: String,
    key: ring::signature::EcdsaKeyPair,
    jwk: serde_json::Value,
    kid: Option<String>,
    nonce: String,
}

impl Client {
    fn new(addr: &str) -> Client {
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        let pk = key.public_key().as_ref();
        let jwk = serde_json::json!({"crv": "P-256", "kty": "EC", "x": URL_SAFE_NO_PAD.encode(&pk[1..33]), "y": URL_SAFE_NO_PAD.encode(&pk[33..65])});
        Client { addr: addr.into(), base: format!("http://{addr}"), key, jwk, kid: None, nonce: String::new() }
    }
    fn post(&mut self, url: &str, payload: Option<serde_json::Value>) -> (u16, Vec<(String, String)>, Vec<u8>) {
        let mut prot = serde_json::json!({"alg": "ES256", "nonce": self.nonce, "url": url});
        match &self.kid {
            Some(k) => prot["kid"] = serde_json::json!(k),
            None => prot["jwk"] = self.jwk.clone(),
        }
        let pb = URL_SAFE_NO_PAD.encode(prot.to_string());
        let pl = payload.map(|p| URL_SAFE_NO_PAD.encode(p.to_string())).unwrap_or_default();
        let sig = self.key.sign(&ring::rand::SystemRandom::new(), format!("{pb}.{pl}").as_bytes()).unwrap();
        let body = serde_json::json!({"protected": pb, "payload": pl, "signature": URL_SAFE_NO_PAD.encode(sig.as_ref())});
        let path = url.trim_start_matches(&self.base).to_string();
        let r = http(&self.addr, "POST", &path, "application/jose+json", body.to_string().as_bytes());
        self.nonce = hdr(&r.1, "replay-nonce");
        r
    }
}

pub fn run(dir: &std::path::Path) -> i32 {
    let _ = std::fs::remove_dir_all(dir);
    let path = dir.join("labcert.json");
    let shared = Arc::new(Shared::new(path.clone()));
    let mut f = 0u32;
    let fails = &mut f;
    let s = Settings::default();
    // --- authorities
    let (root, inter) = {
        let mut st = shared.store();
        st.settings.public_host = "127.0.0.1".into();
        st.settings.server.http_port = 18480;
        st.settings.server.https_port = 18443;
        st.settings.server.acme_auto_approve = true;
        let root = st.create_root(&spec("Test Root", KeyType::EcdsaP384, 10, Some(1), &s), ca::generate_key(KeyType::EcdsaP384).unwrap());
        check(root.is_ok(), "create root authority", fails);
        let root = root.unwrap();
        let inter = st.create_intermediate(&root, &spec("Test Issuing", KeyType::Rsa2048, 5, Some(0), &s), ca::generate_key(KeyType::Rsa2048).unwrap());
        check(inter.is_ok(), &format!("create RSA intermediate {:?}", inter.as_ref().err()), fails);
        (root, inter.unwrap())
    };
    let mut st = shared.store();
    let d = ca::cert_details(&st.authority(&inter).unwrap().cert_pem).unwrap();
    check(d.is_ca && !d.self_signed, "intermediate is an authority signed by the root", fails);
    // --- issue all key types
    let mut leaf_ids = vec![];
    for kt in KeyType::ALL {
        let r = st.issue(leaf(&inter, "web.test.lan", &["192.168.1.5", "*.test.lan"], Profile::Server, kt, 365, &s), ca::generate_key(kt).unwrap());
        check(r.is_ok(), &format!("issue {} certificate {:?}", kt.label(), r.as_ref().err()), fails);
        if let Ok(id) = r {
            leaf_ids.push(id);
        }
    }
    let c = st.cert(&leaf_ids[0]).unwrap().clone();
    let d = ca::cert_details(&c.cert_pem).unwrap();
    check(d.sans.contains(&"web.test.lan".to_string()) && d.sans.contains(&"192.168.1.5".to_string()), "names in certificate", fails);
    check(d.ext_key_usage.contains("TLS server"), "server purpose set", fails);
    check(!d.crl_urls.is_empty(), "revocation list address embedded", fails);
    // verify chain signatures
    {
        use x509_parser::prelude::*;
        let ld = ca::pem_to_der(&c.cert_pem).unwrap();
        let idr = ca::pem_to_der(&st.authority(&inter).unwrap().cert_pem).unwrap();
        let rd = ca::pem_to_der(&st.authority(&root).unwrap().cert_pem).unwrap();
        let (_, l) = parse_x509_certificate(&ld).unwrap();
        let (_, i) = parse_x509_certificate(&idr).unwrap();
        let (_, r) = parse_x509_certificate(&rd).unwrap();
        check(l.verify_signature(Some(i.public_key())).is_ok(), "leaf signature verifies against intermediate", fails);
        check(i.verify_signature(Some(r.public_key())).is_ok(), "intermediate signature verifies against root", fails);
        check(l.issuer() == i.subject(), "leaf issuer matches intermediate subject", fails);
    }
    // exports
    for k in [Export::CertPem, Export::CertDer, Export::KeyPem, Export::ChainPem, Export::FullChainPem, Export::BundlePem, Export::Pfx] {
        let r = st.export_cert(&leaf_ids[0], k, "secret");
        check(r.as_ref().map(|b| !b.is_empty()).unwrap_or(false), &format!("export {}", k.label()), fails);
    }
    let pfx = st.export_cert(&leaf_ids[0], Export::Pfx, "secret").unwrap();
    let parsed = p12::PFX::parse(&pfx).ok().and_then(|p| p.cert_x509_bags("secret").ok());
    check(parsed.map(|b| !b.is_empty()).unwrap_or(false), "PFX opens with its password", fails);
    let _ = std::fs::create_dir_all(dir);
    let _ = std::fs::write(dir.join("leaf.pfx"), &pfx);
    let _ = std::fs::write(dir.join("leaf.fullchain.pem"), st.export_cert(&leaf_ids[0], Export::ChainPem, "").unwrap());
    let _ = std::fs::write(dir.join("leaf.key"), st.export_cert(&leaf_ids[0], Export::KeyPem, "").unwrap());
    let _ = std::fs::write(dir.join("root.pem"), &st.authority(&root).unwrap().cert_pem);
    let _ = std::fs::write(dir.join("inter.pem"), &st.authority(&inter).unwrap().cert_pem);
    // renew + revoke + CRL
    let renewed = st.renew(&leaf_ids[0], Some(ca::generate_key(KeyType::EcdsaP256).unwrap()), None, true);
    check(renewed.is_ok(), "renew with new key and supersede", fails);
    let renewed2 = st.renew(&leaf_ids[1], None, Some(30), false);
    check(renewed2.is_ok(), "renew keeping the key", fails);
    check(st.revoke(&leaf_ids[2], Reason::CertificateHold).is_ok(), "put certificate on hold", fails);
    check(st.release_hold(&leaf_ids[2]).is_ok(), "release hold", fails);
    check(st.revoke(&leaf_ids[3], Reason::KeyCompromise).is_ok(), "revoke certificate", fails);
    let crl = st.authority(&inter).unwrap().crl_pem.clone().unwrap_or_default();
    let sum = ca::crl_summary(&crl);
    check(sum.as_ref().map(|s| s.entries == 2).unwrap_or(false), &format!("revocation list has 2 entries ({:?})", sum.as_ref().map(|s| s.entries).ok()), fails);
    {
        use x509_parser::prelude::*;
        let der = ca::pem_to_der(&crl).unwrap();
        let (_, c) = x509_parser::revocation_list::CertificateRevocationList::from_der(&der).unwrap();
        let idr = ca::pem_to_der(&st.authority(&inter).unwrap().cert_pem).unwrap();
        let (_, i) = parse_x509_certificate(&idr).unwrap();
        check(c.verify_signature(i.public_key()).is_ok(), "revocation list signature verifies", fails);
    }
    let _ = std::fs::write(dir.join("inter.crl.pem"), &crl);
    // CSR signing (generated with rcgen, includes extra extensions)
    let csr_key = rcgen::KeyPair::generate().unwrap();
    let mut cp = rcgen::CertificateParams::new(vec!["device.test.lan".to_string()]).unwrap();
    cp.distinguished_name.push(rcgen::DnType::OrganizationName, "Device Co");
    cp.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    let csr = cp.serialize_request(&csr_key).unwrap();
    let info = ca::parse_csr(csr.pem().unwrap().as_bytes());
    check(info.is_ok(), &format!("read signing request {:?}", info.as_ref().err()), fails);
    let info = info.unwrap();
    let r = st.sign_csr(&info, &inter, Profile::ServerClient, 90, &["10.0.0.9".into()], true, Source::Csr, "test");
    check(r.is_ok(), "sign request", fails);
    let d = ca::cert_details(&st.cert(&r.unwrap()).unwrap().cert_pem).unwrap();
    check(d.sans.contains(&"10.0.0.9".to_string()) && d.subject.contains("Device Co"), "request names and subject kept", fails);
    // import
    let rk = st.authority(&root).unwrap().key_pem.clone();
    let rc = st.authority(&root).unwrap().cert_pem.clone();
    check(st.import_authority("dup", &rc, &rk).is_err(), "duplicate import refused", fails);
    // token
    st.tokens.push(Token { id: "t1".into(), label: "auto".into(), secret: "tok-auto".into(), auto_approve: true, profile: Profile::Server, validity_days: 30, created: now(), ..Default::default() });
    st.tokens.push(Token { id: "t2".into(), label: "manual".into(), secret: "tok-manual".into(), auto_approve: false, profile: Profile::Server, validity_days: 30, created: now(), ..Default::default() });
    shared.save(&st);
    drop(st);
    // reload from disk
    let st2 = Store::load(&path);
    check(st2.authorities.len() == 2 && st2.certs.len() >= 9, "data saved and reloaded", fails);

    // --- network service
    let acme = Arc::new(AcmeState::default());
    let server = Server::start(shared.clone(), acme);
    check(server.is_ok(), &format!("start network service {:?}", server.as_ref().err()), fails);
    let addr = "127.0.0.1:18480";
    let (code, _, body) = http(addr, "GET", "/", "text/plain", b"");
    check(code == 200 && String::from_utf8_lossy(&body).contains("Test Root"), "setup page", fails);
    let (code, _, body) = http(addr, "GET", "/ca.crt", "text/plain", b"");
    check(code == 200 && ca::cert_details_der(&body).map(|d| d.self_signed).unwrap_or(false), "root download", fails);
    let (code, _, _) = http(addr, "GET", &format!("/crl/{inter}.crl"), "text/plain", b"");
    check(code == 200, "revocation list download", fails);
    let (code, _, _) = http(addr, "GET", "/ca.mobileconfig", "text/plain", b"");
    check(code == 200, "iPhone profile", fails);
    // enrollment
    let k2 = rcgen::KeyPair::generate().unwrap();
    let csr2 = rcgen::CertificateParams::new(vec!["enrolled.test.lan".to_string()]).unwrap().serialize_request(&k2).unwrap().pem().unwrap();
    let (code, _, body) = http(addr, "POST", "/api/enroll?token=tok-auto", "application/pkcs10", csr2.as_bytes());
    check(code == 200 && String::from_utf8_lossy(&body).contains("BEGIN CERTIFICATE"), "enrollment with auto token", fails);
    let (code, _, body) = http(addr, "POST", "/api/enroll?token=tok-manual", "application/pkcs10", csr2.as_bytes());
    check(code == 202, "enrollment waiting for approval", fails);
    let poll: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    let pid = poll["id"].as_str().unwrap_or("").to_string();
    let (code, _, _) = http(addr, "GET", &format!("/api/request/{pid}"), "text/plain", b"");
    check(code == 202, "poll pending request", fails);
    let (code, _, _) = http(addr, "POST", "/api/enroll?token=wrong", "application/pkcs10", csr2.as_bytes());
    check(code == 401, "unknown token refused", fails);
    // ACME
    let (code, h, body) = http(addr, "GET", "/acme/directory", "text/plain", b"");
    let dir_json: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    check(code == 200 && dir_json["newOrder"].is_string(), "ACME directory", fails);
    let _ = h;
    let mut cl = Client::new(addr);
    let (_, h, _) = http(addr, "HEAD", "/acme/new-nonce", "text/plain", b"");
    cl.nonce = hdr(&h, "replay-nonce");
    let (code, h, _) = cl.post(dir_json["newAccount"].as_str().unwrap_or(""), Some(serde_json::json!({"termsOfServiceAgreed": true, "contact": ["mailto:test@test.lan"]})));
    check(code == 201, "ACME new account", fails);
    cl.kid = Some(hdr(&h, "location"));
    let (code, h, body) = cl.post(dir_json["newOrder"].as_str().unwrap_or(""), Some(serde_json::json!({"identifiers": [{"type": "dns", "value": "acme.test.lan"}, {"type": "ip", "value": "192.168.1.77"}]})));
    check(code == 201, "ACME new order", fails);
    let order_url = hdr(&h, "location");
    let order: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    for a in order["authorizations"].as_array().cloned().unwrap_or_default() {
        let (_, _, b) = cl.post(a.as_str().unwrap_or(""), None);
        let az: serde_json::Value = serde_json::from_slice(&b).unwrap_or_default();
        let ch = az["challenges"][0]["url"].as_str().unwrap_or("").to_string();
        let (code, _, _) = cl.post(&ch, Some(serde_json::json!({})));
        check(code == 200, "ACME challenge accepted (lab mode)", fails);
    }
    let (_, _, b) = cl.post(&order_url, None);
    let o: serde_json::Value = serde_json::from_slice(&b).unwrap_or_default();
    check(o["status"] == "ready", &format!("ACME order ready ({})", o["status"]), fails);
    let k3 = rcgen::KeyPair::generate().unwrap();
    let mut p3 = rcgen::CertificateParams::new(vec!["acme.test.lan".to_string(), "192.168.1.77".to_string()]).unwrap();
    p3.distinguished_name = rcgen::DistinguishedName::new();
    let csr3 = p3.serialize_request(&k3).unwrap();
    let (code, _, b) = cl.post(order["finalize"].as_str().unwrap_or(""), Some(serde_json::json!({"csr": URL_SAFE_NO_PAD.encode(csr3.der())})));
    let o: serde_json::Value = serde_json::from_slice(&b).unwrap_or_default();
    check(code == 200 && o["status"] == "valid", &format!("ACME finalize ({code} {})", String::from_utf8_lossy(&b).chars().take(200).collect::<String>()), fails);
    let (code, _, b) = cl.post(o["certificate"].as_str().unwrap_or(""), None);
    let chain = String::from_utf8_lossy(&b).to_string();
    check(code == 200 && chain.matches("BEGIN CERTIFICATE").count() == 2, "ACME certificate download with chain", fails);
    let leaf_der = ca::pem_to_der(&chain).unwrap_or_default();
    let (code, _, _) = cl.post(dir_json["revokeCert"].as_str().unwrap_or(""), Some(serde_json::json!({"certificate": URL_SAFE_NO_PAD.encode(&leaf_der), "reason": 4})));
    check(code == 200, "ACME revoke", fails);
    check(thumbprint(&cl.jwk).is_ok(), "JWK thumbprint", fails);
    // bad nonce rejected
    cl.nonce = "bogus".into();
    let (code, _, b) = cl.post(&order_url, None);
    check(code == 400 && String::from_utf8_lossy(&b).contains("badNonce"), "reused/unknown nonce refused", fails);
    // TLS listener answers with our certificate
    let tls_reply = (|| -> Result<String, String> {
        let root_der = ca::pem_to_der(&shared.store().authority(&root).unwrap().cert_pem)?;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(rustls::pki_types::CertificateDer::from(root_der)).map_err(|e| e.to_string())?;
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from("127.0.0.1").map_err(|e| e.to_string())?;
        let conn = rustls::ClientConnection::new(Arc::new(cfg), name).map_err(|e| e.to_string())?;
        let sock = std::net::TcpStream::connect("127.0.0.1:18443").map_err(|e| e.to_string())?;
        let mut tls = rustls::StreamOwned::new(conn, sock);
        tls.write_all(b"GET /api/health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").map_err(|e| e.to_string())?;
        let mut buf = vec![];
        let _ = tls.read_to_end(&mut buf);
        Ok(String::from_utf8_lossy(&buf).to_string())
    })();
    check(tls_reply.as_ref().map(|r| r.contains("\"ok\"")).unwrap_or(false), &format!("secure address works and is trusted via the root {:?}", tls_reply.as_ref().err()), fails);
    if let Ok(srv) = server {
        srv.stop(&shared);
    }
    println!("\n{} failures. Files for manual checks are in {}", f, dir.display());
    if f == 0 { 0 } else { 1 }
}
