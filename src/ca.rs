//! Certificate authority operations: keys, authorities, issuing, CSR signing, renewal,
//! revocation lists, exports and certificate inspection.

use crate::model::*;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateRevocationListParams,
    CrlDistributionPoint, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PublicKeyData, RevocationReason, RevokedCertParams, SanType, SerialNumber,
    SignatureAlgorithm,
};
use std::net::IpAddr;
use x509_parser::prelude::*;

fn e<E: std::fmt::Display>(x: E) -> String {
    x.to_string()
}

fn ts(t: i64) -> ::time::OffsetDateTime {
    ::time::OffsetDateTime::from_unix_timestamp(t).unwrap_or(::time::OffsetDateTime::UNIX_EPOCH)
}

pub fn sig_alg(kt: KeyType) -> &'static SignatureAlgorithm {
    match kt {
        KeyType::EcdsaP256 => &rcgen::PKCS_ECDSA_P256_SHA256,
        KeyType::EcdsaP384 => &rcgen::PKCS_ECDSA_P384_SHA384,
        KeyType::Ed25519 => &rcgen::PKCS_ED25519,
        _ => &rcgen::PKCS_RSA_SHA256,
    }
}

/// Create a new private key. RSA keys can take a few seconds.
pub fn generate_key(kt: KeyType) -> Res<KeyPair> {
    use rsa::pkcs8::EncodePrivateKey;
    let bits = match kt {
        KeyType::Rsa2048 => 2048,
        KeyType::Rsa3072 => 3072,
        KeyType::Rsa4096 => 4096,
        _ => return KeyPair::generate_for(sig_alg(kt)).map_err(e),
    };
    let key = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, bits).map_err(e)?;
    let pem = key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).map_err(e)?;
    KeyPair::from_pkcs8_pem_and_sign_algo(&pem, &rcgen::PKCS_RSA_SHA256).map_err(e)
}

pub fn load_key(pem_str: &str, kt: KeyType) -> Res<KeyPair> {
    KeyPair::from_pem_and_sign_algo(pem_str, sig_alg(kt)).map_err(e)
}

/// Accept PKCS#8 keys and PKCS#1 RSA keys; returns the key as PKCS#8 PEM.
pub fn normalize_key_pem(input: &str) -> Res<String> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::EncodePrivateKey;
    let p = ::pem::parse(input.trim()).map_err(|_| "The private key is not valid PEM text.".to_string())?;
    match p.tag() {
        "PRIVATE KEY" => Ok(input.trim().to_string() + "\n"),
        "RSA PRIVATE KEY" => {
            let k = rsa::RsaPrivateKey::from_pkcs1_der(p.contents()).map_err(e)?;
            Ok(k.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).map_err(e)?.to_string())
        }
        "ENCRYPTED PRIVATE KEY" => Err("The key is password protected. Remove the password first (openssl pkcs8 -in key.pem -out plain.pem).".into()),
        "EC PRIVATE KEY" => Err("This is an older EC key format. Convert it first: openssl pkcs8 -topk8 -nocrypt -in key.pem -out key8.pem".into()),
        t => Err(format!("Unsupported key type \"{t}\".")),
    }
}

pub fn new_serial() -> (SerialNumber, String) {
    let mut b = random_bytes(16);
    b[0] = (b[0] & 0x7f) | 0x10;
    (SerialNumber::from_slice(&b), hex(&b))
}

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..s.len() / 2).filter_map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()).collect()
}

pub fn pem_to_der(pem_str: &str) -> Res<Vec<u8>> {
    ::pem::parse(pem_str.trim()).map(|p| p.contents().to_vec()).map_err(e)
}

pub fn der_to_pem(tag: &str, der: &[u8]) -> String {
    ::pem::encode_config(
        &::pem::Pem::new(tag, der.to_vec()),
        ::pem::EncodeConfig::new().set_line_ending(::pem::LineEnding::LF),
    )
}

pub fn fingerprint(der: &[u8], sha1: bool) -> String {
    let alg = if sha1 { &ring::digest::SHA1_FOR_LEGACY_USE_ONLY } else { &ring::digest::SHA256 };
    hex_colon(ring::digest::digest(alg, der).as_ref())
}

pub struct DnSpec {
    pub common_name: String,
    pub organization: String,
    pub org_unit: String,
    pub locality: String,
    pub state: String,
    pub country: String,
}

impl DnSpec {
    pub fn from_settings(cn: &str, s: &Settings) -> DnSpec {
        DnSpec {
            common_name: cn.into(),
            organization: s.organization.clone(),
            org_unit: s.org_unit.clone(),
            locality: s.locality.clone(),
            state: s.state.clone(),
            country: s.country.clone(),
        }
    }
    fn build(&self) -> DistinguishedName {
        let mut dn = DistinguishedName::new();
        let c = self.country.trim();
        if c.len() == 2 {
            dn.push(DnType::CountryName, rcgen::DnValue::PrintableString(c.to_uppercase().try_into().unwrap_or_else(|_| "XX".try_into().unwrap())));
        }
        for (t, v) in [
            (DnType::StateOrProvinceName, &self.state),
            (DnType::LocalityName, &self.locality),
            (DnType::OrganizationName, &self.organization),
            (DnType::OrganizationalUnitName, &self.org_unit),
        ] {
            if !v.trim().is_empty() {
                dn.push(t, v.trim());
            }
        }
        if !self.common_name.trim().is_empty() {
            dn.push(DnType::CommonName, self.common_name.trim());
        }
        dn
    }
}

// ---------------------------------------------------------------------------
// Names

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NameKind {
    Dns,
    Ip,
    Email,
    Uri,
}

pub fn classify_name(s: &str) -> Res<NameKind> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty name".into());
    }
    if s.parse::<IpAddr>().is_ok() {
        return Ok(NameKind::Ip);
    }
    if s.contains("://") || s.starts_with("urn:") || s.starts_with("spiffe:") {
        return Ok(NameKind::Uri);
    }
    if s.contains('@') {
        return Ok(NameKind::Email);
    }
    let labels: Vec<&str> = s.trim_end_matches('.').split('.').collect();
    for (i, l) in labels.iter().enumerate() {
        if *l == "*" && i == 0 && labels.len() > 1 {
            continue;
        }
        if l.is_empty() || l.len() > 63 {
            return Err(format!("\"{s}\" is not a valid host name"));
        }
        if !l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') || l.starts_with('-') || l.ends_with('-') {
            return Err(format!("\"{s}\" is not a valid host name"));
        }
    }
    Ok(NameKind::Dns)
}

fn san_of(s: &str) -> Res<SanType> {
    let s = s.trim();
    Ok(match classify_name(s)? {
        NameKind::Ip => SanType::IpAddress(s.parse().map_err(e)?),
        NameKind::Email => SanType::Rfc822Name(s.try_into().map_err(e)?),
        NameKind::Uri => SanType::URI(s.try_into().map_err(e)?),
        NameKind::Dns => SanType::DnsName(s.to_lowercase().trim_end_matches('.').try_into().map_err(e)?),
    })
}

/// Split free text (lines, commas, spaces) into unique names.
pub fn split_names(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for n in text.split(|c: char| c == '\n' || c == ',' || c == ';' || c.is_whitespace()) {
        let n = n.trim();
        if !n.is_empty() && !out.iter().any(|x| x.eq_ignore_ascii_case(n)) {
            out.push(n.to_string());
        }
    }
    out
}

pub fn lan_ip() -> Option<IpAddr> {
    // No packet is sent: connecting a UDP socket only picks the outgoing interface.
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:80").ok()?;
    s.local_addr().ok().map(|a| a.ip()).filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
}

pub fn host_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "localhost".into())
        .to_lowercase()
}

/// Names this computer is reachable under on the local network.
pub fn local_names(public_host: &str) -> Vec<String> {
    let mut v = vec![];
    if !public_host.trim().is_empty() {
        v.push(public_host.trim().to_lowercase());
    }
    let h = host_name();
    if h != "localhost" {
        v.push(h.clone());
        v.push(format!("{h}.local"));
        v.push(format!("{h}.lan"));
    }
    v.push("localhost".into());
    if let Some(ip) = lan_ip() {
        v.push(ip.to_string());
    }
    v.push("127.0.0.1".into());
    let mut out: Vec<String> = vec![];
    for n in v {
        if !out.contains(&n) {
            out.push(n);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Public keys taken from requests or existing certificates

pub struct ForeignKey {
    raw: Vec<u8>,
    alg: &'static SignatureAlgorithm,
    pub key_type: KeyType,
    pub desc: String,
}

impl PublicKeyData for ForeignKey {
    fn der_bytes(&self) -> &[u8] {
        &self.raw
    }
    fn algorithm(&self) -> &SignatureAlgorithm {
        self.alg
    }
}

fn foreign_key(spki: &x509_parser::x509::SubjectPublicKeyInfo) -> Res<ForeignKey> {
    let oid = spki.algorithm.algorithm.to_id_string();
    let raw = spki.subject_public_key.data.to_vec();
    match oid.as_str() {
        "1.2.840.113549.1.1.1" => {
            let bits = match spki.parsed() {
                Ok(x509_parser::public_key::PublicKey::RSA(r)) => r.key_size(),
                _ => 2048,
            };
            let kt = if bits >= 4000 { KeyType::Rsa4096 } else if bits >= 3000 { KeyType::Rsa3072 } else { KeyType::Rsa2048 };
            Ok(ForeignKey { raw, alg: &rcgen::PKCS_RSA_SHA256, key_type: kt, desc: format!("RSA {bits}") })
        }
        "1.2.840.10045.2.1" => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .map(|o| o.to_id_string())
                .unwrap_or_default();
            match curve.as_str() {
                "1.2.840.10045.3.1.7" => Ok(ForeignKey { raw, alg: &rcgen::PKCS_ECDSA_P256_SHA256, key_type: KeyType::EcdsaP256, desc: "ECDSA P-256".into() }),
                "1.3.132.0.34" => Ok(ForeignKey { raw, alg: &rcgen::PKCS_ECDSA_P384_SHA384, key_type: KeyType::EcdsaP384, desc: "ECDSA P-384".into() }),
                _ => Err("Only the P-256 and P-384 elliptic curves are supported.".into()),
            }
        }
        "1.3.101.112" => Ok(ForeignKey { raw, alg: &rcgen::PKCS_ED25519, key_type: KeyType::Ed25519, desc: "Ed25519".into() }),
        _ => Err(format!("Unsupported public key algorithm ({oid}).")),
    }
}

fn name_to_dn(name: &X509Name) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    for attr in name.iter_attributes() {
        let Some(oid) = attr.attr_type().iter() else { continue };
        let oid: Vec<u64> = oid.collect();
        if let Ok(v) = attr.as_str() {
            dn.push(DnType::from_oid(&oid), v);
        }
    }
    dn
}

fn general_name_str(g: &GeneralName) -> Option<String> {
    match g {
        GeneralName::DNSName(s) => Some(s.to_string()),
        GeneralName::RFC822Name(s) => Some(s.to_string()),
        GeneralName::URI(s) => Some(s.to_string()),
        GeneralName::IPAddress(b) => match b.len() {
            4 => Some(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string()),
            16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(b);
                Some(std::net::Ipv6Addr::from(a).to_string())
            }
            _ => None,
        },
        _ => None,
    }
}

pub struct CsrInfo {
    pub subject: String,
    pub common_name: String,
    pub sans: Vec<String>,
    pub key: ForeignKey,
    dn: DistinguishedName,
    pub pem: String,
}

/// Read a certificate signing request (PEM or DER) and check its signature.
pub fn parse_csr(input: &[u8]) -> Res<CsrInfo> {
    let der: Vec<u8> = {
        let text = String::from_utf8_lossy(input);
        if text.contains("-----BEGIN") {
            let start = text.find("-----BEGIN").unwrap_or(0);
            let p = ::pem::parse(&text[start..]).map_err(|_| "The request is not valid PEM text.".to_string())?;
            if !p.tag().contains("CERTIFICATE REQUEST") {
                return Err(format!("Expected a CERTIFICATE REQUEST, found \"{}\".", p.tag()));
            }
            p.contents().to_vec()
        } else {
            input.to_vec()
        }
    };
    let (_, csr) = X509CertificationRequest::from_der(&der).map_err(|_| "This is not a readable certificate signing request.".to_string())?;
    csr.verify_signature().map_err(|_| "The request's signature does not match its key.".to_string())?;
    let info = &csr.certification_request_info;
    let key = foreign_key(&info.subject_pki)?;
    let mut sans = vec![];
    if let Some(exts) = csr.requested_extensions() {
        for ext in exts {
            if let ParsedExtension::SubjectAlternativeName(san) = ext {
                for g in &san.general_names {
                    if let Some(s) = general_name_str(g) {
                        sans.push(s);
                    }
                }
            }
        }
    }
    let common_name = info
        .subject
        .iter_common_name()
        .next()
        .and_then(|c| c.as_str().ok())
        .map(String::from)
        .unwrap_or_default();
    Ok(CsrInfo {
        subject: info.subject.to_string(),
        common_name,
        sans,
        key,
        dn: name_to_dn(&info.subject),
        pem: der_to_pem("CERTIFICATE REQUEST", &der),
    })
}

// ---------------------------------------------------------------------------
// Inspecting certificates

#[derive(Clone, Default)]
pub struct CertDetails {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: i64,
    pub not_after: i64,
    pub sig_alg: String,
    pub key_desc: String,
    pub sans: Vec<String>,
    pub key_usage: String,
    pub ext_key_usage: String,
    pub basic: String,
    pub sha256: String,
    pub sha1: String,
    pub ski: String,
    pub aki: String,
    pub crl_urls: Vec<String>,
    pub self_signed: bool,
    pub is_ca: bool,
    pub common_name: String,
}

fn sig_name(oid: &str) -> String {
    match oid {
        "1.2.840.10045.4.3.2" => "ECDSA with SHA-256",
        "1.2.840.10045.4.3.3" => "ECDSA with SHA-384",
        "1.2.840.10045.4.3.4" => "ECDSA with SHA-512",
        "1.2.840.113549.1.1.11" => "RSA with SHA-256",
        "1.2.840.113549.1.1.12" => "RSA with SHA-384",
        "1.2.840.113549.1.1.13" => "RSA with SHA-512",
        "1.2.840.113549.1.1.5" => "RSA with SHA-1 (weak)",
        "1.2.840.113549.1.1.10" => "RSA-PSS",
        "1.3.101.112" => "Ed25519",
        o => return o.to_string(),
    }
    .to_string()
}

pub fn cert_details_der(der: &[u8]) -> Res<CertDetails> {
    let (_, c) = parse_x509_certificate(der).map_err(|_| "Not a readable certificate".to_string())?;
    let mut d = CertDetails {
        subject: c.subject().to_string(),
        issuer: c.issuer().to_string(),
        serial: hex_colon(c.raw_serial()),
        not_before: c.validity().not_before.timestamp(),
        not_after: c.validity().not_after.timestamp(),
        sig_alg: sig_name(&c.signature_algorithm.algorithm.to_id_string()),
        key_desc: foreign_key(c.public_key()).map(|k| k.desc).unwrap_or_else(|x| x),
        sha256: fingerprint(der, false),
        sha1: fingerprint(der, true),
        self_signed: c.subject() == c.issuer(),
        common_name: c.subject().iter_common_name().next().and_then(|x| x.as_str().ok()).unwrap_or("").to_string(),
        ..Default::default()
    };
    if let Ok(Some(san)) = c.subject_alternative_name() {
        d.sans = san.value.general_names.iter().filter_map(general_name_str).collect();
    }
    if let Ok(Some(ku)) = c.key_usage() {
        let k = ku.value;
        let mut v = vec![];
        if k.digital_signature() { v.push("Digital signature"); }
        if k.non_repudiation() { v.push("Non-repudiation"); }
        if k.key_encipherment() { v.push("Key encipherment"); }
        if k.data_encipherment() { v.push("Data encipherment"); }
        if k.key_agreement() { v.push("Key agreement"); }
        if k.key_cert_sign() { v.push("Certificate signing"); }
        if k.crl_sign() { v.push("CRL signing"); }
        d.key_usage = v.join(", ");
    }
    if let Ok(Some(eku)) = c.extended_key_usage() {
        let k = eku.value;
        let mut v = vec![];
        if k.server_auth { v.push("TLS server"); }
        if k.client_auth { v.push("TLS client"); }
        if k.code_signing { v.push("Code signing"); }
        if k.email_protection { v.push("Email protection"); }
        if k.time_stamping { v.push("Time stamping"); }
        if k.ocsp_signing { v.push("OCSP signing"); }
        if k.any { v.push("Any purpose"); }
        d.ext_key_usage = v.join(", ");
    }
    if let Ok(Some(bc)) = c.basic_constraints() {
        d.is_ca = bc.value.ca;
        d.basic = if bc.value.ca {
            match bc.value.path_len_constraint {
                Some(n) => format!("Authority (may sign {n} level(s) below)"),
                None => "Authority (no depth limit)".into(),
            }
        } else {
            "End entity (not an authority)".into()
        };
    }
    for ext in c.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(k) => d.ski = hex_colon(k.0),
            ParsedExtension::AuthorityKeyIdentifier(a) => {
                if let Some(k) = &a.key_identifier {
                    d.aki = hex_colon(k.0);
                }
            }
            ParsedExtension::CRLDistributionPoints(points) => {
                for p in points.iter() {
                    if let Some(x509_parser::extensions::DistributionPointName::FullName(names)) = &p.distribution_point {
                        d.crl_urls.extend(names.iter().filter_map(general_name_str));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(d)
}

pub fn cert_details(pem_str: &str) -> Res<CertDetails> {
    cert_details_der(&pem_to_der(pem_str)?)
}

pub struct CrlSummary {
    pub entries: usize,
    pub this_update: i64,
    pub next_update: Option<i64>,
}

pub fn crl_summary(pem_str: &str) -> Res<CrlSummary> {
    let der = pem_to_der(pem_str)?;
    let (_, crl) = x509_parser::revocation_list::CertificateRevocationList::from_der(&der).map_err(e)?;
    Ok(CrlSummary {
        entries: crl.iter_revoked_certificates().count(),
        this_update: crl.last_update().timestamp(),
        next_update: crl.next_update().map(|t| t.timestamp()),
    })
}

// ---------------------------------------------------------------------------
// Store operations

pub struct CaSpec {
    pub name: String,
    pub dn: DnSpec,
    pub key_type: KeyType,
    pub years: u32,
    pub path_len: Option<u8>,
}

pub struct IssueSpec {
    pub ca_id: String,
    pub dn: DnSpec,
    pub sans: Vec<String>,
    pub cn_as_san: bool,
    pub profile: Profile,
    pub key_type: KeyType,
    pub days: u32,
    pub source: Source,
    pub requested_by: String,
    pub notes: String,
}

fn issuer_of(a: &Authority) -> Res<(Certificate, KeyPair)> {
    let key = load_key(&a.key_pem, a.key_type).map_err(|x| format!("Could not load the authority's key: {x}"))?;
    let params = CertificateParams::from_ca_cert_pem(&a.cert_pem).map_err(|x| format!("Could not read the authority's certificate: {x}"))?;
    let cert = params.self_signed(&key).map_err(e)?;
    Ok((cert, key))
}

fn profile_usages(p: Profile, rsa: bool) -> (Vec<KeyUsagePurpose>, Vec<ExtendedKeyUsagePurpose>) {
    use ExtendedKeyUsagePurpose as X;
    use KeyUsagePurpose as K;
    let mut ku = vec![K::DigitalSignature];
    let eku = match p {
        Profile::Server => {
            if rsa { ku.push(K::KeyEncipherment); }
            vec![X::ServerAuth]
        }
        Profile::Client => vec![X::ClientAuth],
        Profile::ServerClient => {
            if rsa { ku.push(K::KeyEncipherment); }
            vec![X::ServerAuth, X::ClientAuth]
        }
        Profile::CodeSigning => vec![X::CodeSigning],
        Profile::Email => {
            ku.push(K::ContentCommitment);
            if rsa { ku.push(K::KeyEncipherment); }
            vec![X::EmailProtection]
        }
    };
    (ku, eku)
}

pub fn key_type_of_pair(k: &KeyPair, fallback: KeyType) -> KeyType {
    let alg = k.algorithm();
    if alg == &rcgen::PKCS_ECDSA_P256_SHA256 {
        KeyType::EcdsaP256
    } else if alg == &rcgen::PKCS_ECDSA_P384_SHA384 {
        KeyType::EcdsaP384
    } else if alg == &rcgen::PKCS_ED25519 {
        KeyType::Ed25519
    } else {
        fallback
    }
}

impl Store {
    pub fn cdp_url(&self, ca_id: &str) -> Option<String> {
        let s = &self.settings;
        if !s.include_cdp || s.public_host.trim().is_empty() {
            return None;
        }
        Some(format!("http://{}:{}/crl/{}.crl", s.public_host.trim(), s.server.http_port, ca_id))
    }

    fn record_authority(&mut self, name: &str, parent: Option<String>, cert_pem: String, key_pem: String, key_type: KeyType, path_len: Option<u8>, imported: bool) -> Res<String> {
        let d = cert_details(&cert_pem)?;
        let id = random_id(6);
        let a = Authority {
            id: id.clone(),
            name: name.to_string(),
            parent,
            cert_pem,
            key_pem,
            key_type,
            subject: d.subject.clone(),
            serial: d.serial.replace(':', "").to_lowercase(),
            not_before: d.not_before,
            not_after: d.not_after,
            created: now(),
            imported,
            self_signed: d.self_signed,
            path_len,
            fingerprint: d.sha256.clone(),
            ..Default::default()
        };
        self.authorities.push(a);
        if self.settings.default_ca.is_none() {
            self.settings.default_ca = Some(id.clone());
        }
        let _ = self.regen_crl(&id);
        Ok(id)
    }

    fn ca_params(&self, spec: &CaSpec) -> CertificateParams {
        let t = now();
        let mut p = CertificateParams::default();
        p.distinguished_name = spec.dn.build();
        p.is_ca = IsCa::Ca(match spec.path_len {
            Some(n) => BasicConstraints::Constrained(n),
            None => BasicConstraints::Unconstrained,
        });
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
        p.not_before = ts(t - 3600);
        p.not_after = ts(t + spec.years.max(1) as i64 * 365 * 86_400 + spec.years as i64 / 4 * 86_400);
        p.serial_number = Some(new_serial().0);
        p
    }

    pub fn create_root(&mut self, spec: &CaSpec, key: KeyPair) -> Res<String> {
        if spec.name.trim().is_empty() {
            return Err("Give the authority a name.".into());
        }
        let p = self.ca_params(spec);
        let cert = p.self_signed(&key).map_err(e)?;
        let id = self.record_authority(spec.name.trim(), None, cert.pem(), key.serialize_pem(), spec.key_type, spec.path_len, false)?;
        self.log(LogKind::Success, "authority", format!("Created root authority \"{}\" ({}, {} years)", spec.name.trim(), spec.key_type.label(), spec.years));
        Ok(id)
    }

    pub fn create_intermediate(&mut self, parent_id: &str, spec: &CaSpec, key: KeyPair) -> Res<String> {
        let parent = self.authority(parent_id).ok_or("The parent authority no longer exists.")?.clone();
        if let Some(0) = parent.path_len {
            return Err(format!("\"{}\" is not allowed to create further authorities (depth limit 0).", parent.name));
        }
        let (pc, pk) = issuer_of(&parent)?;
        let mut p = self.ca_params(spec);
        p.use_authority_key_identifier_extension = true;
        p.not_after = p.not_after.min(ts(parent.not_after));
        if let Some(url) = self.cdp_url(parent_id) {
            p.crl_distribution_points = vec![CrlDistributionPoint { uris: vec![url] }];
        }
        let cert = p.signed_by(&key, &pc, &pk).map_err(e)?;
        let id = self.record_authority(spec.name.trim(), Some(parent_id.to_string()), cert.pem(), key.serialize_pem(), spec.key_type, spec.path_len, false)?;
        // Prefer issuing from the intermediate from now on.
        self.settings.default_ca = Some(id.clone());
        self.log(LogKind::Success, "authority", format!("Created intermediate authority \"{}\" under \"{}\"", spec.name.trim(), parent.name));
        Ok(id)
    }

    pub fn import_authority(&mut self, name: &str, cert_pem: &str, key_pem: &str) -> Res<String> {
        let cert_pem = {
            let t = cert_pem.trim();
            let start = t.find("-----BEGIN CERTIFICATE").ok_or("Paste the authority's certificate (PEM, starting with -----BEGIN CERTIFICATE-----).")?;
            let p = ::pem::parse(&t[start..]).map_err(e)?;
            der_to_pem("CERTIFICATE", p.contents())
        };
        let d = cert_details(&cert_pem)?;
        if !d.is_ca {
            return Err("This certificate is not an authority (it cannot sign other certificates).".into());
        }
        let key_pem = normalize_key_pem(key_pem)?;
        let key = KeyPair::from_pem(&key_pem).map_err(|x| format!("Could not read the private key: {x}"))?;
        let der = pem_to_der(&cert_pem)?;
        let (_, c) = parse_x509_certificate(&der).map_err(e)?;
        if key.public_key_raw() != c.public_key().subject_public_key.data.as_ref() {
            return Err("The private key does not belong to this certificate.".into());
        }
        let fk = foreign_key(c.public_key())?;
        let kt = key_type_of_pair(&key, fk.key_type);
        if self.authorities.iter().any(|a| a.fingerprint == d.sha256) {
            return Err("This authority is already in the app.".into());
        }
        let parent = if d.self_signed {
            None
        } else {
            self.authorities.iter().find(|a| a.subject == d.issuer).map(|a| a.id.clone())
        };
        let name = if name.trim().is_empty() { if d.common_name.is_empty() { "Imported authority".to_string() } else { d.common_name.clone() } } else { name.trim().to_string() };
        let id = self.record_authority(&name, parent, cert_pem, key_pem, kt, None, true)?;
        self.log(LogKind::Success, "authority", format!("Imported authority \"{name}\""));
        Ok(id)
    }

    /// Chain from the given authority upwards: [issuer, its parent, ..., root].
    pub fn ca_chain(&self, ca_id: &str) -> Vec<&Authority> {
        let mut out = vec![];
        let mut cur = self.authority(ca_id);
        while let Some(a) = cur {
            if out.iter().any(|x: &&Authority| x.id == a.id) {
                break;
            }
            out.push(a);
            cur = a.parent.as_deref().and_then(|p| self.authority(p));
        }
        out
    }

    pub fn root_of(&self, ca_id: &str) -> Option<&Authority> {
        self.ca_chain(ca_id).last().copied()
    }

    /// Core signing routine shared by every way of getting a certificate.
    #[allow(clippy::too_many_arguments)]
    fn sign_leaf(&mut self, ca_id: &str, public_key: &impl PublicKeyData, dn: DistinguishedName, common_name: String, sans: Vec<String>, profile: Profile, key_type: KeyType, days: u32, key_pem: Option<String>, source: Source, requested_by: String, notes: String) -> Res<String> {
        let ca = self.authority(ca_id).ok_or("Choose an authority to sign with.")?.clone();
        if ca.revoked.is_some() {
            return Err(format!("\"{}\" has been revoked and can no longer sign.", ca.name));
        }
        if now() > ca.not_after {
            return Err(format!("\"{}\" has expired.", ca.name));
        }
        if sans.is_empty() && common_name.trim().is_empty() {
            return Err("Add at least one name (host name, IP address or email).".into());
        }
        let mut san_types = vec![];
        for s in &sans {
            san_types.push(san_of(s)?);
        }
        let (ic, ik) = issuer_of(&ca)?;
        let t = now();
        let mut p = CertificateParams::default();
        p.distinguished_name = dn;
        p.subject_alt_names = san_types;
        p.is_ca = IsCa::ExplicitNoCa;
        let (ku, eku) = profile_usages(profile, key_type.is_rsa());
        p.key_usages = ku;
        p.extended_key_usages = eku;
        p.use_authority_key_identifier_extension = true;
        p.not_before = ts(t - 300);
        let end = (t + days.max(1) as i64 * 86_400).min(ca.not_after);
        p.not_after = ts(end);
        let (serial, serial_hex) = new_serial();
        p.serial_number = Some(serial);
        if let Some(url) = self.cdp_url(ca_id) {
            p.crl_distribution_points = vec![CrlDistributionPoint { uris: vec![url] }];
        }
        let cert = p.signed_by(public_key, &ic, &ik).map_err(e)?;
        let id = random_id(8);
        let cn = if common_name.trim().is_empty() { sans.first().cloned().unwrap_or_default() } else { common_name.trim().to_string() };
        self.certs.push(Cert {
            id: id.clone(),
            ca_id: ca_id.to_string(),
            common_name: cn.clone(),
            sans,
            profile,
            key_type,
            serial: serial_hex,
            not_before: t - 300,
            not_after: end,
            cert_pem: cert.pem(),
            key_pem,
            source,
            requested_by,
            created: t,
            fingerprint: fingerprint(cert.der(), false),
            notes,
            ..Default::default()
        });
        self.log(LogKind::Success, "issue", format!("Issued \"{cn}\" ({}, {} days, {}) — signed by \"{}\"", profile.short(), days, source.label().to_lowercase(), ca.name));
        Ok(id)
    }

    pub fn issue(&mut self, spec: IssueSpec, key: KeyPair) -> Res<String> {
        let mut sans = spec.sans.clone();
        let cn = spec.dn.common_name.trim().to_string();
        if spec.cn_as_san && !cn.is_empty() && !sans.iter().any(|s| s.eq_ignore_ascii_case(&cn)) && classify_name(&cn).is_ok() {
            sans.insert(0, cn.clone());
        }
        for s in &sans {
            classify_name(s)?;
        }
        if spec.profile == Profile::Server || spec.profile == Profile::ServerClient {
            if sans.is_empty() {
                return Err("A server certificate needs at least one host name or IP address.".into());
            }
        }
        let kt = key_type_of_pair(&key, spec.key_type);
        let key_pem = key.serialize_pem();
        self.sign_leaf(&spec.ca_id, &key, spec.dn.build(), cn, sans, spec.profile, kt, spec.days, Some(key_pem), spec.source, spec.requested_by, spec.notes)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_csr(&mut self, csr: &CsrInfo, ca_id: &str, profile: Profile, days: u32, extra_sans: &[String], keep_subject: bool, source: Source, requested_by: &str) -> Res<String> {
        let mut sans = csr.sans.clone();
        for s in extra_sans {
            if !sans.iter().any(|x| x.eq_ignore_ascii_case(s)) {
                sans.push(s.clone());
            }
        }
        if sans.is_empty() && !csr.common_name.is_empty() && classify_name(&csr.common_name).is_ok() {
            sans.push(csr.common_name.clone());
        }
        let dn = if keep_subject {
            csr.dn.clone()
        } else {
            let mut d = DistinguishedName::new();
            let cn = if csr.common_name.is_empty() { sans.first().cloned().unwrap_or_default() } else { csr.common_name.clone() };
            if !cn.is_empty() {
                d.push(DnType::CommonName, cn);
            }
            d
        };
        let notes = format!("Request subject: {}", csr.subject);
        self.sign_leaf(ca_id, &csr.key, dn, csr.common_name.clone(), sans, profile, csr.key.key_type, days, None, source, requested_by.to_string(), notes)
    }

    /// Issue a replacement. With `new_key` a fresh key is used; otherwise the existing public key is re-signed.
    pub fn renew(&mut self, id: &str, new_key: Option<KeyPair>, days: Option<u32>, supersede: bool) -> Res<String> {
        let old = self.cert(id).ok_or("Certificate not found.")?.clone();
        let ca_id = if self.authority(&old.ca_id).is_some() { old.ca_id.clone() } else { self.default_ca_id().ok_or("No authority available.")? };
        let der = pem_to_der(&old.cert_pem)?;
        let (_, c) = parse_x509_certificate(&der).map_err(e)?;
        let dn = name_to_dn(c.subject());
        let days = days.unwrap_or_else(|| (((old.not_after - old.not_before) / 86_400) as u32).max(1));
        let new_id = match new_key {
            Some(k) => {
                let kt = key_type_of_pair(&k, old.key_type);
                let pem_k = k.serialize_pem();
                self.sign_leaf(&ca_id, &k, dn, old.common_name.clone(), old.sans.clone(), old.profile, kt, days, Some(pem_k), Source::Renewal, old.requested_by.clone(), format!("Renewal of serial {}", old.serial))?
            }
            None => {
                let fk = foreign_key(c.public_key())?;
                self.sign_leaf(&ca_id, &fk, dn, old.common_name.clone(), old.sans.clone(), old.profile, old.key_type, days, old.key_pem.clone(), Source::Renewal, old.requested_by.clone(), format!("Renewal of serial {} (same key)", old.serial))?
            }
        };
        if let Some(o) = self.cert_mut(id) {
            o.renewed_by = Some(new_id.clone());
        }
        if supersede {
            let _ = self.revoke(id, Reason::Superseded);
        }
        Ok(new_id)
    }

    pub fn revoke(&mut self, id: &str, reason: Reason) -> Res<()> {
        let c = self.cert_mut(id).ok_or("Certificate not found.")?;
        if c.revoked.is_some() && reason != Reason::CertificateHold {
            if c.revoked.as_ref().map(|r| r.reason) != Some(Reason::CertificateHold) {
                return Err("Already revoked.".into());
            }
        }
        c.revoked = Some(Revocation { at: now(), reason });
        let (ca, cn) = (c.ca_id.clone(), c.common_name.clone());
        self.log(LogKind::Warn, "revoke", format!("Revoked \"{cn}\" — {}", reason.label()));
        self.regen_crl(&ca)
    }

    pub fn release_hold(&mut self, id: &str) -> Res<()> {
        let c = self.cert_mut(id).ok_or("Certificate not found.")?;
        if c.revoked.as_ref().map(|r| r.reason) != Some(Reason::CertificateHold) {
            return Err("Only certificates on hold can be released.".into());
        }
        c.revoked = None;
        let (ca, cn) = (c.ca_id.clone(), c.common_name.clone());
        self.log(LogKind::Info, "revoke", format!("Released hold on \"{cn}\""));
        self.regen_crl(&ca)
    }

    pub fn revoke_authority(&mut self, id: &str, reason: Reason) -> Res<()> {
        let a = self.authority_mut(id).ok_or("Authority not found.")?;
        let parent = a.parent.clone().ok_or("A root authority cannot be revoked; remove it from every device's trust instead.")?;
        a.revoked = Some(Revocation { at: now(), reason });
        let name = a.name.clone();
        self.log(LogKind::Warn, "revoke", format!("Revoked authority \"{name}\" — {}", reason.label()));
        self.regen_crl(&parent)
    }

    pub fn regen_crl(&mut self, ca_id: &str) -> Res<()> {
        let a = self.authority(ca_id).ok_or("Authority not found.")?.clone();
        let (ic, ik) = issuer_of(&a)?;
        let t = now();
        let mut revoked: Vec<RevokedCertParams> = vec![];
        let to_reason = |r: Reason| match r {
            Reason::Unspecified => RevocationReason::Unspecified,
            Reason::KeyCompromise => RevocationReason::KeyCompromise,
            Reason::CaCompromise => RevocationReason::CaCompromise,
            Reason::AffiliationChanged => RevocationReason::AffiliationChanged,
            Reason::Superseded => RevocationReason::Superseded,
            Reason::CessationOfOperation => RevocationReason::CessationOfOperation,
            Reason::CertificateHold => RevocationReason::CertificateHold,
            Reason::PrivilegeWithdrawn => RevocationReason::PrivilegeWithdrawn,
        };
        for c in self.certs.iter().filter(|c| c.ca_id == ca_id) {
            if let Some(r) = &c.revoked {
                revoked.push(RevokedCertParams { serial_number: SerialNumber::from_slice(&unhex(&c.serial)), revocation_time: ts(r.at), reason_code: Some(to_reason(r.reason)), invalidity_date: None });
            }
        }
        for c in self.authorities.iter().filter(|x| x.parent.as_deref() == Some(ca_id)) {
            if let Some(r) = &c.revoked {
                revoked.push(RevokedCertParams { serial_number: SerialNumber::from_slice(&unhex(&c.serial)), revocation_time: ts(r.at), reason_code: Some(to_reason(r.reason)), invalidity_date: None });
            }
        }
        let number = a.crl_number + 1;
        let days = self.settings.crl_days.max(1) as i64;
        let params = CertificateRevocationListParams {
            this_update: ts(t - 60),
            next_update: ts(t + days * 86_400),
            crl_number: SerialNumber::from_slice(&number.to_be_bytes()),
            issuing_distribution_point: None,
            revoked_certs: revoked,
            key_identifier_method: ic.params().key_identifier_method.clone(),
        };
        let crl = params.signed_by(&ic, &ik).map_err(e)?;
        let pem_s = crl.pem().map_err(e)?;
        let a = self.authority_mut(ca_id).unwrap();
        a.crl_number = number;
        a.crl_pem = Some(pem_s);
        a.crl_this_update = t - 60;
        a.crl_next_update = t + days * 86_400;
        Ok(())
    }

    /// Refresh revocation lists that are past half their lifetime. Returns true if anything changed.
    pub fn refresh_crls(&mut self) -> bool {
        let t = now();
        let ids: Vec<String> = self
            .authorities
            .iter()
            .filter(|a| a.crl_pem.is_none() || t > a.crl_this_update + (a.crl_next_update - a.crl_this_update) / 2)
            .map(|a| a.id.clone())
            .collect();
        let mut changed = false;
        for id in ids {
            match self.regen_crl(&id) {
                Ok(()) => changed = true,
                Err(x) => {
                    let n = self.ca_name(&id);
                    self.log(LogKind::Error, "crl", format!("Could not refresh the revocation list of \"{n}\": {x}"));
                }
            }
        }
        changed
    }

    pub fn delete_cert(&mut self, id: &str) {
        if let Some(c) = self.cert(id) {
            let cn = c.common_name.clone();
            self.certs.retain(|c| c.id != id);
            self.log(LogKind::Warn, "delete", format!("Deleted certificate \"{cn}\" from the app"));
        }
    }

    /// Removes an authority together with everything it issued (and sub-authorities).
    pub fn delete_authority(&mut self, id: &str) {
        let mut doomed = vec![id.to_string()];
        let mut i = 0;
        while i < doomed.len() {
            let cur = doomed[i].clone();
            for a in &self.authorities {
                if a.parent.as_deref() == Some(cur.as_str()) && !doomed.contains(&a.id) {
                    doomed.push(a.id.clone());
                }
            }
            i += 1;
        }
        let name = self.ca_name(id);
        let before = self.certs.len();
        self.certs.retain(|c| !doomed.contains(&c.ca_id));
        let removed = before - self.certs.len();
        self.authorities.retain(|a| !doomed.contains(&a.id));
        if self.settings.default_ca.as_ref().map(|d| doomed.contains(d)).unwrap_or(false) {
            self.settings.default_ca = None;
        }
        if self.settings.server.acme_ca.as_ref().map(|d| doomed.contains(d)).unwrap_or(false) {
            self.settings.server.acme_ca = None;
        }
        self.log(LogKind::Warn, "delete", format!("Deleted authority \"{name}\" ({} authorities, {removed} certificates removed)", doomed.len()));
    }

    /// Certificate used by the built-in HTTPS listener; reused while still good.
    pub fn ensure_server_cert(&mut self) -> Res<String> {
        let names = local_names(&self.settings.public_host);
        if let Some(id) = self.settings.server.server_cert_id.clone() {
            if let Some(c) = self.cert(&id) {
                let good = c.revoked.is_none() && c.not_after - now() > 14 * 86_400 && c.key_pem.is_some() && names.iter().all(|n| c.sans.contains(n)) && self.authority(&c.ca_id).is_some();
                if good {
                    return Ok(id);
                }
            }
        }
        let ca = self.default_ca_id().ok_or("Create an authority first; the secure (HTTPS) address needs a certificate from it.")?;
        let key = generate_key(KeyType::EcdsaP256)?;
        let spec = IssueSpec {
            ca_id: ca,
            dn: DnSpec::from_settings(&format!("{} LabCert service", host_name()), &self.settings),
            sans: names,
            cn_as_san: false,
            profile: Profile::Server,
            key_type: KeyType::EcdsaP256,
            days: 365,
            source: Source::ServerTls,
            requested_by: "LabCert".into(),
            notes: "Used by the built-in secure web address".into(),
        };
        let id = self.issue(spec, key)?;
        if let Some(old) = self.settings.server.server_cert_id.replace(id.clone()) {
            if let Some(o) = self.cert_mut(&old) {
                o.renewed_by = Some(id.clone());
            }
        }
        Ok(id)
    }

    pub fn chain_pem(&self, ca_id: &str, include_root: bool) -> String {
        self.ca_chain(ca_id)
            .into_iter()
            .filter(|a| include_root || !a.self_signed)
            .map(|a| a.cert_pem.trim().to_string() + "\n")
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Exports

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Export {
    CertPem,
    CertDer,
    KeyPem,
    ChainPem,
    FullChainPem,
    BundlePem,
    Pfx,
}

impl Export {
    pub fn label(self) -> &'static str {
        match self {
            Export::CertPem => "Certificate (.crt, PEM)",
            Export::CertDer => "Certificate (.cer, DER for Windows)",
            Export::KeyPem => "Private key (.key, PEM)",
            Export::ChainPem => "Certificate + intermediates (fullchain.pem)",
            Export::FullChainPem => "Certificate + whole chain incl. root",
            Export::BundlePem => "Key + certificate + chain in one file",
            Export::Pfx => "PKCS#12 / PFX (.pfx, with password)",
        }
    }
    pub fn file_name(self, base: &str) -> String {
        let b = base.replace(['*', '/', '\\', ':', ' '], "_");
        match self {
            Export::CertPem => format!("{b}.crt"),
            Export::CertDer => format!("{b}.cer"),
            Export::KeyPem => format!("{b}.key"),
            Export::ChainPem => format!("{b}.fullchain.pem"),
            Export::FullChainPem => format!("{b}.chain-with-root.pem"),
            Export::BundlePem => format!("{b}.bundle.pem"),
            Export::Pfx => format!("{b}.pfx"),
        }
    }
    pub fn needs_key(self) -> bool {
        matches!(self, Export::KeyPem | Export::BundlePem | Export::Pfx)
    }
}

impl Store {
    pub fn export_cert(&self, id: &str, kind: Export, password: &str) -> Res<Vec<u8>> {
        let c = self.cert(id).ok_or("Certificate not found.")?;
        let leaf = c.cert_pem.trim().to_string() + "\n";
        let key = || c.key_pem.clone().ok_or_else(|| "This certificate was signed from a request; its private key never left the requesting machine.".to_string());
        Ok(match kind {
            Export::CertPem => leaf.into_bytes(),
            Export::CertDer => pem_to_der(&c.cert_pem)?,
            Export::KeyPem => key()?.into_bytes(),
            Export::ChainPem => (leaf + &self.chain_pem(&c.ca_id, false)).into_bytes(),
            Export::FullChainPem => (leaf + &self.chain_pem(&c.ca_id, true)).into_bytes(),
            Export::BundlePem => (key()?.trim().to_string() + "\n" + &leaf + &self.chain_pem(&c.ca_id, true)).into_bytes(),
            Export::Pfx => {
                let k = key()?;
                let kder = pem_to_der(&k)?;
                let cder = pem_to_der(&c.cert_pem)?;
                let chain: Vec<Vec<u8>> = self.ca_chain(&c.ca_id).iter().filter_map(|a| pem_to_der(&a.cert_pem).ok()).collect();
                let refs: Vec<&[u8]> = chain.iter().map(|v| v.as_slice()).collect();
                let pfx = p12::PFX::new_with_cas(&cder, &kder, &refs, password, &c.common_name).ok_or("Could not build the PFX file.")?;
                pfx.to_der()
            }
        })
    }

    pub fn export_authority(&self, id: &str, kind: Export, password: &str) -> Res<Vec<u8>> {
        let a = self.authority(id).ok_or("Authority not found.")?;
        let leaf = a.cert_pem.trim().to_string() + "\n";
        Ok(match kind {
            Export::CertPem => leaf.into_bytes(),
            Export::CertDer => pem_to_der(&a.cert_pem)?,
            Export::KeyPem => a.key_pem.clone().into_bytes(),
            Export::ChainPem | Export::FullChainPem => self.chain_pem(id, true).into_bytes(),
            Export::BundlePem => (a.key_pem.trim().to_string() + "\n" + &self.chain_pem(id, true)).into_bytes(),
            Export::Pfx => {
                let kder = pem_to_der(&a.key_pem)?;
                let cder = pem_to_der(&a.cert_pem)?;
                let chain: Vec<Vec<u8>> = self.ca_chain(id).iter().skip(1).filter_map(|x| pem_to_der(&x.cert_pem).ok()).collect();
                let refs: Vec<&[u8]> = chain.iter().map(|v| v.as_slice()).collect();
                p12::PFX::new_with_cas(&cder, &kder, &refs, password, &a.name).ok_or("Could not build the PFX file.")?.to_der()
            }
        })
    }
}

/// Add a root to the current user's Windows trust store (Windows shows its own confirmation).
pub fn install_trust(a: &Authority) -> Res<String> {
    #[cfg(windows)]
    {
        let path = std::env::temp_dir().join(format!("labcert-{}.crt", a.id));
        std::fs::write(&path, &a.cert_pem).map_err(e)?;
        let out = std::process::Command::new("certutil")
            .args(["-user", "-addstore", "Root"])
            .arg(&path)
            .output()
            .map_err(|x| format!("Could not run certutil: {x}"))?;
        let _ = std::fs::remove_file(&path);
        if out.status.success() {
            Ok(format!("\"{}\" is now trusted by this Windows user (browsers that use the Windows store will accept its certificates).", a.name))
        } else {
            let msg = String::from_utf8_lossy(&out.stdout).trim().to_string();
            Err(if msg.is_empty() { "Windows did not add the certificate (the prompt may have been declined).".into() } else { msg })
        }
    }
    #[cfg(not(windows))]
    {
        let _ = a;
        Err("Automatic trust install is only available on Windows. Export the certificate and add it to your system's trust store.".into())
    }
}
