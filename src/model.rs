//! Persistent data model: authorities, issued certificates, tokens, requests, settings, log.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

pub type Res<T> = Result<T, String>;

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

static LOCAL_OFFSET: OnceLock<time::UtcOffset> = OnceLock::new();

/// Must be called once at startup, before other threads exist.
pub fn init_local_offset() {
    let off = time::UtcOffset::current_local_offset().unwrap_or(time::UtcOffset::UTC);
    let _ = LOCAL_OFFSET.set(off);
}

fn local(ts: i64) -> time::OffsetDateTime {
    let off = *LOCAL_OFFSET.get().unwrap_or(&time::UtcOffset::UTC);
    time::OffsetDateTime::from_unix_timestamp(ts)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
        .to_offset(off)
}

pub fn fmt_date(ts: i64) -> String {
    let d = local(ts);
    format!("{:04}-{:02}-{:02}", d.year(), d.month() as u8, d.day())
}

pub fn fmt_datetime(ts: i64) -> String {
    let d = local(ts);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        d.year(),
        d.month() as u8,
        d.day(),
        d.hour(),
        d.minute()
    )
}

pub fn fmt_time(ts: i64) -> String {
    let d = local(ts);
    format!("{:02}:{:02}:{:02}", d.hour(), d.minute(), d.second())
}

pub fn rfc3339(ts: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(ts)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// "in 23 days", "3 days ago", "today"
pub fn relative_days(ts: i64) -> String {
    let diff = ts - now();
    let days = diff / 86_400;
    if diff >= 0 {
        match days {
            0 => {
                let h = diff / 3600;
                if h <= 1 { "within the hour".into() } else { format!("in {h} hours") }
            }
            1 => "in 1 day".into(),
            d if d < 60 => format!("in {d} days"),
            d if d < 730 => format!("in {} months", d / 30),
            d => format!("in {} years", d / 365),
        }
    } else {
        let days = -days;
        match days {
            0 => "today".into(),
            1 => "1 day ago".into(),
            d if d < 60 => format!("{d} days ago"),
            d if d < 730 => format!("{} months ago", d / 30),
            d => format!("{} years ago", d / 365),
        }
    }
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    use ring::rand::SecureRandom;
    let mut v = vec![0u8; n];
    ring::rand::SystemRandom::new().fill(&mut v).expect("system random");
    v
}

pub fn random_id(n: usize) -> String {
    hex(&random_bytes(n))
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn hex_colon(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(":")
}

// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum KeyType {
    #[default]
    EcdsaP256,
    EcdsaP384,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    Ed25519,
}

impl KeyType {
    pub const ALL: [KeyType; 6] = [
        KeyType::EcdsaP256,
        KeyType::EcdsaP384,
        KeyType::Rsa2048,
        KeyType::Rsa3072,
        KeyType::Rsa4096,
        KeyType::Ed25519,
    ];
    pub fn label(self) -> &'static str {
        match self {
            KeyType::EcdsaP256 => "ECDSA P-256",
            KeyType::EcdsaP384 => "ECDSA P-384",
            KeyType::Rsa2048 => "RSA 2048",
            KeyType::Rsa3072 => "RSA 3072",
            KeyType::Rsa4096 => "RSA 4096",
            KeyType::Ed25519 => "Ed25519",
        }
    }
    pub fn hint(self) -> &'static str {
        match self {
            KeyType::EcdsaP256 => "Fast, modern, works everywhere (recommended)",
            KeyType::EcdsaP384 => "Stronger elliptic curve, widely supported",
            KeyType::Rsa2048 => "Classic; best for very old devices",
            KeyType::Rsa3072 => "Classic, stronger",
            KeyType::Rsa4096 => "Classic, strongest; slow to create",
            KeyType::Ed25519 => "Modern, but browsers and Windows don't accept it for TLS",
        }
    }
    pub fn is_rsa(self) -> bool {
        matches!(self, KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Profile {
    #[default]
    Server,
    Client,
    ServerClient,
    CodeSigning,
    Email,
}

impl Profile {
    pub const ALL: [Profile; 5] = [
        Profile::Server,
        Profile::Client,
        Profile::ServerClient,
        Profile::CodeSigning,
        Profile::Email,
    ];
    pub fn label(self) -> &'static str {
        match self {
            Profile::Server => "Web / TLS server",
            Profile::Client => "Client / user login",
            Profile::ServerClient => "Server + client (mutual TLS)",
            Profile::CodeSigning => "Code signing",
            Profile::Email => "Email (S/MIME)",
        }
    }
    pub fn short(self) -> &'static str {
        match self {
            Profile::Server => "Server",
            Profile::Client => "Client",
            Profile::ServerClient => "Server+Client",
            Profile::CodeSigning => "Code signing",
            Profile::Email => "Email",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Source {
    #[default]
    Manual,
    Csr,
    Enrollment,
    Acme,
    Renewal,
    ServerTls,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::Manual => "Created in app",
            Source::Csr => "Signed request",
            Source::Enrollment => "Network enrollment",
            Source::Acme => "ACME",
            Source::Renewal => "Renewal",
            Source::ServerTls => "Built-in server",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Reason {
    #[default]
    Unspecified,
    KeyCompromise,
    CaCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    PrivilegeWithdrawn,
}

impl Reason {
    pub const ALL: [Reason; 8] = [
        Reason::Unspecified,
        Reason::KeyCompromise,
        Reason::CaCompromise,
        Reason::AffiliationChanged,
        Reason::Superseded,
        Reason::CessationOfOperation,
        Reason::CertificateHold,
        Reason::PrivilegeWithdrawn,
    ];
    pub fn label(self) -> &'static str {
        match self {
            Reason::Unspecified => "Unspecified",
            Reason::KeyCompromise => "Key compromised",
            Reason::CaCompromise => "Authority compromised",
            Reason::AffiliationChanged => "Affiliation changed",
            Reason::Superseded => "Replaced (superseded)",
            Reason::CessationOfOperation => "No longer used",
            Reason::CertificateHold => "On hold (temporary)",
            Reason::PrivilegeWithdrawn => "Privilege withdrawn",
        }
    }
    pub fn from_code(c: u8) -> Reason {
        match c {
            1 => Reason::KeyCompromise,
            2 => Reason::CaCompromise,
            3 => Reason::AffiliationChanged,
            4 => Reason::Superseded,
            5 => Reason::CessationOfOperation,
            6 => Reason::CertificateHold,
            9 => Reason::PrivilegeWithdrawn,
            _ => Reason::Unspecified,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Revocation {
    pub at: i64,
    pub reason: Reason,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Authority {
    pub id: String,
    pub name: String,
    pub parent: Option<String>,
    pub cert_pem: String,
    pub key_pem: String,
    pub key_type: KeyType,
    pub subject: String,
    pub serial: String,
    pub not_before: i64,
    pub not_after: i64,
    pub created: i64,
    pub imported: bool,
    pub path_len: Option<u8>,
    pub crl_number: u64,
    pub crl_pem: Option<String>,
    pub crl_this_update: i64,
    pub crl_next_update: i64,
    pub fingerprint: String,
    pub notes: String,
    pub self_signed: bool,
    pub revoked: Option<Revocation>,
}

impl Authority {
    pub fn is_root(&self) -> bool {
        self.self_signed
    }
    pub fn kind_label(&self) -> &'static str {
        if self.self_signed {
            "Root"
        } else if self.parent.is_some() {
            "Intermediate"
        } else {
            "Intermediate (external root)"
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Cert {
    pub id: String,
    pub ca_id: String,
    pub common_name: String,
    pub sans: Vec<String>,
    pub profile: Profile,
    pub key_type: KeyType,
    pub serial: String,
    pub not_before: i64,
    pub not_after: i64,
    pub cert_pem: String,
    pub key_pem: Option<String>,
    pub source: Source,
    pub requested_by: String,
    pub created: i64,
    pub revoked: Option<Revocation>,
    pub renewed_by: Option<String>,
    pub fingerprint: String,
    pub notes: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CertStatus {
    Valid,
    Expiring,
    Expired,
    Revoked,
    OnHold,
    NotYetValid,
}

impl CertStatus {
    pub fn label(self) -> &'static str {
        match self {
            CertStatus::Valid => "Valid",
            CertStatus::Expiring => "Expiring",
            CertStatus::Expired => "Expired",
            CertStatus::Revoked => "Revoked",
            CertStatus::OnHold => "On hold",
            CertStatus::NotYetValid => "Not yet valid",
        }
    }
}

impl Cert {
    pub fn status(&self, warn_days: u32) -> CertStatus {
        let t = now();
        if let Some(r) = &self.revoked {
            return if r.reason == Reason::CertificateHold { CertStatus::OnHold } else { CertStatus::Revoked };
        }
        if t > self.not_after {
            CertStatus::Expired
        } else if t + 3600 < self.not_before {
            CertStatus::NotYetValid
        } else if self.not_after - t < warn_days as i64 * 86_400 {
            CertStatus::Expiring
        } else {
            CertStatus::Valid
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Token {
    pub id: String,
    pub label: String,
    pub secret: String,
    pub created: i64,
    pub expires: Option<i64>,
    pub uses: u32,
    pub max_uses: Option<u32>,
    pub auto_approve: bool,
    pub profile: Profile,
    pub validity_days: u32,
    pub ca_id: Option<String>,
    pub disabled: bool,
}

impl Token {
    pub fn usable(&self) -> bool {
        !self.disabled
            && self.expires.map(|e| e > now()).unwrap_or(true)
            && self.max_uses.map(|m| self.uses < m).unwrap_or(true)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum RequestStatus {
    #[default]
    Pending,
    Issued,
    Rejected,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct PendingRequest {
    pub id: String,
    pub received: i64,
    pub from_addr: String,
    pub token_label: String,
    pub csr_pem: String,
    pub subject: String,
    pub sans: Vec<String>,
    pub key_desc: String,
    pub profile: Profile,
    pub validity_days: u32,
    pub ca_id: Option<String>,
    pub status: RequestStatus,
    pub cert_id: Option<String>,
    pub note: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct AcmeAccount {
    pub id: String,
    pub jwk: serde_json::Value,
    pub thumbprint: String,
    pub contact: Vec<String>,
    pub created: i64,
    pub status: String,
    pub last_seen: i64,
    pub orders: u32,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum LogKind {
    #[default]
    Info,
    Success,
    Warn,
    Error,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct LogEntry {
    pub ts: i64,
    pub kind: LogKind,
    pub category: String,
    pub msg: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct ServerSettings {
    pub bind: String,
    pub http_on: bool,
    pub http_port: u16,
    pub https_on: bool,
    pub https_port: u16,
    pub autostart: bool,
    pub acme_on: bool,
    pub acme_auto_approve: bool,
    pub acme_days: u32,
    pub acme_ca: Option<String>,
    pub enroll_on: bool,
    pub publish_certs: bool,
    pub server_cert_id: Option<String>,
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0".into(),
            http_on: true,
            http_port: 8080,
            https_on: true,
            https_port: 8443,
            autostart: false,
            acme_on: true,
            acme_auto_approve: false,
            acme_days: 90,
            acme_ca: None,
            enroll_on: true,
            publish_certs: false,
            server_cert_id: None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Settings {
    pub organization: String,
    pub org_unit: String,
    pub locality: String,
    pub state: String,
    pub country: String,
    pub default_key: KeyType,
    pub default_days: u32,
    pub ca_years: u32,
    pub warn_days: u32,
    pub crl_days: u32,
    pub public_host: String,
    pub include_cdp: bool,
    pub dark: bool,
    pub default_ca: Option<String>,
    pub server: ServerSettings,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            organization: "Home Lab".into(),
            org_unit: String::new(),
            locality: String::new(),
            state: String::new(),
            country: String::new(),
            default_key: KeyType::EcdsaP256,
            default_days: 365,
            ca_years: 10,
            warn_days: 30,
            crl_days: 7,
            public_host: String::new(),
            include_cdp: true,
            dark: true,
            default_ca: None,
            server: ServerSettings::default(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Store {
    pub version: u32,
    pub authorities: Vec<Authority>,
    pub certs: Vec<Cert>,
    pub tokens: Vec<Token>,
    pub requests: Vec<PendingRequest>,
    pub acme_accounts: Vec<AcmeAccount>,
    pub settings: Settings,
    pub log: Vec<LogEntry>,
}

const MAX_LOG: usize = 5000;

impl Store {
    pub fn load(path: &Path) -> Store {
        match std::fs::read_to_string(path) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_else(|e| {
                // Keep a copy of the unreadable file rather than overwriting it silently.
                let bad = path.with_extension(format!("broken-{}.json", now()));
                let _ = std::fs::copy(path, &bad);
                let mut st = Store::default();
                st.log(LogKind::Error, "storage", format!("Could not read saved data ({e}); a copy was kept at {}", bad.display()));
                st
            }),
            Err(_) => Store { version: 1, ..Default::default() },
        }
    }

    pub fn save(&self, path: &Path) -> Res<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, json).map_err(|e| e.to_string())?;
        if path.exists() {
            let bak = path.with_extension("json.bak");
            let _ = std::fs::copy(path, bak);
        }
        std::fs::rename(&tmp, path).map_err(|e| e.to_string())
    }

    pub fn log(&mut self, kind: LogKind, category: &str, msg: impl Into<String>) {
        self.log.push(LogEntry { ts: now(), kind, category: category.into(), msg: msg.into() });
        if self.log.len() > MAX_LOG {
            let extra = self.log.len() - MAX_LOG;
            self.log.drain(0..extra);
        }
    }

    pub fn authority(&self, id: &str) -> Option<&Authority> {
        self.authorities.iter().find(|a| a.id == id)
    }
    pub fn authority_mut(&mut self, id: &str) -> Option<&mut Authority> {
        self.authorities.iter_mut().find(|a| a.id == id)
    }
    pub fn cert(&self, id: &str) -> Option<&Cert> {
        self.certs.iter().find(|c| c.id == id)
    }
    pub fn cert_mut(&mut self, id: &str) -> Option<&mut Cert> {
        self.certs.iter_mut().find(|c| c.id == id)
    }
    pub fn ca_name(&self, id: &str) -> String {
        self.authority(id).map(|a| a.name.clone()).unwrap_or_else(|| "(deleted authority)".into())
    }

    /// The authority used when nothing else is chosen.
    pub fn default_ca_id(&self) -> Option<String> {
        if let Some(id) = &self.settings.default_ca {
            if self.authority(id).is_some() {
                return Some(id.clone());
            }
        }
        // Prefer an intermediate if one exists, otherwise the first root.
        self.authorities
            .iter()
            .find(|a| !a.is_root())
            .or_else(|| self.authorities.first())
            .map(|a| a.id.clone())
    }

    pub fn pending_requests(&self) -> usize {
        self.requests.iter().filter(|r| r.status == RequestStatus::Pending).count()
    }
}

// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct HttpLog {
    pub ts: i64,
    pub remote: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub tls: bool,
}

/// Everything shared between the window and the network service.
pub struct Shared {
    pub store: Mutex<Store>,
    pub path: PathBuf,
    pub http_log: Mutex<VecDeque<HttpLog>>,
    pub repaint: Mutex<Option<egui::Context>>,
}

impl Shared {
    pub fn new(path: PathBuf) -> Shared {
        let store = Store::load(&path);
        Shared {
            store: Mutex::new(store),
            path,
            http_log: Mutex::new(VecDeque::new()),
            repaint: Mutex::new(None),
        }
    }

    pub fn store(&self) -> std::sync::MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn save(&self, st: &Store) {
        if let Err(e) = st.save(&self.path) {
            eprintln!("save failed: {e}");
        }
    }

    pub fn poke(&self) {
        if let Some(ctx) = self.repaint.lock().ok().and_then(|g| g.clone()) {
            ctx.request_repaint();
        }
    }

    pub fn http(&self, entry: HttpLog) {
        if let Ok(mut l) = self.http_log.lock() {
            l.push_back(entry);
            while l.len() > 500 {
                l.pop_front();
            }
        }
        self.poke();
    }
}
