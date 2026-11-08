//! The desktop window: navigation, background jobs, dialogs, notifications.

use crate::acme::AcmeState;
use crate::ca::{self, Export};
use crate::model::*;
use crate::server::Server;
use crate::theme::{self, Pal};
use egui::{Align, Color32, CornerRadius, Layout, Margin, RichText, Sense, Stroke, Vec2};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Page {
    Dashboard,
    Authorities,
    Certificates,
    Issue,
    Requests,
    Server,
    Revocation,
    Activity,
    Settings,
}

impl Page {
    pub const ALL: [Page; 9] = [
        Page::Dashboard,
        Page::Authorities,
        Page::Certificates,
        Page::Issue,
        Page::Requests,
        Page::Server,
        Page::Revocation,
        Page::Activity,
        Page::Settings,
    ];
    pub fn label(self) -> &'static str {
        match self {
            Page::Dashboard => "Overview",
            Page::Authorities => "Authorities",
            Page::Certificates => "Certificates",
            Page::Issue => "New certificate",
            Page::Requests => "Signing requests",
            Page::Server => "Network service",
            Page::Revocation => "Revocation",
            Page::Activity => "Activity log",
            Page::Settings => "Settings",
        }
    }
    pub fn subtitle(self) -> &'static str {
        match self {
            Page::Dashboard => "Your local certificate authority at a glance",
            Page::Authorities => "Root and intermediate authorities that sign your certificates",
            Page::Certificates => "Everything this authority has issued",
            Page::Issue => "Create a certificate and its private key",
            Page::Requests => "Sign requests made on other machines, and approve network requests",
            Page::Server => "Hand out the root certificate, enrollment and automatic (ACME) certificates on your network",
            Page::Revocation => "Withdrawn certificates and the lists devices check",
            Page::Activity => "A record of everything that happened",
            Page::Settings => "Defaults, addresses, appearance and backups",
        }
    }
    pub fn from_name(s: &str) -> Option<Page> {
        Page::ALL.iter().copied().find(|p| format!("{p:?}").eq_ignore_ascii_case(s))
    }
}

pub struct Toast {
    pub msg: String,
    pub ok: bool,
    pub until: f64,
}

pub struct JobResult {
    pub result: Res<String>,
    pub goto: Option<(Page, Option<String>)>,
}

pub struct Job {
    pub label: String,
    pub rx: Receiver<JobResult>,
}

pub enum Action {
    StartServer,
    StopServer,
    RestartServer,
    SaveFile { name: String, bytes: Res<Vec<u8>> },
    InstallTrust(String),
    Backup,
    Restore,
    OpenDataFolder,
    ExportLog,
}

#[derive(Clone)]
pub struct CaForm {
    pub name: String,
    pub common_name: String,
    pub organization: String,
    pub org_unit: String,
    pub country: String,
    pub key_type: KeyType,
    pub years: u32,
    pub limit_depth: bool,
    pub with_intermediate: bool,
}

impl CaForm {
    pub fn new(s: &Settings, intermediate: bool) -> CaForm {
        CaForm {
            name: if intermediate { "Issuing CA".into() } else { format!("{} Root CA", if s.organization.is_empty() { "Home Lab" } else { &s.organization }) },
            common_name: String::new(),
            organization: s.organization.clone(),
            org_unit: s.org_unit.clone(),
            country: s.country.clone(),
            key_type: KeyType::EcdsaP384,
            years: if intermediate { (s.ca_years / 2).max(1) } else { s.ca_years.max(1) },
            limit_depth: intermediate,
            with_intermediate: !intermediate,
        }
    }
}

pub struct IssueForm {
    pub ca_id: Option<String>,
    pub profile: Profile,
    pub common_name: String,
    pub sans: String,
    pub cn_as_san: bool,
    pub key_type: KeyType,
    pub days: u32,
    pub organization: String,
    pub org_unit: String,
    pub locality: String,
    pub state: String,
    pub country: String,
    pub notes: String,
}

impl IssueForm {
    pub fn new(s: &Settings) -> IssueForm {
        IssueForm {
            ca_id: None,
            profile: Profile::Server,
            common_name: String::new(),
            sans: String::new(),
            cn_as_san: true,
            key_type: s.default_key,
            days: s.default_days,
            organization: s.organization.clone(),
            org_unit: s.org_unit.clone(),
            locality: s.locality.clone(),
            state: s.state.clone(),
            country: s.country.clone(),
            notes: String::new(),
        }
    }
}

pub struct CsrForm {
    pub text: String,
    pub parsed_for: String,
    pub parsed: Option<Res<ca::CsrInfo>>,
    pub ca_id: Option<String>,
    pub profile: Profile,
    pub days: u32,
    pub extra: String,
    pub keep_subject: bool,
}

pub struct TokenForm {
    pub label: String,
    pub profile: Profile,
    pub days: u32,
    pub auto_approve: bool,
    pub max_uses: u32,
    pub limit_uses: bool,
    pub expires_days: u32,
    pub expires: bool,
    pub ca_id: Option<String>,
}

pub enum Dialog {
    NewCa { form: CaForm, parent: Option<String> },
    ImportCa { name: String, cert: String, key: String },
    Revoke { id: String, reason: Reason },
    RevokeCa { id: String, reason: Reason },
    DeleteCert { id: String },
    DeleteCa { id: String },
    Pfx { id: String, is_ca: bool, pw: String, pw2: String },
    CaKey { id: String },
    Renew { id: String, new_key: bool, days: u32, supersede: bool },
    NewToken(TokenForm),
    Secret { label: String, secret: String },
    Reject { id: String, note: String },
    ConfirmRestore { path: std::path::PathBuf },
    ClearLog,
}

pub struct App {
    pub shared: Arc<Shared>,
    pub acme: Arc<AcmeState>,
    pub server: Option<Server>,
    pub server_error: Option<String>,
    pub page: Page,
    pub toasts: Vec<Toast>,
    pub jobs: Vec<Job>,
    pub dialog: Option<Dialog>,
    pub actions: Vec<Action>,
    pub dirty: bool,
    pub dirty_at: f64,
    pub ca_form: CaForm,
    pub issue: IssueForm,
    pub csr: CsrForm,
    pub search: String,
    pub status_filter: usize,
    pub ca_filter: Option<String>,
    pub selected: Option<String>,
    pub expanded_ca: Option<String>,
    pub log_search: String,
    pub log_kind: Option<LogKind>,
    pub show_pem: bool,
    pub dark_applied: Option<bool>,
    pub frame_no: u64,
    pub screenshot: Option<std::path::PathBuf>,
    pub shot: Arc<Mutex<Option<Arc<egui::ColorImage>>>>,
    pub shot_requested: bool,
    pub last_tick: f64,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, shared: Arc<Shared>, screenshot: Option<std::path::PathBuf>, page: Option<Page>) -> App {
        *shared.repaint.lock().unwrap() = Some(cc.egui_ctx.clone());
        let (settings, autostart, has_ca) = {
            let mut st = shared.store();
            if st.refresh_crls() {
                shared.save(&st);
            }
            (st.settings.clone(), st.settings.server.autostart, !st.authorities.is_empty())
        };
        let mut app = App {
            acme: Arc::new(AcmeState::default()),
            server: None,
            server_error: None,
            page: page.unwrap_or(Page::Dashboard),
            toasts: vec![],
            jobs: vec![],
            dialog: None,
            actions: vec![],
            dirty: false,
            dirty_at: 0.0,
            ca_form: CaForm::new(&settings, false),
            issue: IssueForm::new(&settings),
            csr: CsrForm { text: String::new(), parsed_for: String::new(), parsed: None, ca_id: None, profile: Profile::Server, days: settings.default_days, extra: String::new(), keep_subject: true },
            search: String::new(),
            status_filter: 0,
            ca_filter: None,
            selected: None,
            expanded_ca: None,
            log_search: String::new(),
            log_kind: None,
            show_pem: false,
            dark_applied: None,
            frame_no: 0,
            screenshot,
            shot: Arc::new(Mutex::new(None)),
            shot_requested: false,
            last_tick: 0.0,
            shared,
        };
        if autostart && has_ca && app.screenshot.is_none() {
            app.actions.push(Action::StartServer);
        }
        app
    }

    pub fn toast(&mut self, ctx: &egui::Context, msg: impl Into<String>, ok: bool) {
        let t = ctx.input(|i| i.time);
        self.toasts.push(Toast { msg: msg.into(), ok, until: t + if ok { 5.0 } else { 9.0 } });
    }

    pub fn mark_dirty(&mut self, ctx: &egui::Context) {
        self.dirty = true;
        self.dirty_at = ctx.input(|i| i.time);
    }

    /// Run work (key generation, signing) away from the window so it never freezes.
    pub fn spawn(&mut self, label: &str, f: impl FnOnce(&Shared) -> JobResult + Send + 'static) {
        let (tx, rx) = channel();
        let shared = self.shared.clone();
        std::thread::spawn(move || {
            let r = f(&shared);
            let _ = tx.send(r);
            shared.poke();
        });
        self.jobs.push(Job { label: label.into(), rx });
    }

    fn poll_jobs(&mut self, ctx: &egui::Context) {
        let mut done = vec![];
        self.jobs.retain(|j| match j.rx.try_recv() {
            Ok(r) => {
                done.push(r);
                false
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => true,
            Err(_) => false,
        });
        for r in done {
            match r.result {
                Ok(m) => {
                    self.toast(ctx, m, true);
                    if let Some((page, sel)) = r.goto {
                        self.page = page;
                        if page == Page::Certificates {
                            self.selected = sel;
                        } else if page == Page::Authorities {
                            self.expanded_ca = sel;
                        }
                    }
                }
                Err(e) => self.toast(ctx, e, false),
            }
        }
    }

    fn run_actions(&mut self, ctx: &egui::Context) {
        let actions = std::mem::take(&mut self.actions);
        for a in actions {
            match a {
                Action::StartServer => self.start_server(ctx),
                Action::StopServer => {
                    if let Some(s) = self.server.take() {
                        s.stop(&self.shared);
                        self.toast(ctx, "Network service stopped", true);
                    }
                }
                Action::RestartServer => {
                    if let Some(s) = self.server.take() {
                        s.stop(&self.shared);
                    }
                    self.start_server(ctx);
                }
                Action::SaveFile { name, bytes } => match bytes {
                    Err(e) => self.toast(ctx, e, false),
                    Ok(b) => {
                        let ext = name.rsplit('.').next().unwrap_or("").to_string();
                        let mut dlg = rfd::FileDialog::new().set_file_name(&name);
                        if !ext.is_empty() {
                            dlg = dlg.add_filter(ext.to_uppercase(), &[ext.as_str()]);
                        }
                        if let Some(path) = dlg.save_file() {
                            match std::fs::write(&path, b) {
                                Ok(()) => self.toast(ctx, format!("Saved {}", path.display()), true),
                                Err(e) => self.toast(ctx, format!("Could not save: {e}"), false),
                            }
                        }
                    }
                },
                Action::InstallTrust(id) => {
                    let a = self.shared.store().authority(&id).cloned();
                    if let Some(a) = a {
                        let r = ca::install_trust(&a);
                        let mut st = self.shared.store();
                        match &r {
                            Ok(m) => st.log(LogKind::Success, "trust", m.clone()),
                            Err(e) => st.log(LogKind::Warn, "trust", format!("Trust install for \"{}\" failed: {e}", a.name)),
                        }
                        self.shared.save(&st);
                        drop(st);
                        match r {
                            Ok(m) => self.toast(ctx, m, true),
                            Err(e) => self.toast(ctx, e, false),
                        }
                    }
                }
                Action::Backup => {
                    let name = format!("labcert-backup-{}.json", fmt_date(now()));
                    if let Some(path) = rfd::FileDialog::new().set_file_name(&name).add_filter("JSON", &["json"]).save_file() {
                        let st = self.shared.store();
                        let r = st.save(&path);
                        drop(st);
                        match r {
                            Ok(()) => self.toast(ctx, format!("Backup saved to {} — it contains private keys, keep it safe", path.display()), true),
                            Err(e) => self.toast(ctx, e, false),
                        }
                    }
                }
                Action::Restore => {
                    if let Some(path) = rfd::FileDialog::new().add_filter("JSON", &["json"]).pick_file() {
                        self.dialog = Some(Dialog::ConfirmRestore { path });
                    }
                }
                Action::OpenDataFolder => {
                    if let Some(dir) = self.shared.path.parent() {
                        #[cfg(windows)]
                        let _ = std::process::Command::new("explorer").arg(dir).spawn();
                        #[cfg(target_os = "macos")]
                        let _ = std::process::Command::new("open").arg(dir).spawn();
                        #[cfg(all(unix, not(target_os = "macos")))]
                        let _ = std::process::Command::new("xdg-open").arg(dir).spawn();
                    }
                }
                Action::ExportLog => {
                    let st = self.shared.store();
                    let mut csv = String::from("time,kind,category,message\n");
                    for l in &st.log {
                        csv.push_str(&format!("{},{:?},{},\"{}\"\n", rfc3339(l.ts), l.kind, l.category, l.msg.replace('"', "\"\"")));
                    }
                    drop(st);
                    self.actions.push(Action::SaveFile { name: "labcert-activity.csv".into(), bytes: Ok(csv.into_bytes()) });
                    self.run_actions(ctx);
                }
            }
        }
    }

    fn start_server(&mut self, ctx: &egui::Context) {
        if self.server.is_some() {
            return;
        }
        match Server::start(self.shared.clone(), self.acme.clone()) {
            Ok(s) => {
                self.server_error = None;
                self.server = Some(s);
                self.toast(ctx, "Network service is running", true);
            }
            Err(e) => {
                self.shared.store().log(LogKind::Error, "server", format!("Could not start: {e}"));
                self.server_error = Some(e.clone());
                self.toast(ctx, e, false);
            }
        }
    }

    pub fn save_cert_export(&mut self, st: &Store, id: &str, kind: Export) {
        let name = st.cert(id).map(|c| kind.file_name(&c.common_name)).unwrap_or_else(|| "certificate".into());
        if kind == Export::Pfx {
            self.dialog = Some(Dialog::Pfx { id: id.into(), is_ca: false, pw: String::new(), pw2: String::new() });
            return;
        }
        self.actions.push(Action::SaveFile { name, bytes: st.export_cert(id, kind, "") });
    }

    pub fn save_ca_export(&mut self, st: &Store, id: &str, kind: Export) {
        let name = st.authority(id).map(|a| kind.file_name(&a.name)).unwrap_or_else(|| "authority".into());
        match kind {
            Export::Pfx => self.dialog = Some(Dialog::Pfx { id: id.into(), is_ca: true, pw: String::new(), pw2: String::new() }),
            Export::KeyPem | Export::BundlePem => self.dialog = Some(Dialog::CaKey { id: id.into() }),
            _ => self.actions.push(Action::SaveFile { name, bytes: st.export_authority(id, kind, "") }),
        }
    }

    fn take_screenshot(&mut self, ctx: &egui::Context) {
        let Some(path) = self.screenshot.clone() else { return };
        ctx.request_repaint();
        if self.frame_no >= 120 && !self.shot_requested {
            self.shot_requested = true;
            let slot = self.shot.clone();
            let c2 = ctx.clone();
            ctx.request_screenshot(move |img| {
                *slot.lock().unwrap() = Some(img);
                c2.request_repaint();
            });
        }
        let img = self.shot.lock().unwrap().take();
        if let Some(img) = img {
            let [w, h] = img.size;
            let mut raw = Vec::with_capacity(w * h * 4);
            for px in &img.pixels {
                raw.extend_from_slice(&[px.r(), px.g(), px.b(), 255]);
            }
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            match image::RgbaImage::from_raw(w as u32, h as u32, raw) {
                Some(buf) => {
                    if let Err(e) = buf.save(&path) {
                        eprintln!("could not save screenshot: {e}");
                    }
                }
                None => eprintln!("screenshot buffer had an unexpected size"),
            }
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        if self.frame_no > 600 {
            eprintln!("screenshot was not delivered; closing");
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }

    fn sidebar(&mut self, ui: &mut egui::Ui, st: &Store, p: &Pal) {
        let side_text = Color32::from_rgb(0xc9, 0xd4, 0xe1);
        let side_muted = Color32::from_rgb(0x7d, 0x8d, 0xa1);
        ui.add_space(18.0);
        ui.horizontal(|ui| {
            ui.add_space(8.0);
            theme::logo(ui, p, 34.0);
            ui.vertical(|ui| {
                ui.label(RichText::new("LabCert").size(19.0).strong().color(Color32::WHITE));
                ui.label(RichText::new("Local certificate authority").size(11.0).color(side_muted));
            });
        });
        ui.add_space(22.0);
        let pending = st.pending_requests();
        let warn_days = st.settings.warn_days;
        let expiring = st.certs.iter().filter(|c| c.status(warn_days) == CertStatus::Expiring && c.renewed_by.is_none()).count();
        for page in Page::ALL {
            let selected = self.page == page;
            let (rect, resp) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 38.0), Sense::click());
            let r = rect.shrink2(Vec2::new(10.0, 2.0));
            if selected {
                ui.painter().rect_filled(r, CornerRadius::same(8), p.accent.gamma_multiply(0.18));
                ui.painter().rect_filled(egui::Rect::from_min_size(r.min + Vec2::new(0.0, 8.0), Vec2::new(3.0, r.height() - 16.0)), CornerRadius::same(2), p.accent);
            } else if resp.hovered() {
                ui.painter().rect_filled(r, CornerRadius::same(8), Color32::from_white_alpha(10));
            }
            let icon_rect = egui::Rect::from_center_size(egui::pos2(r.min.x + 22.0, r.center().y), Vec2::splat(16.0));
            nav_icon(ui, page, icon_rect, if selected { p.accent } else { side_muted });
            ui.painter().text(
                egui::pos2(r.min.x + 42.0, r.center().y),
                egui::Align2::LEFT_CENTER,
                page.label(),
                egui::FontId::proportional(14.0),
                if selected { Color32::WHITE } else { side_text },
            );
            let badge = match page {
                Page::Requests if pending > 0 => Some((pending, p.warn)),
                Page::Certificates if expiring > 0 => Some((expiring, p.warn)),
                _ => None,
            };
            if let Some((n, col)) = badge {
                let c = egui::pos2(r.max.x - 18.0, r.center().y);
                ui.painter().circle_filled(c, 9.0, col);
                ui.painter().text(c, egui::Align2::CENTER_CENTER, n.min(99).to_string(), egui::FontId::proportional(11.0), Color32::BLACK);
            }
            if resp.clicked() {
                self.page = page;
            }
            if resp.hovered() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
            }
        }
        // Service status at the bottom.
        let box_h = 112.0;
        ui.add_space((ui.available_height() - box_h - 14.0).max(8.0));
        {
            egui::Frame::new()
                .fill(Color32::from_white_alpha(8))
                .corner_radius(CornerRadius::same(10))
                .inner_margin(Margin::same(12))
                .outer_margin(Margin::symmetric(10, 0))
                .show(ui, |ui| ui.vertical(|ui| {
                    ui.set_width(ui.available_width());
                    let running = self.server.is_some();
                    ui.horizontal(|ui| {
                        let (r, _) = ui.allocate_exact_size(Vec2::splat(10.0), Sense::hover());
                        ui.painter().circle_filled(r.center(), 5.0, if running { p.ok } else { side_muted });
                        ui.label(RichText::new(if running { "Service running" } else { "Service stopped" }).color(Color32::WHITE).size(13.0));
                    });
                    match &self.server {
                        Some(s) => {
                            let port = s.http_addr.or(s.https_addr).map(|a| a.port()).unwrap_or(0);
                            ui.label(RichText::new(format!("{} · port {port}", ca::lan_ip().map(|i| i.to_string()).unwrap_or_else(|| "this computer".into()))).size(11.5).color(side_muted));
                        }
                        None => {
                            ui.label(RichText::new("Devices can't reach it yet").size(11.5).color(side_muted));
                        }
                    }
                    ui.add_space(4.0);
                    let label = if self.server.is_some() { "Stop" } else { "Start service" };
                    if ui.add(egui::Button::new(RichText::new(label).color(Color32::WHITE).size(13.0)).fill(Color32::from_white_alpha(14)).stroke(Stroke::NONE)).clicked() {
                        self.actions.push(if self.server.is_some() { Action::StopServer } else { Action::StartServer });
                    }
                }));
        }
    }

    fn toasts_ui(&mut self, ctx: &egui::Context, p: &Pal) {
        let t = ctx.input(|i| i.time);
        self.toasts.retain(|x| x.until > t);
        if self.toasts.is_empty() && self.jobs.is_empty() {
            return;
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(250));
        egui::Area::new(egui::Id::unique("toasts"))
            .anchor(egui::Align2::RIGHT_BOTTOM, Vec2::new(-18.0, -18.0))
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                ui.set_max_width(420.0);
                for j in &self.jobs {
                    egui::Frame::new().fill(p.card2).stroke(Stroke::new(1.0, p.border)).corner_radius(CornerRadius::same(10)).inner_margin(Margin::same(12)).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label(RichText::new(&j.label).color(p.text));
                        });
                    });
                    ui.add_space(6.0);
                }
                let mut close = None;
                for (i, x) in self.toasts.iter().enumerate() {
                    let col = if x.ok { p.ok } else { p.bad };
                    egui::Frame::new().fill(p.card2).stroke(Stroke::new(1.0, col.gamma_multiply(0.6))).corner_radius(CornerRadius::same(10)).inner_margin(Margin::same(12)).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            let (r, _) = ui.allocate_exact_size(Vec2::new(4.0, 18.0), Sense::hover());
                            ui.painter().rect_filled(r, CornerRadius::same(2), col);
                            ui.add(egui::Label::new(RichText::new(&x.msg).color(p.text)).wrap());
                            if ui.small_button("✕").clicked() {
                                close = Some(i);
                            }
                        });
                    });
                    ui.add_space(6.0);
                }
                if let Some(i) = close {
                    self.toasts.remove(i);
                }
            });
    }
}

/// Small line-art icons for the navigation, drawn with shapes so they never depend on fonts.
fn nav_icon(ui: &egui::Ui, page: Page, r: egui::Rect, col: Color32) {
    let pnt = ui.painter();
    let s = Stroke::new(1.6, col);
    let c = r.center();
    let p = |x: f32, y: f32| egui::pos2(r.min.x + x * r.width(), r.min.y + y * r.height());
    match page {
        Page::Dashboard => {
            for (x, y) in [(0.05, 0.05), (0.55, 0.05), (0.05, 0.55), (0.55, 0.55)] {
                pnt.rect_stroke(egui::Rect::from_min_size(p(x, y), r.size() * 0.4), CornerRadius::same(2), s, egui::StrokeKind::Inside);
            }
        }
        Page::Authorities => {
            pnt.add(egui::Shape::closed_line(vec![p(0.5, 0.0), p(0.95, 0.18), p(0.88, 0.62), p(0.5, 1.0), p(0.12, 0.62), p(0.05, 0.18)], s));
            pnt.circle_filled(c, 2.2, col);
        }
        Page::Certificates => {
            pnt.rect_stroke(egui::Rect::from_min_max(p(0.0, 0.12), p(1.0, 0.88)), CornerRadius::same(2), s, egui::StrokeKind::Inside);
            pnt.line_segment([p(0.18, 0.38), p(0.62, 0.38)], s);
            pnt.line_segment([p(0.18, 0.6), p(0.48, 0.6)], s);
            pnt.circle_stroke(p(0.78, 0.6), 2.2, s);
        }
        Page::Issue => {
            pnt.circle_stroke(c, r.width() * 0.48, s);
            pnt.line_segment([p(0.5, 0.25), p(0.5, 0.75)], s);
            pnt.line_segment([p(0.25, 0.5), p(0.75, 0.5)], s);
        }
        Page::Requests => {
            pnt.add(egui::Shape::line(vec![p(0.0, 0.55), p(0.0, 0.95), p(1.0, 0.95), p(1.0, 0.55)], s));
            pnt.line_segment([p(0.5, 0.0), p(0.5, 0.65)], s);
            pnt.add(egui::Shape::line(vec![p(0.28, 0.45), p(0.5, 0.68), p(0.72, 0.45)], s));
        }
        Page::Server => {
            pnt.rect_stroke(egui::Rect::from_min_max(p(0.0, 0.05), p(1.0, 0.45)), CornerRadius::same(2), s, egui::StrokeKind::Inside);
            pnt.rect_stroke(egui::Rect::from_min_max(p(0.0, 0.55), p(1.0, 0.95)), CornerRadius::same(2), s, egui::StrokeKind::Inside);
            pnt.circle_filled(p(0.8, 0.25), 1.6, col);
            pnt.circle_filled(p(0.8, 0.75), 1.6, col);
        }
        Page::Revocation => {
            pnt.circle_stroke(c, r.width() * 0.48, s);
            pnt.line_segment([p(0.17, 0.83), p(0.83, 0.17)], s);
        }
        Page::Activity => {
            pnt.add(egui::Shape::line(vec![p(0.0, 0.55), p(0.25, 0.55), p(0.4, 0.15), p(0.6, 0.9), p(0.75, 0.55), p(1.0, 0.55)], s));
        }
        Page::Settings => {
            pnt.circle_stroke(c, r.width() * 0.22, s);
            for i in 0..8 {
                let a = i as f32 * std::f32::consts::TAU / 8.0;
                let d = Vec2::new(a.cos(), a.sin());
                pnt.line_segment([c + d * r.width() * 0.32, c + d * r.width() * 0.5], Stroke::new(2.2, col));
            }
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.frame_no += 1;
        self.poll_jobs(&ctx);
        let shared = self.shared.clone();
        let dark = shared.store().settings.dark;
        if self.dark_applied != Some(dark) {
            theme::apply(&ctx, dark);
            self.dark_applied = Some(dark);
        }
        let p = theme::pal(dark);
        let t = ctx.input(|i| i.time);
        // Periodic upkeep: refresh revocation lists, keep relative times current.
        if t - self.last_tick > 60.0 {
            self.last_tick = t;
            let mut st = shared.store();
            if st.refresh_crls() {
                shared.save(&st);
            }
        }
        ctx.request_repaint_after(std::time::Duration::from_secs(5));
        {
            let mut st = shared.store();
            egui::Panel::left("nav")
                .exact_size(232.0)
                .resizable(false)
                .show_separator_line(false)
                .frame(egui::Frame::new().fill(p.side))
                .show(ui, |ui| self.sidebar(ui, &st, &p));
            egui::CentralPanel::default()
                .frame(egui::Frame::new().fill(p.bg).inner_margin(Margin { left: 28, right: 28, top: 22, bottom: 12 }))
                .show(ui, |ui| {
                    self.header(ui, &st, &p);
                    ui.add_space(10.0);
                    self.page_ui(ui, &mut st, &p);
                });
            self.dialogs(&ctx, &mut st, &p);
            if self.dirty && t - self.dirty_at > 0.7 {
                shared.save(&st);
                self.dirty = false;
            }
        }
        self.toasts_ui(&ctx, &p);
        self.run_actions(&ctx);
        self.take_screenshot(&ctx);
    }

    fn on_exit(&mut self) {
        // A screenshot run only looks; it never writes the data file.
        if self.screenshot.is_none() {
            let st = self.shared.store();
            self.shared.save(&st);
        }
        if let Some(s) = self.server.take() {
            s.stop(&self.shared);
        }
    }
}

impl App {
    fn header(&mut self, ui: &mut egui::Ui, st: &Store, p: &Pal) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(RichText::new(self.page.label()).size(24.0).strong().color(p.text));
                ui.label(RichText::new(self.page.subtitle()).size(13.0).color(p.muted));
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let has_ca = !st.authorities.is_empty();
                match self.page {
                    Page::Authorities => {
                        if ui.button("Import existing…").clicked() {
                            self.dialog = Some(Dialog::ImportCa { name: String::new(), cert: String::new(), key: String::new() });
                        }
                        if theme::primary(ui, p, "+ New root authority").clicked() {
                            self.dialog = Some(Dialog::NewCa { form: CaForm::new(&st.settings, false), parent: None });
                        }
                    }
                    Page::Certificates | Page::Dashboard if has_ca => {
                        if theme::primary(ui, p, "+ New certificate").clicked() {
                            self.page = Page::Issue;
                        }
                    }
                    Page::Server => {
                        let running = self.server.is_some();
                        if running {
                            if ui.button("Restart").on_hover_text("Apply changed ports or settings").clicked() {
                                self.actions.push(Action::RestartServer);
                            }
                            if theme::danger(ui, p, "Stop service").clicked() {
                                self.actions.push(Action::StopServer);
                            }
                        } else if theme::primary(ui, p, "Start service").clicked() {
                            self.actions.push(Action::StartServer);
                        }
                    }
                    Page::Activity => {
                        if ui.button("Clear…").clicked() {
                            self.dialog = Some(Dialog::ClearLog);
                        }
                        if ui.button("Export CSV…").clicked() {
                            self.actions.push(Action::ExportLog);
                        }
                    }
                    _ => {}
                }
            });
        });
    }
}
