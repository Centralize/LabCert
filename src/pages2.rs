//! Pages: new certificate and signing requests.

use crate::app::*;
use crate::ca::{self, NameKind};
use crate::model::*;
use crate::pages::*;
use crate::theme::{card, card_title, field_label, muted, pill, primary, Pal};
use egui::{Color32, CornerRadius, RichText, Sense, Vec2};

fn push_line(s: &mut String, n: &str) {
    if !s.is_empty() && !s.ends_with('\n') {
        s.push('\n');
    }
    s.push_str(n);
}

impl App {
    pub fn issue_page(&mut self, ui: &mut egui::Ui, st: &mut Store, p: &Pal) {
        if st.authorities.is_empty() {
            card(ui, p, |ui| {
                card_title(ui, p, "Create an authority first", "Certificates are signed by an authority. It takes a few seconds.");
                if primary(ui, p, "Set up the authority").clicked() {
                    self.page = Page::Dashboard;
                }
            });
            return;
        }
        if self.issue.ca_id.as_deref().map(|i| st.authority(i).is_none()).unwrap_or(true) {
            self.issue.ca_id = st.default_ca_id();
        }
        let names = ca::split_names(&self.issue.sans);
        let cn = self.issue.common_name.trim().to_string();
        let mut all_names: Vec<String> = vec![];
        if self.issue.cn_as_san && !cn.is_empty() && ca::classify_name(&cn).is_ok() {
            all_names.push(cn.clone());
        }
        for n in &names {
            if !all_names.iter().any(|x| x.eq_ignore_ascii_case(n)) {
                all_names.push(n.clone());
            }
        }
        let mut submit = false;
        let local = ca::local_names(&st.settings.public_host);
        let settings = st.settings.clone();
        ui.columns(2, |cols| {
            let (l, r) = cols.split_at_mut(1);
            let l = &mut l[0];
            let r = &mut r[0];
            card(l, p, |ui| {
                let f = &mut self.issue;
                card_title(ui, p, "What is it for?", "");
                egui::Grid::new("issue1").num_columns(2).spacing([16.0, 10.0]).show(ui, |ui| {
                    field_label(ui, p, "Signed by");
                    ca_combo(ui, st, "issue_ca", &mut f.ca_id, None);
                    ui.end_row();
                    field_label(ui, p, "Purpose");
                    profile_combo(ui, "issue_profile", &mut f.profile);
                    ui.end_row();
                });
                ui.add_space(8.0);
                card_title(ui, p, "Names", "The addresses people and programs use to reach it");
                field_label(ui, p, "Main name (common name)");
                ui.add(egui::TextEdit::singleline(&mut f.common_name).desired_width(f32::INFINITY).hint_text(match f.profile {
                    Profile::Client | Profile::Email => "e.g. alice@home.lan",
                    Profile::CodeSigning => "e.g. Home Lab Scripts",
                    _ => "e.g. nas.home.lan",
                }));
                ui.checkbox(&mut f.cn_as_san, "Use the main name as an address too");
                ui.add_space(4.0);
                field_label(ui, p, "Other names — one per line: host names, IP addresses, *.wildcards or emails");
                ui.add(egui::TextEdit::multiline(&mut f.sans).desired_rows(4).desired_width(f32::INFINITY).hint_text("nas\n192.168.1.20\n*.home.lan"));
                ui.horizontal_wrapped(|ui| {
                    if ui.small_button("+ This computer's names").on_hover_text(local.join(", ")).clicked() {
                        for n in &local {
                            if !ca::split_names(&f.sans).contains(n) {
                                push_line(&mut f.sans, n);
                            }
                        }
                    }
                    if ui.small_button("+ localhost").clicked() {
                        for n in ["localhost", "127.0.0.1", "::1"] {
                            if !ca::split_names(&f.sans).iter().any(|x| x == n) {
                                push_line(&mut f.sans, n);
                            }
                        }
                    }
                    let base = f.common_name.trim().to_string();
                    if ca::classify_name(&base) == Ok(NameKind::Dns) && !base.starts_with("*.") && base.contains('.') && ui.small_button(format!("+ *.{base}")).on_hover_text("Also cover every name directly below it").clicked() {
                        push_line(&mut f.sans, &format!("*.{base}"));
                    }
                });
                ui.add_space(10.0);
                card_title(ui, p, "Key and lifetime", "");
                egui::Grid::new("issue2").num_columns(2).spacing([16.0, 10.0]).show(ui, |ui| {
                    field_label(ui, p, "Key type");
                    ui.vertical(|ui| {
                        key_combo(ui, "issue_key", &mut f.key_type);
                        muted(ui, p, f.key_type.hint());
                    });
                    ui.end_row();
                    field_label(ui, p, "Valid for");
                    days_chips(ui, &mut f.days, &[(90, "90 d"), (365, "1 year"), (397, "397 d"), (825, "825 d"), (1825, "5 years")]);
                    ui.end_row();
                });
                ui.add_space(6.0);
                ui.collapsing("Organization details (optional)", |ui| {
                    egui::Grid::new("issue3").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
                        for (l, v) in [("Organization", &mut f.organization), ("Department", &mut f.org_unit), ("City", &mut f.locality), ("State / region", &mut f.state), ("Country (2 letters)", &mut f.country)] {
                            field_label(ui, p, l);
                            ui.add(egui::TextEdit::singleline(v).desired_width(240.0));
                            ui.end_row();
                        }
                    });
                });
                field_label(ui, p, "Notes (kept in this app only)");
                ui.add(egui::TextEdit::singleline(&mut f.notes).desired_width(f32::INFINITY));
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if primary(ui, p, "Create certificate").clicked() {
                        submit = true;
                    }
                    if ui.button("Clear form").clicked() {
                        let ca_id = f.ca_id.clone();
                        *f = IssueForm::new(&settings);
                        f.ca_id = ca_id;
                    }
                });
            });
            card(r, p, |ui| {
                card_title(ui, p, "Preview", "What the certificate will contain");
                let f = &self.issue;
                egui::Grid::new("preview").num_columns(2).spacing([14.0, 7.0]).show(ui, |ui| {
                    kv(ui, p, "Main name", if cn.is_empty() { "—".to_string() } else { cn.clone() });
                    kv(ui, p, "Purpose", f.profile.label());
                    kv(ui, p, "Signed by", f.ca_id.as_deref().map(|i| st.ca_name(i)).unwrap_or_default());
                    let ca_end = f.ca_id.as_deref().and_then(|i| st.authority(i)).map(|a| a.not_after).unwrap_or(i64::MAX);
                    let end = (now() + f.days as i64 * 86_400).min(ca_end);
                    kv(ui, p, "Valid until", format!("{} ({})", fmt_date(end), relative_days(end)));
                    kv(ui, p, "Key", f.key_type.label());
                });
                ui.add_space(8.0);
                ui.label(RichText::new("Addresses").strong());
                if all_names.is_empty() {
                    muted(ui, p, "No addresses yet.");
                }
                for n in &all_names {
                    ui.horizontal(|ui| match ca::classify_name(n) {
                        Ok(k) => {
                            pill(ui, name_kind_label(k), p.info);
                            ui.label(n);
                        }
                        Err(e) => {
                            pill(ui, "Invalid", p.bad);
                            ui.label(RichText::new(e).color(p.bad));
                        }
                    });
                }
                for n in &names {
                    if !all_names.contains(n) {
                        ui.horizontal(|ui| {
                            pill(ui, "Invalid", p.bad);
                            ui.label(RichText::new(n).color(p.bad));
                        });
                    }
                }
                ui.add_space(8.0);
                let mut tips: Vec<(Color32, String)> = vec![];
                let server = matches!(f.profile, Profile::Server | Profile::ServerClient);
                if server && all_names.is_empty() {
                    tips.push((p.warn, "A server certificate needs at least one host name or IP address.".into()));
                }
                if server && f.days > 825 {
                    tips.push((p.warn, "Apple devices reject server certificates valid for more than 825 days.".into()));
                }
                if f.key_type == KeyType::Ed25519 && server {
                    tips.push((p.warn, "Browsers don't accept Ed25519 for websites yet. Pick ECDSA P-256 for web servers.".into()));
                }
                if all_names.iter().any(|n| n.starts_with("*.")) {
                    tips.push((p.info, "A wildcard covers one level only: *.home.lan matches nas.home.lan, not home.lan itself or a.b.home.lan.".into()));
                }
                if all_names.iter().any(|n| n.ends_with(".local")) {
                    tips.push((p.info, ".local names come from multicast DNS (Bonjour); make sure devices actually see that name.".into()));
                }
                if f.key_type.is_rsa() && f.key_type != KeyType::Rsa2048 {
                    tips.push((p.muted, "Large RSA keys take a few seconds to create.".into()));
                }
                if server && !all_names.is_empty() && !all_names.iter().any(|n| ca::classify_name(n) == Ok(NameKind::Ip)) {
                    tips.push((p.muted, "Tip: add the IP address too if people open the service by IP.".into()));
                }
                for (c, t) in tips {
                    ui.horizontal(|ui| {
                        let (r, _) = ui.allocate_exact_size(Vec2::new(4.0, 16.0), Sense::hover());
                        ui.painter().rect_filled(r, CornerRadius::same(2), c);
                        ui.add(egui::Label::new(RichText::new(t).size(12.5)).wrap());
                    });
                }
            });
        });
        if submit {
            self.submit_issue(ui.ctx(), st, names, cn);
        }
    }

    fn submit_issue(&mut self, ctx: &egui::Context, st: &Store, names: Vec<String>, cn: String) {
        let f = &self.issue;
        let Some(ca_id) = f.ca_id.clone() else {
            self.toast(ctx, "Choose an authority to sign with", false);
            return;
        };
        for n in &names {
            if let Err(e) = ca::classify_name(n) {
                self.toast(ctx, e, false);
                return;
            }
        }
        if cn.is_empty() && names.is_empty() {
            self.toast(ctx, "Add a main name or at least one other name", false);
            return;
        }
        let spec = ca::IssueSpec {
            ca_id,
            dn: ca::DnSpec { common_name: cn.clone(), organization: f.organization.clone(), org_unit: f.org_unit.clone(), locality: f.locality.clone(), state: f.state.clone(), country: f.country.clone() },
            sans: names.clone(),
            cn_as_san: f.cn_as_san,
            profile: f.profile,
            key_type: f.key_type,
            days: f.days,
            source: Source::Manual,
            requested_by: String::new(),
            notes: f.notes.clone(),
        };
        let kt = f.key_type;
        let label = format!("Creating \"{}\"…", if cn.is_empty() { names.first().cloned().unwrap_or_default() } else { cn.clone() });
        self.spawn(&label, move |sh| {
            let key = match ca::generate_key(kt) {
                Ok(k) => k,
                Err(e) => return JobResult { result: Err(e), goto: None },
            };
            let mut st = sh.store();
            let r = st.issue(spec, key);
            sh.save(&st);
            match r {
                Ok(id) => {
                    let name = st.cert(&id).map(|c| c.common_name.clone()).unwrap_or_default();
                    JobResult { result: Ok(format!("Created \"{name}\". Use Save… to export it.")), goto: Some((Page::Certificates, Some(id))) }
                }
                Err(e) => JobResult { result: Err(e), goto: None },
            }
        });
        let ca_id = self.issue.ca_id.clone();
        let keep = (self.issue.profile, self.issue.key_type, self.issue.days);
        self.issue = IssueForm::new(&st.settings);
        self.issue.ca_id = ca_id;
        (self.issue.profile, self.issue.key_type, self.issue.days) = keep;
    }

    pub fn requests(&mut self, ui: &mut egui::Ui, st: &mut Store, p: &Pal) {
        let pending: Vec<PendingRequest> = st.requests.iter().filter(|r| r.status == RequestStatus::Pending).cloned().collect();
        if !pending.is_empty() {
            card(ui, p, |ui| {
                card_title(ui, p, &format!("Waiting for approval ({})", pending.len()), "Sent over the network with an enrollment token that needs approval");
                for r in &pending {
                    egui::Frame::new().fill(p.card2).corner_radius(CornerRadius::same(10)).inner_margin(egui::Margin::same(12)).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(if r.sans.is_empty() { r.subject.clone() } else { r.sans.join(", ") }).strong());
                            pill(ui, r.profile.short(), p.info);
                            pill(ui, &r.key_desc, p.muted);
                        });
                        muted(ui, p, format!("{} · from {} · token \"{}\" · {} days · {}", r.subject, r.from_addr, r.token_label, r.validity_days, fmt_datetime(r.received)));
                        ui.horizontal(|ui| {
                            if primary(ui, p, "Approve and sign").clicked() {
                                let ca_id = r.ca_id.clone().filter(|c| st.authority(c).is_some()).or_else(|| st.default_ca_id());
                                let res = ca::parse_csr(r.csr_pem.as_bytes()).and_then(|csr| match ca_id {
                                    Some(ca) => st.sign_csr(&csr, &ca, r.profile, r.validity_days, &[], true, Source::Enrollment, &format!("Token \"{}\" from {}", r.token_label, r.from_addr)),
                                    None => Err("No authority available".into()),
                                });
                                match res {
                                    Ok(cid) => {
                                        if let Some(x) = st.requests.iter_mut().find(|x| x.id == r.id) {
                                            x.status = RequestStatus::Issued;
                                            x.cert_id = Some(cid);
                                        }
                                        self.toast(ui.ctx(), "Approved. The requester can now download the certificate.", true);
                                    }
                                    Err(e) => self.toast(ui.ctx(), e, false),
                                }
                                self.mark_dirty(ui.ctx());
                            }
                            if ui.button("Reject…").clicked() {
                                self.dialog = Some(Dialog::Reject { id: r.id.clone(), note: String::new() });
                            }
                        });
                    });
                    ui.add_space(6.0);
                }
            });
            ui.add_space(12.0);
        }
        card(ui, p, |ui| {
            card_title(ui, p, "Sign a request (CSR)", "The private key stays on the machine that made the request. Paste the request or open the file.");
            ui.horizontal(|ui| {
                if ui.button("Open file…").clicked() {
                    if let Some(path) = rfd::FileDialog::new().add_filter("Signing request", &["csr", "req", "pem", "der", "txt"]).pick_file() {
                        match std::fs::read(&path) {
                            Ok(b) => {
                                self.csr.text = match ca::parse_csr(&b) {
                                    Ok(info) => info.pem.clone(),
                                    Err(_) => String::from_utf8_lossy(&b).into_owned(),
                                }
                            }
                            Err(e) => self.toast(ui.ctx(), format!("Could not read the file: {e}"), false),
                        }
                    }
                }
                if !self.csr.text.is_empty() && ui.button("Clear").clicked() {
                    self.csr.text.clear();
                }
            });
            ui.add(egui::TextEdit::multiline(&mut self.csr.text).font(egui::TextStyle::Monospace).desired_rows(7).desired_width(f32::INFINITY).hint_text("-----BEGIN CERTIFICATE REQUEST-----\n…"));
            if self.csr.parsed_for != self.csr.text {
                self.csr.parsed_for = self.csr.text.clone();
                self.csr.parsed = if self.csr.text.trim().is_empty() { None } else { Some(ca::parse_csr(self.csr.text.as_bytes())) };
            }
            let mut sign = false;
            match &self.csr.parsed {
                None => {
                    ui.add_space(4.0);
                    muted(ui, p, "Make one with:  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout host.key -subj \"/CN=host.lan\" -out host.csr");
                }
                Some(Err(e)) => {
                    ui.label(RichText::new(e).color(p.bad));
                }
                Some(Ok(info)) => {
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        pill(ui, "Signature checked", p.ok);
                        pill(ui, &info.key.desc, p.muted);
                    });
                    egui::Grid::new("csr_kv").num_columns(2).spacing([14.0, 6.0]).show(ui, |ui| {
                        kv(ui, p, "Subject", if info.subject.is_empty() { "—".into() } else { info.subject.clone() });
                        kv(ui, p, "Names", if info.sans.is_empty() { "(none — the main name will be used)".into() } else { info.sans.join(", ") });
                    });
                    ui.add_space(6.0);
                    if self.csr.ca_id.as_deref().map(|i| st.authority(i).is_none()).unwrap_or(true) {
                        self.csr.ca_id = st.default_ca_id();
                    }
                    egui::Grid::new("csr_opts").num_columns(2).spacing([16.0, 10.0]).show(ui, |ui| {
                        field_label(ui, p, "Signed by");
                        ca_combo(ui, st, "csr_ca", &mut self.csr.ca_id, None);
                        ui.end_row();
                        field_label(ui, p, "Purpose");
                        profile_combo(ui, "csr_profile", &mut self.csr.profile);
                        ui.end_row();
                        field_label(ui, p, "Valid for");
                        days_chips(ui, &mut self.csr.days, &[(90, "90 d"), (365, "1 year"), (825, "825 d")]);
                        ui.end_row();
                        field_label(ui, p, "Add names");
                        ui.add(egui::TextEdit::singleline(&mut self.csr.extra).desired_width(300.0).hint_text("optional, comma separated"));
                        ui.end_row();
                        field_label(ui, p, "");
                        ui.checkbox(&mut self.csr.keep_subject, "Keep the requested subject (organization, etc.)");
                        ui.end_row();
                    });
                    ui.add_space(8.0);
                    if st.authorities.is_empty() {
                        muted(ui, p, "Create an authority first.");
                    } else if primary(ui, p, "Sign request").clicked() {
                        sign = true;
                    }
                }
            }
            if sign {
                if let (Some(Ok(info)), Some(ca_id)) = (&self.csr.parsed, self.csr.ca_id.clone()) {
                    let extra = ca::split_names(&self.csr.extra);
                    match st.sign_csr(info, &ca_id, self.csr.profile, self.csr.days, &extra, self.csr.keep_subject, Source::Csr, "Pasted in the app") {
                        Ok(id) => {
                            self.toast(ui.ctx(), "Signed. Save the certificate (with chain) and copy it to the requesting machine.", true);
                            self.csr.text.clear();
                            self.csr.extra.clear();
                            self.page = Page::Certificates;
                            self.selected = Some(id);
                        }
                        Err(e) => self.toast(ui.ctx(), e, false),
                    }
                    self.mark_dirty(ui.ctx());
                }
            }
        });
        let done: Vec<PendingRequest> = st.requests.iter().filter(|r| r.status != RequestStatus::Pending).cloned().collect();
        if !done.is_empty() {
            ui.add_space(12.0);
            card(ui, p, |ui| {
                card_title(ui, p, "Handled network requests", "");
                egui::Grid::new("done_req").num_columns(5).striped(true).spacing([14.0, 6.0]).show(ui, |ui| {
                    for r in done.iter().rev().take(50) {
                        let issued = r.status == RequestStatus::Issued;
                        pill(ui, if issued { "Issued" } else { "Rejected" }, if issued { p.ok } else { p.bad });
                        ui.label(if r.sans.is_empty() { r.subject.clone() } else { r.sans.join(", ") });
                        muted(ui, p, &r.from_addr);
                        muted(ui, p, fmt_datetime(r.received));
                        if let Some(cid) = &r.cert_id {
                            if ui.link("Open").clicked() {
                                self.page = Page::Certificates;
                                self.selected = Some(cid.clone());
                            }
                        } else {
                            muted(ui, p, &r.note);
                        }
                        ui.end_row();
                    }
                });
                if ui.small_button("Clear handled requests").clicked() {
                    st.requests.retain(|r| r.status == RequestStatus::Pending);
                    self.mark_dirty(ui.ctx());
                }
            });
        }
    }
}
