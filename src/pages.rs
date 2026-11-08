//! The pages of the window: overview, authorities and certificates.

use crate::app::*;
use crate::ca::{self, Export, NameKind};
use crate::model::*;
use crate::theme::{self, card, card_title, field_label, muted, pill, primary, Pal};
use egui::{Align, Align2, CornerRadius, FontId, Layout, RichText, Sense, Stroke, Vec2};

pub fn ca_combo(ui: &mut egui::Ui, st: &Store, salt: &str, sel: &mut Option<String>, none_label: Option<&str>) {
    let current = sel
        .as_deref()
        .and_then(|id| st.authority(id))
        .map(|a| a.name.clone())
        .unwrap_or_else(|| none_label.map(String::from).unwrap_or_else(|| st.default_ca_id().map(|d| st.ca_name(&d)).unwrap_or_else(|| "—".into())));
    egui::ComboBox::from_id_salt(salt).width(260.0).selected_text(current).show_ui(ui, |ui| {
        if let Some(l) = none_label {
            ui.selectable_value(sel, None, l);
        }
        for a in &st.authorities {
            let label = format!("{}  ({})", a.name, a.kind_label());
            ui.selectable_value(sel, Some(a.id.clone()), label);
        }
    });
}

pub fn profile_combo(ui: &mut egui::Ui, salt: &str, v: &mut Profile) {
    egui::ComboBox::from_id_salt(salt).width(260.0).selected_text(v.label()).show_ui(ui, |ui| {
        for pr in Profile::ALL {
            ui.selectable_value(v, pr, pr.label());
        }
    });
}

pub fn key_combo(ui: &mut egui::Ui, salt: &str, v: &mut KeyType) {
    egui::ComboBox::from_id_salt(salt).width(260.0).selected_text(v.label()).show_ui(ui, |ui| {
        for k in KeyType::ALL {
            ui.selectable_value(v, k, k.label()).on_hover_text(k.hint());
        }
    });
}

pub fn days_chips(ui: &mut egui::Ui, days: &mut u32, opts: &[(u32, &str)]) {
    ui.horizontal_wrapped(|ui| {
        ui.add(egui::DragValue::new(days).range(1..=36500).suffix(" days"));
        for (d, l) in opts {
            if ui.selectable_label(*days == *d, *l).clicked() {
                *days = *d;
            }
        }
    });
}

pub fn name_kind_label(k: NameKind) -> &'static str {
    match k {
        NameKind::Dns => "Host name",
        NameKind::Ip => "IP address",
        NameKind::Email => "Email",
        NameKind::Uri => "URI",
    }
}

pub fn reason_combo(ui: &mut egui::Ui, v: &mut Reason) {
    egui::ComboBox::from_id_salt("reason").width(260.0).selected_text(v.label()).show_ui(ui, |ui| {
        for r in Reason::ALL {
            ui.selectable_value(v, r, r.label());
        }
    });
}

pub fn kv(ui: &mut egui::Ui, p: &Pal, k: &str, v: impl Into<String>) {
    ui.label(RichText::new(k).color(p.muted).size(12.5));
    ui.add(egui::Label::new(RichText::new(v.into()).color(p.text)).wrap());
    ui.end_row();
}

impl App {
    pub fn page_ui(&mut self, ui: &mut egui::Ui, st: &mut Store, p: &Pal) {
        match self.page {
            Page::Certificates => self.certificates(ui, st, p),
            _ => {
                egui::ScrollArea::vertical().auto_shrink([false, false]).id_salt(format!("{:?}", self.page)).show(ui, |ui| {
                    ui.set_width(ui.available_width() - 6.0);
                    match self.page {
                        Page::Dashboard => self.dashboard(ui, st, p),
                        Page::Authorities => self.authorities(ui, st, p),
                        Page::Issue => self.issue_page(ui, st, p),
                        Page::Requests => self.requests(ui, st, p),
                        Page::Server => self.server_page(ui, st, p),
                        Page::Revocation => self.revocation(ui, st, p),
                        Page::Activity => self.activity(ui, st, p),
                        Page::Settings => self.settings_page(ui, st, p),
                        Page::Certificates => {}
                    }
                    ui.add_space(20.0);
                });
            }
        }
    }

    // -----------------------------------------------------------------------
    // Overview

    fn welcome(&mut self, ui: &mut egui::Ui, st: &mut Store, p: &Pal) {
        card(ui, p, |ui| {
            ui.horizontal(|ui| {
                theme::logo(ui, p, 54.0);
                ui.vertical(|ui| {
                    ui.label(RichText::new("Welcome! Let's set up your certificate authority").size(20.0).strong());
                    muted(ui, p, "It signs certificates for the devices and services on your network, so browsers trust them without warnings.");
                });
            });
            ui.add_space(14.0);
            ui.columns(3, |cols| {
                let steps = [
                    ("1", "Create the authority", "A root certificate plus an issuing authority, made on this computer. Keys never leave it."),
                    ("2", "Trust it once per device", "Install the root on phones, laptops and servers. The built-in web page walks you through it."),
                    ("3", "Issue certificates", "Create them here, sign requests, or let servers fetch and renew their own with ACME."),
                ];
                for (i, (n, t, d)) in steps.iter().enumerate() {
                    let ui = &mut cols[i];
                    egui::Frame::new().fill(p.card2).corner_radius(CornerRadius::same(10)).inner_margin(egui::Margin::same(14)).show(ui, |ui| ui.with_layout(Layout::top_down(Align::Min), |ui| {
                        ui.set_width(ui.available_width());
                        ui.set_min_height(96.0);
                        ui.horizontal(|ui| {
                            let (r, _) = ui.allocate_exact_size(Vec2::splat(24.0), Sense::hover());
                            ui.painter().circle_filled(r.center(), 12.0, p.accent);
                            ui.painter().text(r.center(), Align2::CENTER_CENTER, *n, FontId::proportional(13.0), p.accent_text);
                            ui.label(RichText::new(*t).strong());
                        });
                        ui.add_space(4.0);
                        ui.add(egui::Label::new(RichText::new(*d).color(p.muted).size(12.5)).wrap());
                    }));
                }
            });
        });
        ui.add_space(12.0);
        card(ui, p, |ui| {
            card_title(ui, p, "Create your authority", "You can change everything later. These defaults suit most home labs.");
            let f = &mut self.ca_form;
            egui::Grid::new("welcome_form").num_columns(2).spacing([16.0, 10.0]).show(ui, |ui| {
                field_label(ui, p, "Name");
                ui.add(egui::TextEdit::singleline(&mut f.name).desired_width(320.0));
                ui.end_row();
                field_label(ui, p, "Organization");
                ui.add(egui::TextEdit::singleline(&mut f.organization).desired_width(320.0).hint_text("e.g. Home Lab"));
                ui.end_row();
                field_label(ui, p, "Key type");
                key_combo(ui, "w_key", &mut f.key_type);
                ui.end_row();
                field_label(ui, p, "Valid for");
                ui.add(egui::DragValue::new(&mut f.years).range(1..=50).suffix(" years"));
                ui.end_row();
                field_label(ui, p, "");
                ui.checkbox(&mut f.with_intermediate, "Also create an issuing (intermediate) authority — recommended");
                ui.end_row();
            });
            ui.add_space(8.0);
            if primary(ui, p, "Create authority").clicked() {
                let f = self.ca_form.clone();
                self.create_ca_job(f, None, st);
            }
        });
    }

    pub fn create_ca_job(&mut self, f: CaForm, parent: Option<String>, st: &Store) {
        let settings = st.settings.clone();
        let label = if f.key_type.is_rsa() { "Creating authority (RSA keys take a moment)…" } else { "Creating authority…" };
        self.spawn(label, move |sh| {
            let mk = |name: &str, kt: KeyType, years: u32, depth: Option<u8>| -> ca::CaSpec {
                ca::CaSpec {
                    name: name.into(),
                    dn: ca::DnSpec {
                        common_name: if f.common_name.trim().is_empty() { name.into() } else { f.common_name.clone() },
                        organization: f.organization.clone(),
                        org_unit: f.org_unit.clone(),
                        locality: settings.locality.clone(),
                        state: settings.state.clone(),
                        country: f.country.clone(),
                    },
                    key_type: kt,
                    years,
                    path_len: depth,
                }
            };
            let key = match ca::generate_key(f.key_type) {
                Ok(k) => k,
                Err(e) => return JobResult { result: Err(e), goto: None },
            };
            let depth = if f.limit_depth { Some(0) } else { None };
            let mut st = sh.store();
            let r = match &parent {
                Some(pid) => st.create_intermediate(pid, &mk(&f.name, f.key_type, f.years, depth), key),
                None => st.create_root(&mk(&f.name, f.key_type, f.years, if f.with_intermediate { Some(1) } else { None }), key),
            };
            let mut result = r.map(|id| (id, format!("Created \"{}\"", f.name.trim())));
            if let (Ok((root_id, _)), None, true) = (&result, &parent, f.with_intermediate) {
                let root_id = root_id.clone();
                drop(st);
                let k2 = ca::generate_key(f.key_type);
                st = sh.store();
                let org = if f.organization.trim().is_empty() { "Home Lab".to_string() } else { f.organization.trim().to_string() };
                let name = format!("{org} Issuing CA");
                let years = (f.years / 2).max(1);
                let r2 = k2.and_then(|k| st.create_intermediate(&root_id, &mk(&name, f.key_type, years, Some(0)), k));
                result = r2.map(|_| (root_id.clone(), format!("Created \"{}\" and \"{name}\"", f.name.trim())));
            }
            sh.save(&st);
            match result {
                Ok((id, msg)) => JobResult { result: Ok(msg), goto: Some((Page::Authorities, Some(id))) },
                Err(e) => JobResult { result: Err(e), goto: None },
            }
        });
    }

    fn dashboard(&mut self, ui: &mut egui::Ui, st: &mut Store, p: &Pal) {
        if st.authorities.is_empty() {
            self.welcome(ui, st, p);
            return;
        }
        let wd = st.settings.warn_days;
        let active = st.certs.iter().filter(|c| matches!(c.status(wd), CertStatus::Valid | CertStatus::Expiring)).count();
        let expiring: Vec<Cert> = {
            let mut v: Vec<Cert> = st.certs.iter().filter(|c| c.status(wd) == CertStatus::Expiring && c.renewed_by.is_none()).cloned().collect();
            v.sort_by_key(|c| c.not_after);
            v
        };
        let revoked = st.certs.iter().filter(|c| c.revoked.is_some()).count();
        let roots = st.authorities.iter().filter(|a| a.is_root()).count();
        let total = st.certs.len();
        let n_auth = st.authorities.len();
        ui.columns(4, |c| {
            theme::stat(&mut c[0], p, "Active certificates", &active.to_string(), &format!("{total} issued in total"), p.ok);
            theme::stat(&mut c[1], p, "Expiring soon", &expiring.len().to_string(), &format!("within {wd} days"), p.warn);
            theme::stat(&mut c[2], p, "Revoked", &revoked.to_string(), "listed for devices", p.bad);
            theme::stat(&mut c[3], p, "Authorities", &n_auth.to_string(), &format!("{roots} root, {} intermediate", n_auth - roots), p.info);
        });
        ui.add_space(12.0);
        let pending = st.pending_requests();
        let mut recent: Vec<Cert> = st.certs.clone();
        recent.sort_by_key(|c| -c.created);
        recent.truncate(8);
        let host = ca::lan_ip().map(|i| i.to_string()).unwrap_or_else(ca::host_name);
        let srv = st.settings.server.clone();
        let default = st.default_ca_id();
        let auths = st.authorities.clone();
        let root = default.as_deref().and_then(|d| st.root_of(d)).map(|a| a.id.clone());
        ui.columns(2, |cols| {
            let (l, r) = cols.split_at_mut(1);
            let l = &mut l[0];
            let r = &mut r[0];
            card(l, p, |ui| {
                card_title(ui, p, "Needs attention", "Certificates running out, oldest first");
                if expiring.is_empty() {
                    ui.horizontal(|ui| {
                        pill(ui, "All good", p.ok);
                        muted(ui, p, "Nothing expires soon.");
                    });
                }
                for c in expiring.iter().take(6) {
                    ui.horizontal(|ui| {
                        pill(ui, "Expiring", p.warn);
                        if ui.link(RichText::new(&c.common_name).strong()).clicked() {
                            self.page = Page::Certificates;
                            self.selected = Some(c.id.clone());
                        }
                        muted(ui, p, format!("{} ({})", fmt_date(c.not_after), relative_days(c.not_after)));
                    });
                }
                if pending > 0 {
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        pill(ui, &format!("{pending} waiting"), p.warn);
                        if ui.link("Signing requests are waiting for your approval").clicked() {
                            self.page = Page::Requests;
                        }
                    });
                }
            });
            l.add_space(12.0);
            card(l, p, |ui| {
                card_title(ui, p, "Recently issued", "");
                if recent.is_empty() {
                    muted(ui, p, "Nothing issued yet.");
                    ui.add_space(4.0);
                    if primary(ui, p, "Create your first certificate").clicked() {
                        self.page = Page::Issue;
                    }
                }
                egui::Grid::new("recent").num_columns(4).spacing([14.0, 8.0]).show(ui, |ui| {
                    for c in &recent {
                        let s = c.status(wd);
                        pill(ui, s.label(), theme::status_color(p, s));
                        if ui.link(&c.common_name).clicked() {
                            self.page = Page::Certificates;
                            self.selected = Some(c.id.clone());
                        }
                        muted(ui, p, c.source.label());
                        muted(ui, p, fmt_date(c.created));
                        ui.end_row();
                    }
                });
            });
            card(r, p, |ui| {
                card_title(ui, p, "Network service", "Lets devices download your root certificate and request their own");
                ui.horizontal(|ui| {
                    let running = self.server.is_some();
                    pill(ui, if running { "Running" } else { "Stopped" }, if running { p.ok } else { p.muted });
                    if running {
                        if ui.button("Stop").clicked() {
                            self.actions.push(Action::StopServer);
                        }
                    } else if primary(ui, p, "Start").clicked() {
                        self.actions.push(Action::StartServer);
                    }
                    if ui.button("Details").clicked() {
                        self.page = Page::Server;
                    }
                });
                if let Some(e) = &self.server_error {
                    ui.label(RichText::new(e).color(p.bad).size(12.5));
                }
                ui.add_space(4.0);
                if srv.http_on {
                    field_label(ui, p, "Device setup page");
                    theme::copy_line(ui, p, &format!("http://{host}:{}/", srv.http_port));
                }
                if srv.acme_on {
                    field_label(ui, p, "ACME directory");
                    let base = if srv.https_on { format!("https://{host}:{}", srv.https_port) } else { format!("http://{host}:{}", srv.http_port) };
                    theme::copy_line(ui, p, &format!("{base}/acme/directory"));
                }
            });
            r.add_space(12.0);
            card(r, p, |ui| {
                card_title(ui, p, "Authorities", "");
                for a in &auths {
                    ui.horizontal(|ui| {
                        pill(ui, a.kind_label(), if a.is_root() { p.info } else { p.accent });
                        if ui.link(RichText::new(&a.name).strong()).clicked() {
                            self.page = Page::Authorities;
                            self.expanded_ca = Some(a.id.clone());
                        }
                        if default.as_deref() == Some(a.id.as_str()) {
                            pill(ui, "Issues by default", p.ok);
                        }
                    });
                    muted(ui, p, format!("{} · valid until {} ({})", a.key_type.label(), fmt_date(a.not_after), relative_days(a.not_after)));
                    ui.add_space(4.0);
                }
            });
            r.add_space(12.0);
            card(r, p, |ui| {
                card_title(ui, p, "Quick actions", "");
                ui.horizontal_wrapped(|ui| {
                    if ui.button("New certificate").clicked() {
                        self.page = Page::Issue;
                    }
                    if ui.button("Sign a request").clicked() {
                        self.page = Page::Requests;
                    }
                    if let Some(root) = &root {
                        if ui.button("Save root certificate…").clicked() {
                            self.save_ca_export(st, root, Export::CertPem);
                        }
                        #[cfg(windows)]
                        if ui.button("Trust root on this PC").clicked() {
                            self.actions.push(Action::InstallTrust(root.clone()));
                        }
                    }
                    if ui.button("Back up everything…").clicked() {
                        self.actions.push(Action::Backup);
                    }
                });
            });
        });
    }

    // -----------------------------------------------------------------------
    // Authorities

    fn authorities(&mut self, ui: &mut egui::Ui, st: &mut Store, p: &Pal) {
        if st.authorities.is_empty() {
            card(ui, p, |ui| {
                card_title(ui, p, "No authorities yet", "Create a root authority, or import one you already have (certificate + private key).");
                if primary(ui, p, "+ New root authority").clicked() {
                    self.dialog = Some(Dialog::NewCa { form: CaForm::new(&st.settings, false), parent: None });
                }
            });
            return;
        }
        // Roots first, then their children right below them.
        fn walk(st: &Store, id: &str, depth: usize, out: &mut Vec<(usize, String)>) {
            if out.iter().any(|(_, x)| x == id) {
                return;
            }
            out.push((depth, id.to_string()));
            for c in st.authorities.iter().filter(|a| a.parent.as_deref() == Some(id)) {
                walk(st, &c.id, depth + 1, out);
            }
        }
        let mut order: Vec<(usize, String)> = vec![];
        for a in st.authorities.iter().filter(|a| a.parent.as_deref().map(|p| st.authority(p).is_none()).unwrap_or(true)) {
            walk(st, &a.id, 0, &mut order);
        }
        let default = st.default_ca_id();
        for (depth, id) in order {
            let Some(a) = st.authority(&id).cloned() else { continue };
            ui.horizontal(|ui| {
                if depth > 0 {
                    ui.add_space(28.0 * depth as f32);
                }
                ui.vertical(|ui| self.authority_card(ui, st, p, &a, default.as_deref() == Some(a.id.as_str())));
            });
            ui.add_space(10.0);
        }
    }

    fn authority_card(&mut self, ui: &mut egui::Ui, st: &mut Store, p: &Pal, a: &Authority, is_default: bool) {
        let issued = st.certs.iter().filter(|c| c.ca_id == a.id).count();
        let active = st.certs.iter().filter(|c| c.ca_id == a.id && matches!(c.status(st.settings.warn_days), CertStatus::Valid | CertStatus::Expiring)).count();
        let expired = now() > a.not_after;
        card(ui, p, |ui| {
            ui.horizontal(|ui| {
                let (r, _) = ui.allocate_exact_size(Vec2::splat(40.0), Sense::hover());
                let col = if a.is_root() { p.info } else { p.accent };
                ui.painter().rect_filled(r, CornerRadius::same(10), col.gamma_multiply(0.2));
                ui.painter().text(r.center(), Align2::CENTER_CENTER, if a.is_root() { "R" } else { "I" }, FontId::proportional(18.0), col);
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&a.name).size(17.0).strong());
                        pill(ui, a.kind_label(), col);
                        if is_default {
                            pill(ui, "Issues by default", p.ok);
                        }
                        if a.imported {
                            pill(ui, "Imported", p.muted);
                        }
                        if a.revoked.is_some() {
                            pill(ui, "Revoked", p.bad);
                        } else if expired {
                            pill(ui, "Expired", p.bad);
                        }
                    });
                    muted(ui, p, &a.subject);
                });
            });
            ui.add_space(8.0);
            let life = (a.not_after - a.not_before).max(1) as f32;
            let used = ((now() - a.not_before) as f32 / life).clamp(0.0, 1.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("{} → {}", fmt_date(a.not_before), fmt_date(a.not_after))).size(13.0));
                muted(ui, p, format!("expires {}", relative_days(a.not_after)));
            });
            ui.add(egui::ProgressBar::new(used).desired_height(5.0).desired_width(ui.available_width().min(520.0)).fill(if used > 0.85 { p.warn } else { p.accent }));
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                muted(ui, p, format!("{} · {issued} issued, {active} active", a.key_type.label()));
                if let Some(pl) = a.path_len {
                    muted(ui, p, if pl == 0 { "· signs certificates only".to_string() } else { format!("· may create {pl} level(s) of sub-authorities") });
                }
                if let Some(par) = &a.parent {
                    muted(ui, p, format!("· signed by {}", st.ca_name(par)));
                }
            });
            ui.add_space(6.0);
            ui.horizontal_wrapped(|ui| {
                if !is_default {
                    let tip = if a.is_root() { "Tip: it's safer to issue from an intermediate and keep the root for signing authorities only" } else { "New certificates are signed by this authority unless you pick another" };
                    if ui.button("Issue by default").on_hover_text(tip).clicked() {
                        st.settings.default_ca = Some(a.id.clone());
                        self.mark_dirty(ui.ctx());
                    }
                }
                ui.menu_button("Save…", |ui| {
                    for (k, label) in [(Export::CertPem, "Certificate (.crt, PEM)"), (Export::CertDer, "Certificate (.cer, for Windows)"), (Export::ChainPem, "Chain up to the root (.pem)")] {
                        if ui.button(label).clicked() {
                            self.save_ca_export(st, &a.id, k);
                            ui.close();
                        }
                    }
                    ui.separator();
                    if ui.button(RichText::new("Private key (.key) — sensitive").color(p.warn)).clicked() {
                        self.save_ca_export(st, &a.id, Export::KeyPem);
                        ui.close();
                    }
                    if ui.button(RichText::new("PFX with key — sensitive").color(p.warn)).clicked() {
                        self.save_ca_export(st, &a.id, Export::Pfx);
                        ui.close();
                    }
                });
                #[cfg(windows)]
                if a.is_root() && ui.button("Trust on this PC").on_hover_text("Adds the root to your Windows trust store; Windows asks to confirm").clicked() {
                    self.actions.push(Action::InstallTrust(a.id.clone()));
                }
                if a.path_len != Some(0) && a.revoked.is_none() && ui.button("+ Sub-authority").clicked() {
                    let mut f = CaForm::new(&st.settings, true);
                    f.key_type = a.key_type;
                    self.dialog = Some(Dialog::NewCa { form: f, parent: Some(a.id.clone()) });
                }
                if a.revoked.is_none() && ui.button("Issue certificate").clicked() {
                    self.issue.ca_id = Some(a.id.clone());
                    self.page = Page::Issue;
                }
                let open = self.expanded_ca.as_deref() == Some(a.id.as_str());
                if ui.selectable_label(open, "Details").clicked() {
                    self.expanded_ca = if open { None } else { Some(a.id.clone()) };
                }
                if !a.is_root() && a.parent.is_some() && a.revoked.is_none() && ui.button(RichText::new("Revoke…").color(p.bad)).clicked() {
                    self.dialog = Some(Dialog::RevokeCa { id: a.id.clone(), reason: Reason::CessationOfOperation });
                }
                if ui.button(RichText::new("Delete…").color(p.bad)).clicked() {
                    self.dialog = Some(Dialog::DeleteCa { id: a.id.clone() });
                }
            });
            if self.expanded_ca.as_deref() == Some(a.id.as_str()) {
                ui.add_space(8.0);
                ui.separator();
                if let Ok(d) = ca::cert_details(&a.cert_pem) {
                    egui::Grid::new(format!("cad{}", a.id)).num_columns(2).spacing([16.0, 6.0]).show(ui, |ui| {
                        kv(ui, p, "Subject", &d.subject);
                        kv(ui, p, "Issuer", &d.issuer);
                        kv(ui, p, "Serial", &d.serial);
                        kv(ui, p, "Signature", &d.sig_alg);
                        kv(ui, p, "Key", &d.key_desc);
                        kv(ui, p, "Constraints", &d.basic);
                        kv(ui, p, "Key usage", &d.key_usage);
                        kv(ui, p, "Key ID", &d.ski);
                        kv(ui, p, "SHA-256", &d.sha256);
                        kv(ui, p, "SHA-1", &d.sha1);
                        if let Some(crl) = st.cdp_url(&a.id) {
                            kv(ui, p, "Revocation list", crl);
                        }
                    });
                }
                ui.add_space(6.0);
                field_label(ui, p, "Notes");
                let mut notes = a.notes.clone();
                if ui.add(egui::TextEdit::multiline(&mut notes).desired_rows(2).desired_width(f32::INFINITY)).changed() {
                    if let Some(x) = st.authority_mut(&a.id) {
                        x.notes = notes;
                    }
                    self.mark_dirty(ui.ctx());
                }
                ui.collapsing("Certificate text (PEM)", |ui| {
                    let mut t = a.cert_pem.clone();
                    ui.add(egui::TextEdit::multiline(&mut t).font(egui::TextStyle::Monospace).desired_width(f32::INFINITY).desired_rows(8));
                    if ui.button("Copy").clicked() {
                        ui.ctx().copy_text(a.cert_pem.clone());
                    }
                });
            }
        });
    }

    // -----------------------------------------------------------------------
    // Certificates

    fn certificates(&mut self, ui: &mut egui::Ui, st: &mut Store, p: &Pal) {
        let wd = st.settings.warn_days;
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.search).hint_text("Search names, serials, notes…").desired_width(260.0));
            let labels = ["All", "Active", "Expiring", "Expired", "Revoked", "Replaced"];
            for (i, l) in labels.iter().enumerate() {
                if ui.selectable_label(self.status_filter == i, *l).clicked() {
                    self.status_filter = i;
                }
            }
            ui.add_space(8.0);
            ca_combo(ui, st, "cert_ca_filter", &mut self.ca_filter, Some("All authorities"));
        });
        ui.add_space(8.0);
        let q = self.search.to_lowercase();
        let mut list: Vec<Cert> = st
            .certs
            .iter()
            .filter(|c| {
                let s = c.status(wd);
                let ok_status = match self.status_filter {
                    1 => matches!(s, CertStatus::Valid | CertStatus::Expiring | CertStatus::NotYetValid) && c.renewed_by.is_none(),
                    2 => s == CertStatus::Expiring,
                    3 => s == CertStatus::Expired,
                    4 => matches!(s, CertStatus::Revoked | CertStatus::OnHold),
                    5 => c.renewed_by.is_some(),
                    _ => true,
                };
                let ok_ca = self.ca_filter.as_deref().map(|f| f == c.ca_id).unwrap_or(true);
                let ok_q = q.is_empty()
                    || c.common_name.to_lowercase().contains(&q)
                    || c.sans.iter().any(|s| s.to_lowercase().contains(&q))
                    || c.serial.contains(&q)
                    || c.notes.to_lowercase().contains(&q)
                    || c.requested_by.to_lowercase().contains(&q);
                ok_status && ok_ca && ok_q
            })
            .cloned()
            .collect();
        list.sort_by_key(|c| -c.created);

        if self.selected.as_deref().map(|s| st.cert(s).is_none()).unwrap_or(false) {
            self.selected = None;
        }
        if let Some(sel) = self.selected.clone() {
            egui::Panel::right("cert_detail")
                .default_size(450.0)
                .size_range(360.0..=660.0)
                .show_separator_line(false)
                .frame(egui::Frame::new().fill(p.bg).inner_margin(egui::Margin { left: 14, right: 0, top: 0, bottom: 0 }))
                .show(ui, |ui| {
                    egui::ScrollArea::vertical().id_salt("detail_scroll").auto_shrink([false, false]).show(ui, |ui| self.cert_detail(ui, st, p, &sel));
                });
        }
        egui::CentralPanel::default().frame(egui::Frame::new()).show(ui, |ui| {
            if st.certs.is_empty() {
                card(ui, p, |ui| {
                    card_title(ui, p, "No certificates yet", "Create one here, sign a request from another machine, or turn on the network service so servers can fetch their own.");
                    ui.horizontal(|ui| {
                        if primary(ui, p, "+ New certificate").clicked() {
                            self.page = Page::Issue;
                        }
                        if ui.button("Sign a request").clicked() {
                            self.page = Page::Requests;
                        }
                    });
                });
                return;
            }
            self.cert_table(ui, st, p, &list);
        });
    }

    fn cert_table(&mut self, ui: &mut egui::Ui, st: &Store, p: &Pal, list: &[Cert]) {
        let wd = st.settings.warn_days;
        let w = ui.available_width();
        let cols = [0.0, 0.14, 0.46, 0.68, 0.85];
        let heads = ["Status", "Name", "Authority", "Expires", "Source"];
        let (hr, _) = ui.allocate_exact_size(Vec2::new(w, 26.0), Sense::hover());
        for (i, h) in heads.iter().enumerate() {
            ui.painter().text(egui::pos2(hr.min.x + 12.0 + cols[i] * w, hr.center().y), Align2::LEFT_CENTER, *h, FontId::proportional(12.0), p.muted);
        }
        ui.painter().line_segment([hr.left_bottom(), hr.right_bottom()], Stroke::new(1.0, p.border));
        if list.is_empty() {
            ui.add_space(14.0);
            muted(ui, p, "No certificates match the filter.");
            return;
        }
        egui::ScrollArea::vertical().id_salt("cert_rows").auto_shrink([false, false]).show(ui, |ui| {
            for c in list {
                let (r, resp) = ui.allocate_exact_size(Vec2::new(w, 50.0), Sense::click());
                let selected = self.selected.as_deref() == Some(c.id.as_str());
                if selected {
                    ui.painter().rect_filled(r, CornerRadius::same(8), p.accent.gamma_multiply(0.14));
                } else if resp.hovered() {
                    ui.painter().rect_filled(r, CornerRadius::same(8), p.card2);
                }
                let s = c.status(wd);
                let pn = ui.painter();
                let replaced = c.renewed_by.is_some() && c.revoked.is_none();
                let label = if replaced { "Replaced" } else { s.label() };
                let pcol = if replaced { p.muted } else { theme::status_color(p, s) };
                let g = pn.layout_no_wrap(label.to_string(), FontId::proportional(11.5), pcol);
                let pr = egui::Rect::from_min_size(egui::pos2(r.min.x + 12.0, r.center().y - 10.0), g.size() + Vec2::new(14.0, 6.0));
                pn.rect_filled(pr, CornerRadius::same(255), pcol.gamma_multiply(0.16));
                pn.galley(pr.center() - g.size() / 2.0, g, pcol);
                let cell = |i: usize| {
                    let right = if i + 1 < cols.len() { cols[i + 1] * w - 8.0 } else { w };
                    egui::Rect::from_min_max(egui::pos2(r.min.x + 12.0 + cols[i] * w, r.min.y), egui::pos2(r.min.x + right, r.max.y))
                };
                let c1 = pn.with_clip_rect(cell(1));
                c1.text(egui::pos2(cell(1).min.x, r.center().y - 8.0), Align2::LEFT_CENTER, &c.common_name, FontId::proportional(14.0), p.text);
                let others: Vec<&str> = c.sans.iter().filter(|s| **s != c.common_name).map(|s| s.as_str()).collect();
                let sub = if others.is_empty() { c.profile.short().to_string() } else { format!("{} · {}", c.profile.short(), others.join(", ")) };
                c1.text(egui::pos2(cell(1).min.x, r.center().y + 10.0), Align2::LEFT_CENTER, sub, FontId::proportional(12.0), p.muted);
                pn.with_clip_rect(cell(2)).text(egui::pos2(cell(2).min.x, r.center().y), Align2::LEFT_CENTER, st.ca_name(&c.ca_id), FontId::proportional(13.0), p.text);
                let c3 = pn.with_clip_rect(cell(3));
                c3.text(egui::pos2(cell(3).min.x, r.center().y - 8.0), Align2::LEFT_CENTER, fmt_date(c.not_after), FontId::proportional(13.0), p.text);
                c3.text(egui::pos2(cell(3).min.x, r.center().y + 10.0), Align2::LEFT_CENTER, relative_days(c.not_after), FontId::proportional(12.0), if s == CertStatus::Expiring { p.warn } else { p.muted });
                pn.with_clip_rect(cell(4)).text(egui::pos2(cell(4).min.x, r.center().y), Align2::LEFT_CENTER, c.source.label(), FontId::proportional(12.5), p.muted);
                if resp.clicked() {
                    self.selected = if selected { None } else { Some(c.id.clone()) };
                }
                if resp.hovered() {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                }
            }
        });
    }

    fn cert_detail(&mut self, ui: &mut egui::Ui, st: &mut Store, p: &Pal, id: &str) {
        let Some(c) = st.cert(id).cloned() else { return };
        let s = c.status(st.settings.warn_days);
        card(ui, p, |ui| {
            ui.horizontal(|ui| {
                ui.add(egui::Label::new(RichText::new(&c.common_name).size(18.0).strong()).wrap());
                ui.with_layout(Layout::right_to_left(Align::Min), |ui| {
                    if ui.small_button("✕").on_hover_text("Close").clicked() {
                        self.selected = None;
                    }
                });
            });
            ui.horizontal_wrapped(|ui| {
                pill(ui, s.label(), theme::status_color(p, s));
                pill(ui, c.profile.short(), p.info);
                pill(ui, c.key_type.label(), p.muted);
                if c.key_pem.is_none() {
                    pill(ui, "Key held by requester", p.muted);
                }
            });
            if let Some(r) = &c.revoked {
                ui.label(RichText::new(format!("Revoked {} — {}", fmt_datetime(r.at), r.reason.label())).color(p.bad));
            }
            if let Some(n) = &c.renewed_by {
                ui.horizontal(|ui| {
                    muted(ui, p, "Replaced by a newer certificate.");
                    if ui.link("Open it").clicked() {
                        self.selected = Some(n.clone());
                    }
                });
            }
            ui.add_space(6.0);
            ui.horizontal_wrapped(|ui| {
                ui.menu_button("Save…", |ui| {
                    for k in [Export::CertPem, Export::ChainPem, Export::CertDer, Export::FullChainPem, Export::KeyPem, Export::BundlePem, Export::Pfx] {
                        let enabled = !k.needs_key() || c.key_pem.is_some();
                        if ui.add_enabled(enabled, egui::Button::new(k.label())).clicked() {
                            self.save_cert_export(st, &c.id, k);
                            ui.close();
                        }
                    }
                });
                if ui.button("Renew…").clicked() {
                    let days = (((c.not_after - c.not_before) / 86_400) as u32).max(1);
                    self.dialog = Some(Dialog::Renew { id: c.id.clone(), new_key: c.key_pem.is_some(), days, supersede: false });
                }
                match c.revoked.as_ref().map(|r| r.reason) {
                    Some(Reason::CertificateHold) => {
                        if ui.button("Release hold").clicked() {
                            match st.release_hold(&c.id) {
                                Ok(()) => self.toast(ui.ctx(), "Hold released; the certificate works again", true),
                                Err(e) => self.toast(ui.ctx(), e, false),
                            }
                            self.mark_dirty(ui.ctx());
                        }
                        if ui.button(RichText::new("Revoke…").color(p.bad)).clicked() {
                            self.dialog = Some(Dialog::Revoke { id: c.id.clone(), reason: Reason::Unspecified });
                        }
                    }
                    Some(_) => {}
                    None => {
                        if ui.button(RichText::new("Revoke…").color(p.bad)).clicked() {
                            self.dialog = Some(Dialog::Revoke { id: c.id.clone(), reason: Reason::Unspecified });
                        }
                    }
                }
                if ui.button(RichText::new("Delete…").color(p.bad)).clicked() {
                    self.dialog = Some(Dialog::DeleteCert { id: c.id.clone() });
                }
            });
        });
        ui.add_space(10.0);
        let d = ca::cert_details(&c.cert_pem).unwrap_or_default();
        card(ui, p, |ui| {
            card_title(ui, p, "Details", "");
            egui::Grid::new("cert_kv").num_columns(2).spacing([14.0, 7.0]).min_col_width(90.0).show(ui, |ui| {
                kv(ui, p, "Names", if d.sans.is_empty() { "—".to_string() } else { d.sans.join("\n") });
                kv(ui, p, "Valid", format!("{}  →  {}\n{}", fmt_datetime(c.not_before), fmt_datetime(c.not_after), relative_days(c.not_after)));
                let chain: Vec<String> = st.ca_chain(&c.ca_id).iter().map(|a| a.name.clone()).collect();
                kv(ui, p, "Signed by", if chain.is_empty() { "(authority deleted)".into() } else { chain.join("  ←  ") });
                kv(ui, p, "Subject", &d.subject);
                kv(ui, p, "Purpose", if d.ext_key_usage.is_empty() { "—".into() } else { d.ext_key_usage.clone() });
                kv(ui, p, "Key usage", &d.key_usage);
                kv(ui, p, "Key", &d.key_desc);
                kv(ui, p, "Signature", &d.sig_alg);
                kv(ui, p, "Serial", &d.serial);
                kv(ui, p, "Source", format!("{}{}", c.source.label(), if c.requested_by.is_empty() { String::new() } else { format!(" — {}", c.requested_by) }));
                kv(ui, p, "Created", fmt_datetime(c.created));
                if !d.crl_urls.is_empty() {
                    kv(ui, p, "Revocation list", d.crl_urls.join("\n"));
                }
                kv(ui, p, "SHA-256", &d.sha256);
                kv(ui, p, "SHA-1", &d.sha1);
            });
            ui.add_space(6.0);
            field_label(ui, p, "Notes");
            let mut notes = c.notes.clone();
            if ui.add(egui::TextEdit::multiline(&mut notes).desired_rows(2).desired_width(f32::INFINITY).hint_text("Where is it installed? Who owns it?")).changed() {
                if let Some(x) = st.cert_mut(&c.id) {
                    x.notes = notes;
                }
                self.mark_dirty(ui.ctx());
            }
        });
        ui.add_space(10.0);
        card(ui, p, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Certificate text (PEM)").strong());
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.small_button("Copy with chain").clicked() {
                        ui.ctx().copy_text(c.cert_pem.trim().to_string() + "\n" + &st.chain_pem(&c.ca_id, false));
                        self.toast(ui.ctx(), "Copied certificate and chain", true);
                    }
                    if ui.small_button("Copy").clicked() {
                        ui.ctx().copy_text(c.cert_pem.clone());
                        self.toast(ui.ctx(), "Copied certificate", true);
                    }
                    if ui.small_button(if self.show_pem { "Hide" } else { "Show" }).clicked() {
                        self.show_pem = !self.show_pem;
                    }
                });
            });
            if self.show_pem {
                let mut t = c.cert_pem.clone();
                ui.add(egui::TextEdit::multiline(&mut t).font(egui::TextStyle::Monospace).desired_width(f32::INFINITY).desired_rows(10));
            }
        });
    }
}
