//! Pages: network service, revocation, activity log, settings.

use crate::app::*;
use crate::ca::{self, Export};
use crate::model::*;
use crate::pages::*;
use crate::theme::{self, card, card_title, field_label, muted, pill, primary, Pal};
use egui::{CornerRadius, RichText, Sense, Vec2};

impl App {
    pub fn server_page(&mut self, ui: &mut egui::Ui, st: &mut Store, p: &Pal) {
        let host = ca::lan_ip().map(|i| i.to_string()).unwrap_or_else(ca::host_name);
        let running = self.server.is_some();
        let mut changed = false;
        card(ui, p, |ui| {
            ui.horizontal(|ui| {
                let (r, _) = ui.allocate_exact_size(Vec2::splat(14.0), Sense::hover());
                ui.painter().circle_filled(r.center(), 7.0, if running { p.ok } else { p.muted });
                ui.label(RichText::new(if running { "Running" } else { "Stopped" }).size(18.0).strong());
                if let Some(s) = &self.server {
                    muted(ui, p, format!("since {} · {} requests served", fmt_datetime(s.started), s.requests.load(std::sync::atomic::Ordering::Relaxed)));
                }
            });
            if let Some(e) = &self.server_error {
                ui.label(RichText::new(e).color(p.bad));
            }
            if st.authorities.is_empty() {
                muted(ui, p, "Create an authority first — the service hands out its root certificate.");
            }
            ui.add_space(6.0);
            card_title(ui, p, "Addresses for your devices", "Share these on your network (Wi-Fi, LAN). Copy and paste them on the device.");
            let s = &st.settings.server;
            let http = format!("http://{host}:{}", s.http_port);
            let https = format!("https://{host}:{}", s.https_port);
            egui::Grid::new("addr").num_columns(2).spacing([16.0, 6.0]).show(ui, |ui| {
                if s.http_on {
                    field_label(ui, p, "Setup page (start here)");
                    theme::copy_line(ui, p, &format!("{http}/"));
                    ui.end_row();
                    field_label(ui, p, "Root certificate");
                    theme::copy_line(ui, p, &format!("{http}/ca.crt"));
                    ui.end_row();
                    field_label(ui, p, "iPhone / iPad profile");
                    theme::copy_line(ui, p, &format!("{http}/ca.mobileconfig"));
                    ui.end_row();
                    field_label(ui, p, "Revocation list");
                    theme::copy_line(ui, p, &format!("{http}/crl.crl"));
                    ui.end_row();
                }
                if s.acme_on {
                    field_label(ui, p, "ACME directory");
                    theme::copy_line(ui, p, &format!("{}/acme/directory", if s.https_on { &https } else { &http }));
                    ui.end_row();
                }
                if s.enroll_on {
                    field_label(ui, p, "Enrollment (token)");
                    theme::copy_line(ui, p, &format!("{http}/api/enroll?token=…"));
                    ui.end_row();
                }
            });
            if running && s.http_on {
                ui.add_space(4.0);
                ui.hyperlink_to("Open the setup page in your browser", format!("http://127.0.0.1:{}/", s.http_port));
            }
        });
        ui.add_space(12.0);
        ui.columns(2, |cols| {
            let (l, r) = cols.split_at_mut(1);
            let l = &mut l[0];
            let r = &mut r[0];
            card(l, p, |ui| {
                let s = &mut st.settings.server;
                card_title(ui, p, "Connection", "Changes apply when the service is (re)started");
                egui::Grid::new("conn").num_columns(2).spacing([16.0, 10.0]).show(ui, |ui| {
                    field_label(ui, p, "Listen on");
                    ui.vertical(|ui| {
                        changed |= ui.add(egui::TextEdit::singleline(&mut s.bind).desired_width(160.0)).changed();
                        muted(ui, p, "0.0.0.0 = every network; 127.0.0.1 = this PC only");
                    });
                    ui.end_row();
                    field_label(ui, p, "Plain address (HTTP)");
                    ui.horizontal(|ui| {
                        changed |= ui.checkbox(&mut s.http_on, "").changed();
                        changed |= ui.add_enabled(s.http_on, egui::DragValue::new(&mut s.http_port).range(1..=65535).prefix("port ")).changed();
                    });
                    ui.end_row();
                    field_label(ui, p, "Secure address (HTTPS)");
                    ui.horizontal(|ui| {
                        changed |= ui.checkbox(&mut s.https_on, "").changed();
                        changed |= ui.add_enabled(s.https_on, egui::DragValue::new(&mut s.https_port).range(1..=65535).prefix("port ")).changed();
                    });
                    ui.end_row();
                    field_label(ui, p, "");
                    changed |= ui.checkbox(&mut s.autostart, "Start automatically when LabCert opens").changed();
                    ui.end_row();
                    field_label(ui, p, "");
                    changed |= ui.checkbox(&mut s.publish_certs, "Publish issued certificates (no keys) at /certs").changed();
                    ui.end_row();
                });
                muted(ui, p, "The secure address uses a certificate from your own authority, so devices must trust the root first. Windows may ask to allow LabCert through the firewall.");
            });
            l.add_space(12.0);
            card(l, p, |ui| {
                card_title(ui, p, "Automatic certificates (ACME)", "certbot, acme.sh, Caddy, Traefik, Home Assistant, pfSense and others can request and renew on their own");
                let s = &mut st.settings.server;
                changed |= ui.checkbox(&mut s.acme_on, "Offer ACME").changed();
                ui.add_enabled_ui(s.acme_on, |ui| {
                    changed |= ui.radio_value(&mut s.acme_auto_approve, false, "Check ownership (http-01 on port 80) — safer").changed();
                    changed |= ui.radio_value(&mut s.acme_auto_approve, true, "Lab mode: approve every request without checking (allows wildcards)").changed();
                    egui::Grid::new("acme").num_columns(2).spacing([16.0, 10.0]).show(ui, |ui| {
                        field_label(ui, p, "Valid for");
                        changed |= ui.add(egui::DragValue::new(&mut s.acme_days).range(1..=825).suffix(" days")).changed();
                        ui.end_row();
                    });
                });
                let mut acme_ca = st.settings.server.acme_ca.clone();
                ui.horizontal(|ui| {
                    field_label(ui, p, "Signed by");
                    ca_combo(ui, st, "acme_ca", &mut acme_ca, Some("Default authority"));
                });
                if acme_ca != st.settings.server.acme_ca {
                    st.settings.server.acme_ca = acme_ca;
                    changed = true;
                }
                let sum = self.acme.summary();
                ui.add_space(6.0);
                muted(ui, p, format!("{} accounts · {} orders since start ({} open)", st.acme_accounts.len(), sum.orders, sum.pending));
                if !st.acme_accounts.is_empty() {
                    ui.collapsing("Accounts", |ui| {
                        let mut deact = None;
                        egui::Grid::new("accts").num_columns(4).striped(true).spacing([12.0, 6.0]).show(ui, |ui| {
                            for a in &st.acme_accounts {
                                pill(ui, &a.status, if a.status == "valid" { p.ok } else { p.muted });
                                ui.label(if a.contact.is_empty() { format!("Account {}", a.id) } else { a.contact.join(", ").replace("mailto:", "") });
                                muted(ui, p, format!("{} orders · seen {}", a.orders, fmt_datetime(a.last_seen)));
                                if a.status == "valid" && ui.small_button("Block").clicked() {
                                    deact = Some(a.id.clone());
                                }
                                ui.end_row();
                            }
                        });
                        if let Some(id) = deact {
                            if let Some(a) = st.acme_accounts.iter_mut().find(|a| a.id == id) {
                                a.status = "deactivated".into();
                            }
                            changed = true;
                        }
                    });
                }
            });
            card(r, p, |ui| {
                card_title(ui, p, "Enrollment tokens", "Give a token to a machine so it can send a signing request over the network");
                changed |= ui.checkbox(&mut st.settings.server.enroll_on, "Accept requests with a token").changed();
                ui.add_space(4.0);
                if st.tokens.is_empty() {
                    muted(ui, p, "No tokens yet.");
                }
                let mut remove = None;
                let mut toggle = None;
                for t in &st.tokens {
                    egui::Frame::new().fill(p.card2).corner_radius(CornerRadius::same(8)).inner_margin(egui::Margin::same(10)).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(&t.label).strong());
                            if t.usable() {
                                pill(ui, "Active", p.ok);
                            } else {
                                pill(ui, if t.disabled { "Disabled" } else { "Used up / expired" }, p.muted);
                            }
                            pill(ui, if t.auto_approve { "Signs immediately" } else { "Needs approval" }, if t.auto_approve { p.warn } else { p.info });
                        });
                        muted(ui, p, format!(
                            "{} · {} days · used {}{} · {}",
                            t.profile.short(),
                            t.validity_days,
                            t.uses,
                            t.max_uses.map(|m| format!(" of {m}")).unwrap_or_default(),
                            t.expires.map(|e| format!("expires {}", fmt_date(e))).unwrap_or_else(|| "no expiry".into())
                        ));
                        ui.horizontal(|ui| {
                            if ui.small_button("Copy token").clicked() {
                                ui.ctx().copy_text(t.secret.clone());
                                self.toast(ui.ctx(), "Token copied", true);
                            }
                            if ui.small_button("Copy curl command").clicked() {
                                let port = st.settings.server.http_port;
                                ui.ctx().copy_text(format!("curl --data-binary @host.csr \"http://{host}:{port}/api/enroll?token={}\" -o host.crt", t.secret));
                                self.toast(ui.ctx(), "Command copied", true);
                            }
                            if ui.small_button(if t.disabled { "Enable" } else { "Disable" }).clicked() {
                                toggle = Some(t.id.clone());
                            }
                            if ui.small_button("Delete").clicked() {
                                remove = Some(t.id.clone());
                            }
                        });
                    });
                    ui.add_space(4.0);
                }
                if let Some(id) = toggle {
                    if let Some(t) = st.tokens.iter_mut().find(|t| t.id == id) {
                        t.disabled = !t.disabled;
                    }
                    changed = true;
                }
                if let Some(id) = remove {
                    st.tokens.retain(|t| t.id != id);
                    changed = true;
                }
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    if primary(ui, p, "+ New token").clicked() {
                        self.dialog = Some(Dialog::NewToken(TokenForm { label: String::new(), profile: Profile::Server, days: 365, auto_approve: false, max_uses: 1, limit_uses: true, expires_days: 7, expires: true, ca_id: None }));
                    }
                });
            });
            r.add_space(12.0);
            card(r, p, |ui| {
                card_title(ui, p, "Recent requests", "Live view of what devices ask for");
                let log: Vec<HttpLog> = self.shared.http_log.lock().map(|l| l.iter().rev().take(40).cloned().collect()).unwrap_or_default();
                if log.is_empty() {
                    muted(ui, p, if running { "Nothing yet. Open the setup page from another device." } else { "Start the service to see requests here." });
                }
                egui::Grid::new("httplog").num_columns(4).spacing([10.0, 4.0]).show(ui, |ui| {
                    for e in log {
                        muted(ui, p, fmt_time(e.ts));
                        let col = if e.status < 300 { p.ok } else if e.status < 500 { p.warn } else { p.bad };
                        pill(ui, &e.status.to_string(), col);
                        ui.label(RichText::new(format!("{} {}", e.method, e.path)).monospace().size(12.0));
                        muted(ui, p, format!("{}{}", e.remote, if e.tls { " · TLS" } else { "" }));
                        ui.end_row();
                    }
                });
            });
        });
        if changed {
            self.mark_dirty(ui.ctx());
        }
    }

    pub fn revocation(&mut self, ui: &mut egui::Ui, st: &mut Store, p: &Pal) {
        if st.authorities.is_empty() {
            card(ui, p, |ui| card_title(ui, p, "Nothing here yet", "Revocation lists appear once you have an authority."));
            return;
        }
        card(ui, p, |ui| {
            card_title(ui, p, "How revocation works", "");
            ui.add(egui::Label::new(RichText::new("When you revoke a certificate it's added to its authority's revocation list (CRL). Devices that check the list stop trusting it. Lists are re-signed automatically before they run out.").color(p.muted)).wrap());
            if st.settings.public_host.trim().is_empty() {
                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    pill(ui, "Tip", p.info);
                    ui.label("Set this computer's network name in Settings so new certificates tell devices where the list is.");
                    if ui.link("Open Settings").clicked() {
                        self.page = Page::Settings;
                    }
                });
            }
        });
        ui.add_space(12.0);
        let ids: Vec<String> = st.authorities.iter().map(|a| a.id.clone()).collect();
        for id in ids {
            let Some(a) = st.authority(&id).cloned() else { continue };
            let summary = a.crl_pem.as_deref().and_then(|c| ca::crl_summary(c).ok());
            card(ui, p, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&a.name).size(16.0).strong());
                    pill(ui, a.kind_label(), if a.is_root() { p.info } else { p.accent });
                });
                match &summary {
                    Some(s) => {
                        muted(ui, p, format!(
                            "List #{} · {} entries · published {} · valid until {}",
                            a.crl_number,
                            s.entries,
                            fmt_datetime(s.this_update),
                            s.next_update.map(fmt_datetime).unwrap_or_else(|| "—".into())
                        ));
                    }
                    None => {
                        muted(ui, p, "No list published yet.");
                    }
                }
                if let Some(url) = st.cdp_url(&a.id) {
                    ui.horizontal(|ui| {
                        field_label(ui, p, "Address in certificates");
                        theme::copy_line(ui, p, &url);
                    });
                }
                ui.horizontal(|ui| {
                    if ui.button("Publish a new list now").clicked() {
                        match st.regen_crl(&a.id) {
                            Ok(()) => self.toast(ui.ctx(), format!("New revocation list for \"{}\"", a.name), true),
                            Err(e) => self.toast(ui.ctx(), e, false),
                        }
                        self.mark_dirty(ui.ctx());
                    }
                    if let Some(c) = &a.crl_pem {
                        if ui.button("Save .crl").clicked() {
                            self.actions.push(Action::SaveFile { name: format!("{}.crl", a.name.replace(' ', "_")), bytes: ca::pem_to_der(c) });
                        }
                        if ui.button("Save .pem").clicked() {
                            self.actions.push(Action::SaveFile { name: format!("{}.crl.pem", a.name.replace(' ', "_")), bytes: Ok(c.clone().into_bytes()) });
                        }
                    }
                });
            });
            ui.add_space(10.0);
        }
        let revoked: Vec<Cert> = st.certs.iter().filter(|c| c.revoked.is_some()).cloned().collect();
        let revoked_cas: Vec<Authority> = st.authorities.iter().filter(|a| a.revoked.is_some()).cloned().collect();
        card(ui, p, |ui| {
            card_title(ui, p, "Revoked", "");
            if revoked.is_empty() && revoked_cas.is_empty() {
                muted(ui, p, "Nothing has been revoked.");
            }
            egui::Grid::new("revoked").num_columns(5).striped(true).spacing([14.0, 6.0]).show(ui, |ui| {
                for a in &revoked_cas {
                    let r = a.revoked.clone().unwrap_or_default();
                    pill(ui, "Authority", p.bad);
                    ui.label(&a.name);
                    muted(ui, p, fmt_datetime(r.at));
                    muted(ui, p, r.reason.label());
                    ui.label("");
                    ui.end_row();
                }
                for c in &revoked {
                    let r = c.revoked.clone().unwrap_or_default();
                    let hold = r.reason == Reason::CertificateHold;
                    pill(ui, if hold { "On hold" } else { "Revoked" }, if hold { p.hold } else { p.bad });
                    if ui.link(&c.common_name).clicked() {
                        self.page = Page::Certificates;
                        self.selected = Some(c.id.clone());
                    }
                    muted(ui, p, fmt_datetime(r.at));
                    muted(ui, p, r.reason.label());
                    if hold {
                        if ui.small_button("Release hold").clicked() {
                            match st.release_hold(&c.id) {
                                Ok(()) => self.toast(ui.ctx(), "Hold released", true),
                                Err(e) => self.toast(ui.ctx(), e, false),
                            }
                            self.mark_dirty(ui.ctx());
                        }
                    } else {
                        muted(ui, p, format!("serial {}", &c.serial[..c.serial.len().min(12)]));
                    }
                    ui.end_row();
                }
            });
        });
    }

    pub fn activity(&mut self, ui: &mut egui::Ui, st: &mut Store, p: &Pal) {
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.log_search).hint_text("Search the log…").desired_width(260.0));
            for (k, l) in [(None, "All"), (Some(LogKind::Success), "Done"), (Some(LogKind::Info), "Info"), (Some(LogKind::Warn), "Warnings"), (Some(LogKind::Error), "Errors")] {
                if ui.selectable_label(self.log_kind == k, l).clicked() {
                    self.log_kind = k;
                }
            }
        });
        ui.add_space(8.0);
        let q = self.log_search.to_lowercase();
        let entries: Vec<&LogEntry> = st
            .log
            .iter()
            .rev()
            .filter(|e| self.log_kind.map(|k| k == e.kind).unwrap_or(true))
            .filter(|e| q.is_empty() || e.msg.to_lowercase().contains(&q) || e.category.contains(&q))
            .take(500)
            .collect();
        card(ui, p, |ui| {
            if entries.is_empty() {
                muted(ui, p, "Nothing recorded yet.");
            }
            let mut last_day = String::new();
            for e in entries {
                let day = fmt_date(e.ts);
                if day != last_day {
                    ui.add_space(4.0);
                    ui.label(RichText::new(&day).strong().size(12.5).color(p.muted));
                    last_day = day;
                }
                ui.horizontal(|ui| {
                    let col = match e.kind {
                        LogKind::Success => p.ok,
                        LogKind::Info => p.info,
                        LogKind::Warn => p.warn,
                        LogKind::Error => p.bad,
                    };
                    let (r, _) = ui.allocate_exact_size(Vec2::splat(10.0), Sense::hover());
                    ui.painter().circle_filled(r.center(), 4.0, col);
                    muted(ui, p, fmt_time(e.ts));
                    pill(ui, &e.category, p.muted);
                    ui.add(egui::Label::new(&e.msg).wrap());
                });
            }
        });
    }

    pub fn settings_page(&mut self, ui: &mut egui::Ui, st: &mut Store, p: &Pal) {
        let mut changed = false;
        ui.columns(2, |cols| {
            let (l, r) = cols.split_at_mut(1);
            let l = &mut l[0];
            let r = &mut r[0];
            card(l, p, |ui| {
                card_title(ui, p, "Certificate defaults", "Pre-filled on every new certificate");
                let s = &mut st.settings;
                egui::Grid::new("defaults").num_columns(2).spacing([16.0, 10.0]).show(ui, |ui| {
                    for (label, v) in [("Organization", &mut s.organization), ("Department", &mut s.org_unit), ("City", &mut s.locality), ("State / region", &mut s.state)] {
                        field_label(ui, p, label);
                        changed |= ui.add(egui::TextEdit::singleline(v).desired_width(240.0)).changed();
                        ui.end_row();
                    }
                    field_label(ui, p, "Country (2 letters)");
                    changed |= ui.add(egui::TextEdit::singleline(&mut s.country).char_limit(2).desired_width(60.0)).changed();
                    ui.end_row();
                    field_label(ui, p, "Key type");
                    let before = s.default_key;
                    key_combo(ui, "def_key", &mut s.default_key);
                    changed |= before != s.default_key;
                    ui.end_row();
                    field_label(ui, p, "Certificates valid for");
                    changed |= ui.add(egui::DragValue::new(&mut s.default_days).range(1..=3650).suffix(" days")).changed();
                    ui.end_row();
                    field_label(ui, p, "Authorities valid for");
                    changed |= ui.add(egui::DragValue::new(&mut s.ca_years).range(1..=50).suffix(" years")).changed();
                    ui.end_row();
                    field_label(ui, p, "Warn before expiry");
                    changed |= ui.add(egui::DragValue::new(&mut s.warn_days).range(1..=365).suffix(" days")).changed();
                    ui.end_row();
                });
                if changed {
                    self.issue = IssueForm { ca_id: self.issue.ca_id.clone(), common_name: std::mem::take(&mut self.issue.common_name), sans: std::mem::take(&mut self.issue.sans), ..IssueForm::new(s) };
                }
            });
            l.add_space(12.0);
            card(l, p, |ui| {
                card_title(ui, p, "Appearance", "");
                let s = &mut st.settings;
                ui.horizontal(|ui| {
                    changed |= ui.selectable_value(&mut s.dark, true, "Dark").changed();
                    changed |= ui.selectable_value(&mut s.dark, false, "Light").changed();
                });
            });
            card(r, p, |ui| {
                card_title(ui, p, "Network name and revocation", "");
                let s = &mut st.settings;
                field_label(ui, p, "This computer's name on the network");
                changed |= ui.add(egui::TextEdit::singleline(&mut s.public_host).desired_width(280.0).hint_text(format!("e.g. {}.lan or {}", ca::host_name(), ca::lan_ip().map(|i| i.to_string()).unwrap_or_default()))).changed();
                muted(ui, p, "Used in the secure address's certificate and to tell devices where the revocation list is.");
                ui.add_space(6.0);
                changed |= ui.checkbox(&mut s.include_cdp, "Put the revocation list address in new certificates").changed();
                ui.horizontal(|ui| {
                    field_label(ui, p, "Lists valid for");
                    changed |= ui.add(egui::DragValue::new(&mut s.crl_days).range(1..=365).suffix(" days")).changed();
                });
                if s.public_host.trim().is_empty() && s.include_cdp {
                    muted(ui, p, "No address is added until the network name is set.");
                }
            });
            r.add_space(12.0);
            card(r, p, |ui| {
                card_title(ui, p, "Your data", "Authorities, keys and certificates are stored on this computer only");
                field_label(ui, p, "Data file");
                theme::copy_line(ui, p, &self.shared.path.display().to_string());
                ui.horizontal_wrapped(|ui| {
                    if ui.button("Open folder").clicked() {
                        self.actions.push(Action::OpenDataFolder);
                    }
                    if ui.button("Back up…").clicked() {
                        self.actions.push(Action::Backup);
                    }
                    if ui.button("Restore from backup…").clicked() {
                        self.actions.push(Action::Restore);
                    }
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    pill(ui, "Important", p.warn);
                    ui.add(egui::Label::new(RichText::new("Private keys are kept unencrypted in your user profile. Keep backups somewhere safe and don't share them.").size(12.5)).wrap());
                });
            });
            r.add_space(12.0);
            card(r, p, |ui| {
                card_title(ui, p, "About", "");
                muted(ui, p, format!("LabCert {} · {} authorities · {} certificates · {} log entries", env!("CARGO_PKG_VERSION"), st.authorities.len(), st.certs.len(), st.log.len()));
                if let Some(root) = st.default_ca_id().and_then(|d| st.root_of(&d).map(|a| a.id.clone())) {
                    ui.horizontal(|ui| {
                        if ui.button("Save root certificate…").clicked() {
                            self.save_ca_export(st, &root, Export::CertPem);
                        }
                    });
                }
            });
        });
        if changed {
            self.mark_dirty(ui.ctx());
        }
    }
}
