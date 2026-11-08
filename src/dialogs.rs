//! Modal dialogs.

use crate::app::*;
use crate::ca::{self, Export};
use crate::model::*;
use crate::pages::*;
use crate::theme::{danger, field_label, muted, primary, Pal};
use egui::RichText;

impl App {
    pub fn dialogs(&mut self, ctx: &egui::Context, st: &mut Store, p: &Pal) {
        let Some(mut dlg) = self.dialog.take() else { return };
        let mut close = false;
        let modal = egui::Modal::new(egui::Id::unique("dialog")).show(ctx, |ui| {
            ui.set_width(480.0);
            match &mut dlg {
                Dialog::NewCa { form, parent } => {
                    let title = if parent.is_some() { "New sub-authority" } else { "New root authority" };
                    ui.label(RichText::new(title).size(18.0).strong());
                    if let Some(pid) = parent {
                        muted(ui, p, format!("Signed by \"{}\"", st.ca_name(pid)));
                    } else {
                        muted(ui, p, "A new trust anchor. Devices must trust it before they accept its certificates.");
                    }
                    ui.add_space(8.0);
                    egui::Grid::new("newca").num_columns(2).spacing([14.0, 10.0]).show(ui, |ui| {
                        field_label(ui, p, "Name");
                        ui.add(egui::TextEdit::singleline(&mut form.name).desired_width(280.0));
                        ui.end_row();
                        field_label(ui, p, "Common name");
                        ui.add(egui::TextEdit::singleline(&mut form.common_name).desired_width(280.0).hint_text("same as name"));
                        ui.end_row();
                        field_label(ui, p, "Organization");
                        ui.add(egui::TextEdit::singleline(&mut form.organization).desired_width(280.0));
                        ui.end_row();
                        field_label(ui, p, "Department");
                        ui.add(egui::TextEdit::singleline(&mut form.org_unit).desired_width(280.0));
                        ui.end_row();
                        field_label(ui, p, "Country (2 letters)");
                        ui.add(egui::TextEdit::singleline(&mut form.country).char_limit(2).desired_width(60.0));
                        ui.end_row();
                        field_label(ui, p, "Key type");
                        key_combo(ui, "nca_key", &mut form.key_type);
                        ui.end_row();
                        field_label(ui, p, "Valid for");
                        ui.add(egui::DragValue::new(&mut form.years).range(1..=50).suffix(" years"));
                        ui.end_row();
                        field_label(ui, p, "");
                        if parent.is_some() {
                            ui.checkbox(&mut form.limit_depth, "Signs certificates only (no further sub-authorities)");
                        } else {
                            ui.checkbox(&mut form.with_intermediate, "Also create an issuing authority under it (recommended)");
                        }
                        ui.end_row();
                    });
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if primary(ui, p, "Create").clicked() {
                            if form.name.trim().is_empty() {
                                self.toast(ctx, "Give the authority a name", false);
                            } else {
                                let (f, par) = (form.clone(), parent.clone());
                                self.create_ca_job(f, par, st);
                                close = true;
                            }
                        }
                        if ui.button("Cancel").clicked() {
                            close = true;
                        }
                    });
                }
                Dialog::ImportCa { name, cert, key } => {
                    ui.label(RichText::new("Import an existing authority").size(18.0).strong());
                    muted(ui, p, "Bring the certificate and private key of an authority you already use, so LabCert can sign with it.");
                    ui.add_space(8.0);
                    field_label(ui, p, "Name (optional)");
                    ui.add(egui::TextEdit::singleline(name).desired_width(f32::INFINITY));
                    ui.horizontal(|ui| {
                        field_label(ui, p, "Certificate (PEM)");
                        if ui.small_button("Open file…").clicked() {
                            if let Some(f) = rfd::FileDialog::new().pick_file() {
                                match std::fs::read(&f) {
                                    Ok(b) => {
                                        *cert = if b.starts_with(b"-----") { String::from_utf8_lossy(&b).into_owned() } else { ca::der_to_pem("CERTIFICATE", &b) };
                                    }
                                    Err(e) => self.toast(ctx, e.to_string(), false),
                                }
                            }
                        }
                    });
                    ui.add(egui::TextEdit::multiline(cert).font(egui::TextStyle::Monospace).desired_rows(4).desired_width(f32::INFINITY).hint_text("-----BEGIN CERTIFICATE-----"));
                    ui.horizontal(|ui| {
                        field_label(ui, p, "Private key (PEM)");
                        if ui.small_button("Open file…").clicked() {
                            if let Some(f) = rfd::FileDialog::new().pick_file() {
                                if let Ok(s) = std::fs::read_to_string(&f) {
                                    *key = s;
                                }
                            }
                        }
                    });
                    ui.add(egui::TextEdit::multiline(key).font(egui::TextStyle::Monospace).desired_rows(4).desired_width(f32::INFINITY).hint_text("-----BEGIN PRIVATE KEY-----"));
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if primary(ui, p, "Import").clicked() {
                            match st.import_authority(name, cert, key) {
                                Ok(id) => {
                                    self.toast(ctx, "Authority imported", true);
                                    self.expanded_ca = Some(id);
                                    self.mark_dirty(ctx);
                                    close = true;
                                }
                                Err(e) => self.toast(ctx, e, false),
                            }
                        }
                        if ui.button("Cancel").clicked() {
                            close = true;
                        }
                    });
                }
                Dialog::Revoke { id, reason } => {
                    let name = st.cert(id).map(|c| c.common_name.clone()).unwrap_or_default();
                    ui.label(RichText::new(format!("Revoke \"{name}\"?")).size(18.0).strong());
                    muted(ui, p, "Devices that check the revocation list will stop trusting it. \"On hold\" can be undone later; other reasons are permanent.");
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        field_label(ui, p, "Reason");
                        reason_combo(ui, reason);
                    });
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if danger(ui, p, "Revoke").clicked() {
                            match st.revoke(id, *reason) {
                                Ok(()) => self.toast(ctx, format!("Revoked \"{name}\""), true),
                                Err(e) => self.toast(ctx, e, false),
                            }
                            self.mark_dirty(ctx);
                            close = true;
                        }
                        if ui.button("Cancel").clicked() {
                            close = true;
                        }
                    });
                }
                Dialog::RevokeCa { id, reason } => {
                    let name = st.ca_name(id);
                    ui.label(RichText::new(format!("Revoke authority \"{name}\"?")).size(18.0).strong());
                    muted(ui, p, "Everything it signed becomes untrusted for devices that check revocation. It can no longer issue certificates.");
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        field_label(ui, p, "Reason");
                        reason_combo(ui, reason);
                    });
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if danger(ui, p, "Revoke authority").clicked() {
                            match st.revoke_authority(id, *reason) {
                                Ok(()) => self.toast(ctx, format!("Revoked \"{name}\""), true),
                                Err(e) => self.toast(ctx, e, false),
                            }
                            self.mark_dirty(ctx);
                            close = true;
                        }
                        if ui.button("Cancel").clicked() {
                            close = true;
                        }
                    });
                }
                Dialog::DeleteCert { id } => {
                    let name = st.cert(id).map(|c| c.common_name.clone()).unwrap_or_default();
                    ui.label(RichText::new(format!("Delete \"{name}\" from LabCert?")).size(18.0).strong());
                    muted(ui, p, "This only removes it from the app (including its private key). It stays valid wherever it's installed — revoke it first if it should stop working.");
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if danger(ui, p, "Delete").clicked() {
                            st.delete_cert(id);
                            self.selected = None;
                            self.mark_dirty(ctx);
                            close = true;
                        }
                        if ui.button("Cancel").clicked() {
                            close = true;
                        }
                    });
                }
                Dialog::DeleteCa { id } => {
                    let name = st.ca_name(id);
                    let n = st.certs.iter().filter(|c| c.ca_id == *id).count();
                    let subs = st.authorities.iter().filter(|a| a.parent.as_deref() == Some(id.as_str())).count();
                    ui.label(RichText::new(format!("Delete \"{name}\"?")).size(18.0).strong());
                    ui.label(RichText::new(format!("This permanently removes the authority's private key, {subs} sub-authorities and {n} certificates it issued from LabCert. You can't issue or revoke for it afterwards.")).color(p.bad));
                    muted(ui, p, "Make a backup first if you might need it again.");
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if danger(ui, p, "Delete everything").clicked() {
                            st.delete_authority(id);
                            self.mark_dirty(ctx);
                            close = true;
                        }
                        if ui.button("Cancel").clicked() {
                            close = true;
                        }
                    });
                }
                Dialog::Pfx { id, is_ca, pw, pw2 } => {
                    ui.label(RichText::new("Save as PFX / PKCS#12").size(18.0).strong());
                    muted(ui, p, "One file with the certificate, its private key and the chain — what Windows, IIS and many appliances import. Protect it with a password.");
                    ui.add_space(8.0);
                    egui::Grid::new("pfx").num_columns(2).spacing([14.0, 10.0]).show(ui, |ui| {
                        field_label(ui, p, "Password");
                        ui.add(egui::TextEdit::singleline(pw).password(true).desired_width(240.0));
                        ui.end_row();
                        field_label(ui, p, "Repeat");
                        ui.add(egui::TextEdit::singleline(pw2).password(true).desired_width(240.0));
                        ui.end_row();
                    });
                    if !pw.is_empty() && pw != pw2 {
                        ui.label(RichText::new("The passwords don't match").color(p.bad));
                    }
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.add_enabled(pw == pw2, egui::Button::new("Save…")).clicked() {
                            let (bytes, name) = if *is_ca {
                                (st.export_authority(id, Export::Pfx, pw), Export::Pfx.file_name(&st.ca_name(id)))
                            } else {
                                (st.export_cert(id, Export::Pfx, pw), Export::Pfx.file_name(&st.cert(id).map(|c| c.common_name.clone()).unwrap_or_default()))
                            };
                            self.actions.push(Action::SaveFile { name, bytes });
                            close = true;
                        }
                        if ui.button("Cancel").clicked() {
                            close = true;
                        }
                    });
                }
                Dialog::CaKey { id } => {
                    ui.label(RichText::new("Save the authority's private key?").size(18.0).strong());
                    ui.label(RichText::new("Anyone with this file can create certificates your devices trust. Only export it to move the authority to another machine or into a safe.").color(p.warn));
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if danger(ui, p, "I understand, save it").clicked() {
                            let name = Export::KeyPem.file_name(&st.ca_name(id));
                            self.actions.push(Action::SaveFile { name, bytes: st.export_authority(id, Export::KeyPem, "") });
                            st.log(LogKind::Warn, "export", format!("Private key of \"{}\" was exported", st.ca_name(id)));
                            self.mark_dirty(ctx);
                            close = true;
                        }
                        if ui.button("Cancel").clicked() {
                            close = true;
                        }
                    });
                }
                Dialog::Renew { id, new_key, days, supersede } => {
                    let c = st.cert(id).cloned();
                    let name = c.as_ref().map(|c| c.common_name.clone()).unwrap_or_default();
                    let has_key = c.as_ref().map(|c| c.key_pem.is_some()).unwrap_or(false);
                    ui.label(RichText::new(format!("Renew \"{name}\"")).size(18.0).strong());
                    muted(ui, p, "Creates a fresh certificate with the same names and purpose.");
                    ui.add_space(8.0);
                    ui.radio_value(new_key, true, "New private key (recommended)");
                    ui.radio_value(new_key, false, if has_key { "Keep the same key" } else { "Keep the same key (the requester's key)" });
                    if !has_key && *new_key {
                        muted(ui, p, "A new key will be created here; you'll need to install it along with the certificate.");
                    }
                    ui.horizontal(|ui| {
                        field_label(ui, p, "Valid for");
                        days_chips(ui, days, &[(90, "90 d"), (365, "1 year"), (825, "825 d")]);
                    });
                    ui.checkbox(supersede, "Revoke the old certificate (reason: replaced)");
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if primary(ui, p, "Renew").clicked() {
                            let (id, nk, d, sup) = (id.clone(), *new_key, *days, *supersede);
                            let kt = c.as_ref().map(|c| c.key_type).unwrap_or_default();
                            self.spawn("Renewing…", move |sh| {
                                let key = if nk {
                                    match ca::generate_key(kt) {
                                        Ok(k) => Some(k),
                                        Err(e) => return JobResult { result: Err(e), goto: None },
                                    }
                                } else {
                                    None
                                };
                                let mut st = sh.store();
                                let r = st.renew(&id, key, Some(d), sup);
                                sh.save(&st);
                                match r {
                                    Ok(nid) => JobResult { result: Ok("Renewed. Install the new certificate where the old one is used.".into()), goto: Some((Page::Certificates, Some(nid))) },
                                    Err(e) => JobResult { result: Err(e), goto: None },
                                }
                            });
                            close = true;
                        }
                        if ui.button("Cancel").clicked() {
                            close = true;
                        }
                    });
                }
                Dialog::NewToken(f) => {
                    ui.label(RichText::new("New enrollment token").size(18.0).strong());
                    muted(ui, p, "A machine sends its signing request together with this token.");
                    ui.add_space(8.0);
                    egui::Grid::new("tok").num_columns(2).spacing([14.0, 10.0]).show(ui, |ui| {
                        field_label(ui, p, "Label");
                        ui.add(egui::TextEdit::singleline(&mut f.label).desired_width(260.0).hint_text("e.g. Kitchen tablet"));
                        ui.end_row();
                        field_label(ui, p, "Purpose");
                        profile_combo(ui, "tok_profile", &mut f.profile);
                        ui.end_row();
                        field_label(ui, p, "Certificates valid for");
                        ui.add(egui::DragValue::new(&mut f.days).range(1..=3650).suffix(" days"));
                        ui.end_row();
                        field_label(ui, p, "Signed by");
                        ca_combo(ui, st, "tok_ca", &mut f.ca_id, Some("Default authority"));
                        ui.end_row();
                        field_label(ui, p, "Uses");
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut f.limit_uses, "limit to");
                            ui.add_enabled(f.limit_uses, egui::DragValue::new(&mut f.max_uses).range(1..=10000));
                        });
                        ui.end_row();
                        field_label(ui, p, "Expires");
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut f.expires, "after");
                            ui.add_enabled(f.expires, egui::DragValue::new(&mut f.expires_days).range(1..=3650).suffix(" days"));
                        });
                        ui.end_row();
                        field_label(ui, p, "");
                        ui.checkbox(&mut f.auto_approve, "Sign immediately (no approval step)");
                        ui.end_row();
                    });
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if primary(ui, p, "Create token").clicked() {
                            let secret = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, random_bytes(18));
                            let label = if f.label.trim().is_empty() { format!("Token {}", st.tokens.len() + 1) } else { f.label.trim().to_string() };
                            st.tokens.push(Token {
                                id: random_id(6),
                                label: label.clone(),
                                secret: secret.clone(),
                                created: now(),
                                expires: f.expires.then(|| now() + f.expires_days as i64 * 86_400),
                                uses: 0,
                                max_uses: f.limit_uses.then_some(f.max_uses),
                                auto_approve: f.auto_approve,
                                profile: f.profile,
                                validity_days: f.days,
                                ca_id: f.ca_id.clone(),
                                disabled: false,
                            });
                            st.log(LogKind::Info, "enroll", format!("Created enrollment token \"{label}\""));
                            self.mark_dirty(ctx);
                            self.dialog = Some(Dialog::Secret { label, secret });
                            return;
                        }
                        if ui.button("Cancel").clicked() {
                            close = true;
                        }
                    });
                }
                Dialog::Secret { label, secret } => {
                    ui.label(RichText::new(format!("Token \"{label}\" is ready")).size(18.0).strong());
                    muted(ui, p, "Give this to the machine that will request a certificate. You can copy it again later from the Network service page.");
                    ui.add_space(8.0);
                    crate::theme::copy_line(ui, p, secret);
                    ui.add_space(6.0);
                    let host = ca::lan_ip().map(|i| i.to_string()).unwrap_or_else(ca::host_name);
                    field_label(ui, p, "Example");
                    crate::theme::copy_line(ui, p, &format!("curl --data-binary @host.csr \"http://{host}:{}/api/enroll?token={secret}\" -o host.crt", st.settings.server.http_port));
                    ui.add_space(10.0);
                    if primary(ui, p, "Done").clicked() {
                        close = true;
                    }
                }
                Dialog::Reject { id, note } => {
                    ui.label(RichText::new("Reject this request?").size(18.0).strong());
                    field_label(ui, p, "Reason shown to the requester (optional)");
                    ui.add(egui::TextEdit::singleline(note).desired_width(f32::INFINITY));
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if danger(ui, p, "Reject").clicked() {
                            if let Some(r) = st.requests.iter_mut().find(|r| r.id == *id) {
                                r.status = RequestStatus::Rejected;
                                r.note = note.clone();
                            }
                            st.log(LogKind::Info, "enroll", "Rejected a network request");
                            self.mark_dirty(ctx);
                            close = true;
                        }
                        if ui.button("Cancel").clicked() {
                            close = true;
                        }
                    });
                }
                Dialog::ConfirmRestore { path } => {
                    ui.label(RichText::new("Replace everything with this backup?").size(18.0).strong());
                    muted(ui, p, path.display().to_string());
                    ui.label(RichText::new("All current authorities, certificates and settings are replaced. The current data is kept as a .bak file next to the data file.").color(p.warn));
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if danger(ui, p, "Restore").clicked() {
                            match std::fs::read_to_string(&*path).map_err(|e| e.to_string()).and_then(|s| serde_json::from_str::<Store>(&s).map_err(|e| format!("Not a LabCert backup: {e}"))) {
                                Ok(mut restored) => {
                                    let _ = std::fs::copy(&self.shared.path, self.shared.path.with_extension(format!("before-restore-{}.bak", now())));
                                    restored.log(LogKind::Warn, "storage", format!("Restored from backup {}", path.display()));
                                    *st = restored;
                                    self.dark_applied = None;
                                    self.selected = None;
                                    self.mark_dirty(ctx);
                                    self.toast(ctx, "Backup restored", true);
                                }
                                Err(e) => self.toast(ctx, e, false),
                            }
                            close = true;
                        }
                        if ui.button("Cancel").clicked() {
                            close = true;
                        }
                    });
                }
                Dialog::ClearLog => {
                    ui.label(RichText::new("Clear the activity log?").size(18.0).strong());
                    muted(ui, p, "Certificates and authorities are not affected.");
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if danger(ui, p, "Clear").clicked() {
                            st.log.clear();
                            st.log(LogKind::Info, "log", "Activity log cleared");
                            self.mark_dirty(ctx);
                            close = true;
                        }
                        if ui.button("Cancel").clicked() {
                            close = true;
                        }
                    });
                }
            }
        });
        if modal.should_close() {
            close = true;
        }
        if !close && self.dialog.is_none() {
            self.dialog = Some(dlg);
        }
    }
}
