//! Help page: shows the user guide and installation notes (docs/*.md) inside the app.

use crate::app::*;
use crate::model::*;
use crate::theme::{card, muted, Pal};
use egui::text::{LayoutJob, TextFormat};
use egui::{Align, Color32, CornerRadius, FontId, RichText, Stroke};

pub const USER_GUIDE: &str = include_str!("../docs/USER_GUIDE.md");
pub const INSTALL: &str = include_str!("../docs/INSTALL.md");

/// Inline text with **bold**, `code` and [links](url) shown as plain words.
fn inline(text: &str, size: f32, p: &Pal, strong: bool) -> LayoutJob {
    let mut job = LayoutJob::default();
    let mut bold = strong;
    let mut code = false;
    let mut buf = String::new();
    let flush = |job: &mut LayoutJob, buf: &mut String, bold: bool, code: bool| {
        if buf.is_empty() {
            return;
        }
        let fmt = if code {
            TextFormat { font_id: FontId::monospace(size - 1.0), color: p.accent, background: p.card2, ..Default::default() }
        } else {
            TextFormat { font_id: FontId::proportional(size), color: if bold { Color32::from_gray(if p.bg.r() < 128 { 245 } else { 15 }) } else { p.text }, ..Default::default() }
        };
        job.append(buf, 0.0, fmt);
        buf.clear();
    };
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if !code && c == '*' && chars.get(i + 1) == Some(&'*') {
            flush(&mut job, &mut buf, bold, code);
            bold = !bold;
            i += 2;
            continue;
        }
        if c == '`' {
            flush(&mut job, &mut buf, bold, code);
            code = !code;
            i += 1;
            continue;
        }
        if !code && c == '[' {
            // [text](url) -> text
            let rest: String = chars[i + 1..].iter().collect();
            if let Some(close) = rest.find("](") {
                if let Some(end) = rest[close..].find(')') {
                    buf.push_str(&rest[..close]);
                    i += 1 + rest[..close + end + 1].chars().count();
                    continue;
                }
            }
        }
        if !code && c == '*' {
            // single *emphasis*: drop the marker
            i += 1;
            continue;
        }
        buf.push(c);
        i += 1;
    }
    flush(&mut job, &mut buf, bold, code);
    job
}

fn para(ui: &mut egui::Ui, mut job: LayoutJob) {
    job.wrap.max_width = ui.available_width();
    ui.add(egui::Label::new(job).wrap());
}

fn code_block(ui: &mut egui::Ui, p: &Pal, text: &str) {
    egui::Frame::new()
        .fill(ui.visuals().extreme_bg_color)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(egui::Margin::same(10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.add(egui::Label::new(RichText::new(text).monospace().color(p.text)).wrap());
            if ui.small_button("Copy").clicked() {
                ui.ctx().copy_text(text.to_string());
            }
        });
}

/// Section headings ("## ...") of a document, for the contents list.
fn headings(doc: &str) -> Vec<String> {
    let mut out = vec![];
    let mut in_code = false;
    for l in doc.lines() {
        if l.trim_start().starts_with("```") {
            in_code = !in_code;
        }
        if !in_code {
            if let Some(h) = l.strip_prefix("## ") {
                out.push(h.trim().to_string());
            }
        }
    }
    out
}

fn render(ui: &mut egui::Ui, p: &Pal, doc: &str, jump: &mut Option<usize>) {
    let lines: Vec<&str> = doc.lines().collect();
    let mut i = 0;
    let mut h2 = 0usize;
    while i < lines.len() {
        let raw = lines[i];
        let l = raw.trim_end();
        let t = l.trim_start();
        if t.starts_with("```") {
            let mut code = vec![];
            i += 1;
            while i < lines.len() && !lines[i].trim_start().starts_with("```") {
                code.push(lines[i].trim_start());
                i += 1;
            }
            code_block(ui, p, &code.join("\n"));
            ui.add_space(4.0);
            i += 1;
            continue;
        }
        if t.starts_with('|') {
            let mut rows: Vec<Vec<String>> = vec![];
            while i < lines.len() && lines[i].trim_start().starts_with('|') {
                let row = lines[i].trim();
                if !row.replace(['|', '-', ' ', ':'], "").is_empty() {
                    rows.push(row.trim_matches('|').split('|').map(|c| c.trim().to_string()).collect());
                }
                i += 1;
            }
            let cols = rows.first().map(|r| r.len()).unwrap_or(1);
            egui::Frame::new().stroke(Stroke::new(1.0, p.border)).corner_radius(CornerRadius::same(8)).inner_margin(egui::Margin::same(10)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                let col_w = ((ui.available_width() - 18.0 * cols as f32) / cols as f32).max(120.0);
                egui::Grid::new(ui.next_auto_id()).num_columns(cols).striped(true).spacing([18.0, 6.0]).max_col_width(col_w).show(ui, |ui| {
                    for (ri, r) in rows.iter().enumerate() {
                        for c in r {
                            ui.add(egui::Label::new(inline(c, 13.0, p, ri == 0)).wrap());
                        }
                        ui.end_row();
                    }
                });
            });
            ui.add_space(6.0);
            continue;
        }
        if let Some(h) = t.strip_prefix("# ") {
            ui.label(RichText::new(h).size(24.0).strong());
            ui.add_space(4.0);
        } else if let Some(h) = t.strip_prefix("## ") {
            ui.add_space(14.0);
            let r = ui.label(RichText::new(h).size(19.0).strong().color(p.accent));
            if *jump == Some(h2) {
                r.scroll_to_me(Some(Align::TOP));
                *jump = None;
            }
            h2 += 1;
            ui.add_space(2.0);
        } else if let Some(h) = t.strip_prefix("### ") {
            ui.add_space(8.0);
            ui.label(RichText::new(h).size(15.5).strong());
        } else if let Some(b) = t.strip_prefix("- ") {
            let indent = (l.len() - t.len()) as f32 * 6.0;
            ui.horizontal(|ui| {
                ui.add_space(6.0 + indent);
                ui.label(RichText::new("•").color(p.accent));
                para(ui, inline(b, 14.0, p, false));
            });
        } else if t.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) && t.contains(". ") && t.split_once(". ").map(|(n, _)| n.chars().all(|c| c.is_ascii_digit())).unwrap_or(false) {
            let (n, rest) = t.split_once(". ").unwrap();
            ui.horizontal(|ui| {
                ui.add_space(6.0);
                ui.label(RichText::new(format!("{n}.")).color(p.accent).strong());
                para(ui, inline(rest, 14.0, p, false));
            });
        } else if t.is_empty() {
            ui.add_space(4.0);
        } else {
            para(ui, inline(t, 14.0, p, false));
        }
        i += 1;
    }
}

impl App {
    pub fn help_page(&mut self, ui: &mut egui::Ui, _st: &mut Store, p: &Pal) {
        let docs = [("User guide", USER_GUIDE, "LabCert-User-Guide.md"), ("Installation", INSTALL, "LabCert-Installation.md")];
        let (_, doc, file) = docs[self.help_tab.min(1)];
        let total = ui.available_width();
        let height = ui.available_height();
        let toc_w = 236.0;
        let gap = 14.0;
        let doc_w = (total - toc_w - gap).max(300.0);
        let origin = ui.cursor().min;
        let toc_rect = egui::Rect::from_min_size(origin, egui::vec2(toc_w, height));
        let doc_rect = egui::Rect::from_min_size(origin + egui::vec2(toc_w + gap, 0.0), egui::vec2(doc_w, height));
        ui.allocate_rect(egui::Rect::from_min_size(origin, egui::vec2(total, height)), egui::Sense::hover());
        ui.scope_builder(egui::UiBuilder::new().max_rect(toc_rect).layout(egui::Layout::top_down(Align::Min)), |ui| {
                card(ui, p, |ui| {
                    ui.horizontal(|ui| {
                        for (i, (name, _, _)) in docs.iter().enumerate() {
                            if ui.selectable_label(self.help_tab == i, *name).clicked() {
                                self.help_tab = i;
                                self.help_jump = Some(usize::MAX);
                            }
                        }
                    });
                    ui.add_space(8.0);
                    muted(ui, p, "Contents");
                    for (i, h) in headings(doc).iter().enumerate() {
                        if ui.link(RichText::new(h).size(13.0)).clicked() {
                            self.help_jump = Some(i);
                        }
                    }
                    ui.add_space(10.0);
                    if ui.button("Save as file…").on_hover_text("Save this document to read or print elsewhere").clicked() {
                        self.actions.push(Action::SaveFile { name: file.into(), bytes: Ok(doc.as_bytes().to_vec()) });
                    }
                });
            });
        ui.scope_builder(egui::UiBuilder::new().max_rect(doc_rect).layout(egui::Layout::top_down(Align::Min)), |ui| {
            ui.set_width(doc_w);
            let mut area = egui::ScrollArea::vertical().id_salt(("help", self.help_tab)).auto_shrink([false, false]);
            if self.help_jump == Some(usize::MAX) {
                area = area.vertical_scroll_offset(0.0);
                self.help_jump = None;
            }
            area.show(ui, |ui| {
                card(ui, p, |ui| {
                    render(ui, p, doc, &mut self.help_jump);
                });
                ui.add_space(20.0);
            });
        });
    }
}
