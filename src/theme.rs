//! Colours, styling and small reusable widgets.

use egui::{Color32, CornerRadius, FontId, Margin, Response, RichText, Sense, Stroke, StrokeKind, Ui, Vec2};

#[derive(Clone, Copy)]
pub struct Pal {
    pub bg: Color32,
    pub side: Color32,
    pub card: Color32,
    pub card2: Color32,
    pub border: Color32,
    pub text: Color32,
    pub muted: Color32,
    pub accent: Color32,
    pub accent_text: Color32,
    pub ok: Color32,
    pub warn: Color32,
    pub bad: Color32,
    pub info: Color32,
    pub hold: Color32,
}

pub const DARK: Pal = Pal {
    bg: Color32::from_rgb(0x0f, 0x17, 0x20),
    side: Color32::from_rgb(0x0b, 0x12, 0x1a),
    card: Color32::from_rgb(0x17, 0x22, 0x2f),
    card2: Color32::from_rgb(0x1d, 0x2a, 0x39),
    border: Color32::from_rgb(0x26, 0x34, 0x45),
    text: Color32::from_rgb(0xdc, 0xe4, 0xee),
    muted: Color32::from_rgb(0x8a, 0x9b, 0xb0),
    accent: Color32::from_rgb(0x2b, 0xb5, 0xa0),
    accent_text: Color32::from_rgb(0x05, 0x22, 0x1d),
    ok: Color32::from_rgb(0x4c, 0xc3, 0x8a),
    warn: Color32::from_rgb(0xe0, 0xa4, 0x3a),
    bad: Color32::from_rgb(0xe0, 0x5a, 0x5a),
    info: Color32::from_rgb(0x5a, 0x9c, 0xe8),
    hold: Color32::from_rgb(0xa8, 0x7c, 0xe8),
};

pub const LIGHT: Pal = Pal {
    bg: Color32::from_rgb(0xf3, 0xf5, 0xf8),
    side: Color32::from_rgb(0x15, 0x22, 0x31),
    card: Color32::from_rgb(0xff, 0xff, 0xff),
    card2: Color32::from_rgb(0xf0, 0xf3, 0xf7),
    border: Color32::from_rgb(0xdc, 0xe2, 0xea),
    text: Color32::from_rgb(0x1b, 0x26, 0x33),
    muted: Color32::from_rgb(0x64, 0x72, 0x84),
    accent: Color32::from_rgb(0x15, 0x9a, 0x86),
    accent_text: Color32::from_rgb(0xff, 0xff, 0xff),
    ok: Color32::from_rgb(0x1f, 0x9d, 0x62),
    warn: Color32::from_rgb(0xc2, 0x7c, 0x0e),
    bad: Color32::from_rgb(0xcc, 0x3b, 0x3b),
    info: Color32::from_rgb(0x2f, 0x74, 0xc8),
    hold: Color32::from_rgb(0x7c, 0x4d, 0xc4),
};

pub fn pal(dark: bool) -> Pal {
    if dark { DARK } else { LIGHT }
}

pub fn apply(ctx: &egui::Context, dark: bool) {
    let p = pal(dark);
    let theme = if dark { egui::Theme::Dark } else { egui::Theme::Light };
    ctx.set_theme(theme);
    let mut v = if dark { egui::Visuals::dark() } else { egui::Visuals::light() };
    v.panel_fill = p.bg;
    v.window_fill = p.card;
    v.window_stroke = Stroke::new(1.0, p.border);
    v.window_corner_radius = CornerRadius::same(12);
    v.extreme_bg_color = if dark { Color32::from_rgb(0x0a, 0x11, 0x18) } else { Color32::from_rgb(0xfa, 0xfb, 0xfc) };
    v.faint_bg_color = p.card2;
    v.code_bg_color = p.card2;
    v.hyperlink_color = p.accent;
    v.selection.bg_fill = p.accent.gamma_multiply(0.45);
    v.selection.stroke = Stroke::new(1.0, p.accent);
    v.override_text_color = Some(p.text);
    let r = CornerRadius::same(7);
    v.widgets.noninteractive.bg_fill = p.card;
    v.widgets.noninteractive.weak_bg_fill = p.card;
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, p.border);
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, p.text);
    v.widgets.noninteractive.corner_radius = r;
    v.widgets.inactive.bg_fill = p.card2;
    v.widgets.inactive.weak_bg_fill = p.card2;
    v.widgets.inactive.bg_stroke = Stroke::new(1.0, p.border);
    v.widgets.inactive.fg_stroke = Stroke::new(1.0, p.text);
    v.widgets.inactive.corner_radius = r;
    v.widgets.hovered.bg_fill = p.card2;
    v.widgets.hovered.weak_bg_fill = p.border;
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, p.accent.gamma_multiply(0.7));
    v.widgets.hovered.fg_stroke = Stroke::new(1.5, p.text);
    v.widgets.hovered.corner_radius = r;
    v.widgets.active.bg_fill = p.border;
    v.widgets.active.weak_bg_fill = p.border;
    v.widgets.active.bg_stroke = Stroke::new(1.0, p.accent);
    v.widgets.active.fg_stroke = Stroke::new(1.5, p.text);
    v.widgets.active.corner_radius = r;
    v.widgets.open.corner_radius = r;
    v.widgets.open.weak_bg_fill = p.card2;
    ctx.set_visuals_of(theme, v);
    ctx.style_mut_of(theme, |s| {
        s.spacing.item_spacing = Vec2::new(8.0, 7.0);
        s.spacing.button_padding = Vec2::new(11.0, 5.0);
        s.spacing.interact_size.y = 26.0;
        s.spacing.combo_width = 200.0;
        use egui::TextStyle::*;
        s.text_styles.insert(Body, FontId::proportional(14.0));
        s.text_styles.insert(Button, FontId::proportional(14.0));
        s.text_styles.insert(Small, FontId::proportional(11.5));
        s.text_styles.insert(Heading, FontId::proportional(22.0));
        s.text_styles.insert(Monospace, FontId::monospace(12.5));
    });
}

pub fn card<R>(ui: &mut Ui, p: &Pal, add: impl FnOnce(&mut Ui) -> R) -> R {
    egui::Frame::new()
        .fill(p.card)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::same(16))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

pub fn card_title(ui: &mut Ui, p: &Pal, title: &str, sub: &str) {
    ui.label(RichText::new(title).size(16.0).strong().color(p.text));
    if !sub.is_empty() {
        ui.label(RichText::new(sub).size(12.5).color(p.muted));
    }
    ui.add_space(6.0);
}

pub fn pill(ui: &mut Ui, text: &str, color: Color32) -> Response {
    let font = FontId::proportional(11.5);
    let galley = ui.painter().layout_no_wrap(text.to_string(), font, color);
    let size = galley.size() + Vec2::new(14.0, 6.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::hover());
    ui.painter().rect_filled(rect, CornerRadius::same(255), color.gamma_multiply(0.16));
    ui.painter().rect_stroke(rect, CornerRadius::same(255), Stroke::new(1.0, color.gamma_multiply(0.45)), StrokeKind::Inside);
    ui.painter().galley(rect.center() - galley.size() / 2.0, galley, color);
    resp
}

pub fn primary(ui: &mut Ui, p: &Pal, text: &str) -> Response {
    ui.add(
        egui::Button::new(RichText::new(text).strong().color(p.accent_text))
            .fill(p.accent)
            .stroke(Stroke::NONE)
            .corner_radius(CornerRadius::same(7)),
    )
}

pub fn danger(ui: &mut Ui, p: &Pal, text: &str) -> Response {
    ui.add(
        egui::Button::new(RichText::new(text).strong().color(Color32::WHITE))
            .fill(p.bad)
            .stroke(Stroke::NONE)
            .corner_radius(CornerRadius::same(7)),
    )
}

pub fn muted(ui: &mut Ui, p: &Pal, text: impl Into<String>) -> Response {
    ui.label(RichText::new(text.into()).color(p.muted).size(12.5))
}

pub fn field_label(ui: &mut Ui, p: &Pal, text: &str) {
    ui.label(RichText::new(text).color(p.muted).size(12.5));
}

/// The shield-with-check logo, drawn with shapes.
pub fn logo(ui: &mut Ui, p: &Pal, size: f32) -> Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let c = rect.center();
    let w = size * 0.42;
    let h = size * 0.48;
    let pts = vec![
        egui::pos2(c.x, c.y - h),
        egui::pos2(c.x + w, c.y - h * 0.62),
        egui::pos2(c.x + w * 0.92, c.y + h * 0.18),
        egui::pos2(c.x, c.y + h),
        egui::pos2(c.x - w * 0.92, c.y + h * 0.18),
        egui::pos2(c.x - w, c.y - h * 0.62),
    ];
    ui.painter().add(egui::Shape::convex_polygon(pts, p.accent, Stroke::NONE));
    let s = size / 24.0;
    ui.painter().add(egui::Shape::line(
        vec![egui::pos2(c.x - 4.5 * s, c.y), egui::pos2(c.x - 1.0 * s, c.y + 3.5 * s), egui::pos2(c.x + 5.0 * s, c.y - 3.5 * s)],
        Stroke::new(2.4 * s, Color32::WHITE),
    ));
    resp
}

/// A big number tile for the dashboard.
pub fn stat(ui: &mut Ui, p: &Pal, label: &str, value: &str, sub: &str, color: Color32) {
    egui::Frame::new()
        .fill(p.card)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::same(16))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                let (r, _) = ui.allocate_exact_size(Vec2::new(8.0, 8.0), Sense::hover());
                ui.painter().circle_filled(r.center(), 4.0, color);
                ui.label(RichText::new(label).color(p.muted).size(12.5));
            });
            ui.label(RichText::new(value).size(30.0).strong().color(p.text));
            ui.label(RichText::new(sub).color(p.muted).size(12.0));
        });
}

/// Monospace value with a copy button.
pub fn copy_line(ui: &mut Ui, p: &Pal, text: &str) -> bool {
    let mut copied = false;
    ui.horizontal(|ui| {
        egui::Frame::new()
            .fill(ui.visuals().extreme_bg_color)
            .stroke(Stroke::new(1.0, p.border))
            .corner_radius(CornerRadius::same(6))
            .inner_margin(Margin::symmetric(8, 5))
            .show(ui, |ui| {
                ui.add(egui::Label::new(RichText::new(text).monospace().color(p.text)).truncate());
            });
        if ui.small_button("Copy").on_hover_text("Copy to clipboard").clicked() {
            ui.ctx().copy_text(text.to_string());
            copied = true;
        }
    });
    copied
}

pub fn status_color(p: &Pal, s: crate::model::CertStatus) -> Color32 {
    use crate::model::CertStatus::*;
    match s {
        Valid => p.ok,
        Expiring => p.warn,
        Expired => p.muted,
        Revoked => p.bad,
        OnHold => p.hold,
        NotYetValid => p.info,
    }
}
