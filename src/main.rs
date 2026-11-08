#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod acme;
mod app;
mod ca;
mod dialogs;
mod help;
mod model;
mod pages;
mod pages2;
mod pages3;
mod selftest;
mod server;
mod theme;

use std::path::PathBuf;
use std::sync::Arc;

fn default_data_file() -> PathBuf {
    dirs::data_dir().unwrap_or_else(|| PathBuf::from(".")).join("LabCert").join("labcert.json")
}

fn main() {
    model::init_local_offset();
    let args: Vec<String> = std::env::args().collect();
    let arg = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    let screenshot = arg("--screenshot").map(PathBuf::from);
    let data = arg("--data-dir").map(|d| PathBuf::from(d).join("labcert.json")).unwrap_or_else(default_data_file);
    let page = arg("--page").and_then(|p| app::Page::from_name(&p));
    let select_first = args.iter().any(|a| a == "--select-first");

    if args.iter().any(|a| a == "--selftest") {
        let dir = arg("--data-dir").map(PathBuf::from).unwrap_or_else(|| std::env::temp_dir().join("labcert-selftest"));
        std::process::exit(selftest::run(&dir));
    }

    let shared = Arc::new(model::Shared::new(data));
    if args.iter().any(|a| a == "--demo") {
        selftest::seed_demo(&shared);
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("LabCert — Local Certificate Authority")
            .with_inner_size([1360.0, 860.0])
            .with_min_inner_size([980.0, 640.0]),
        ..Default::default()
    };
    let result = eframe::run_native(
        "LabCert",
        options,
        Box::new(move |cc| {
            let mut a = app::App::new(cc, shared.clone(), screenshot, page);
            if select_first {
                a.selected = shared.store().certs.first().map(|c| c.id.clone());
                a.expanded_ca = shared.store().authorities.last().map(|c| c.id.clone());
            }
            Ok(Box::new(a))
        }),
    );
    if let Err(e) = result {
        eprintln!("LabCert could not open its window: {e}");
        std::process::exit(1);
    }
}
