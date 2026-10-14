//! fsnitch-gui: tray icon showing whether protection is fully active, plus a
//! management window. Reads the daemon's read-only status socket; every change
//! runs as `pkexec fsnitch …`.

mod actions;
mod client;
mod dialogs;
mod log_page;
mod model;
mod path_page;
mod tray;
mod window;

use adw::prelude::*;
use libadwaita as adw;
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

const APP_ID: &str = "io.github.balemy.Fsnitch";
const DEFAULT_CONTROL_SOCKET: &str = "/run/fsnitch/fsnitchd.sock";
const DEFAULT_CLI: &str = "/usr/bin/fsnitch";
const STATUS_SOCKET_NAME: &str = "status.sock";

const USAGE: &str = "usage: fsnitch-gui [--background] [--socket CONTROL_SOCKET] [--cli PATH]

  --background   start with only the tray icon (the systemd unit uses this)
  --socket PATH  the daemon's control socket; status.sock next to it is read
                 (default /run/fsnitch/fsnitchd.sock)
  --cli PATH     the fsnitch CLI run through pkexec (default /usr/bin/fsnitch)";

#[derive(Debug, Clone)]
pub struct Config {
    pub status_socket: PathBuf,
    /// Passed to the CLI only when not the default (dev runs).
    pub control_socket: Option<PathBuf>,
    pub cli: PathBuf,
    /// Extra tray icon search path; set by dev runs via FSNITCH_GUI_ICON_DIR.
    pub icon_dir: String,
    pub background: bool,
}

fn parse_args() -> Config {
    let mut control = PathBuf::from(DEFAULT_CONTROL_SOCKET);
    let mut cli = PathBuf::from(DEFAULT_CLI);
    let mut background = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--background" => background = true,
            "--socket" => control = args.next().map(PathBuf::from).unwrap_or(control),
            "--cli" => cli = args.next().map(PathBuf::from).unwrap_or(cli),
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            other => {
                eprintln!("fsnitch-gui: unknown argument {other:?}\n\n{USAGE}");
                std::process::exit(2);
            }
        }
    }
    let status_socket = control
        .parent()
        .map(|dir| dir.join(STATUS_SOCKET_NAME))
        .unwrap_or_else(|| PathBuf::from(STATUS_SOCKET_NAME));
    Config {
        status_socket,
        control_socket: (control != std::path::Path::new(DEFAULT_CONTROL_SOCKET))
            .then_some(control),
        cli,
        icon_dir: std::env::var("FSNITCH_GUI_ICON_DIR").unwrap_or_default(),
        background,
    }
}

fn main() -> gtk4::glib::ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let config = parse_args();
    // libadwaita doesn't support GTK_THEME: with it set, GTK swaps in its own
    // theme and libadwaita's widgets lose their styling. Keep only the
    // light/dark wish.
    let prefer_dark = std::env::var("GTK_THEME").is_ok_and(|t| t.ends_with(":dark"));
    std::env::remove_var("GTK_THEME");

    // A dev run (non-default socket) must not just activate an installed
    // instance through GApplication's single-instance handling.
    let app_id = match config.control_socket {
        Some(_) => format!("{APP_ID}.Devel"),
        None => APP_ID.to_string(),
    };
    let app = adw::Application::builder().application_id(app_id).build();
    let ui: Rc<RefCell<Option<Rc<window::Ui>>>> = Rc::default();

    {
        let icon_dir = config.icon_dir.clone();
        app.connect_startup(move |_| {
            if prefer_dark {
                adw::StyleManager::default().set_color_scheme(adw::ColorScheme::PreferDark);
            }
            window::init_display(&icon_dir);
        });
    }
    app.connect_activate(move |app| {
        let mut slot = ui.borrow_mut();
        match slot.as_ref() {
            // A second launch (e.g. from the app launcher) shows the window.
            Some(ui) => ui.present(),
            None => {
                // Keep running with the window closed: the tray lives on.
                std::mem::forget(app.hold());
                let ui = window::Ui::new(app, config.clone());
                if !config.background {
                    ui.present();
                }
                *slot = Some(ui);
            }
        }
    });
    // GApplication must not see our own flags.
    app.run_with_args(&[std::env::args().next().unwrap_or_default()])
}
