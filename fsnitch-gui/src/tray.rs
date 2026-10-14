//! StatusNotifierItem tray icon (waybar, KDE, GNOME with the AppIndicator
//! extension). Runs on ksni's own thread; menu clicks are forwarded to the GTK
//! main loop as `TrayMsg`s.

use crate::model::Health;
use ksni::blocking::TrayMethods;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayMsg {
    Open,
    ResumeAll,
    Quit,
}

pub struct FsnitchTray {
    health: Health,
    /// Any path paused — offers "Resume all" in the menu.
    paused: bool,
    /// Extra icon search path (dev runs use the repo's packaging/icons).
    icon_dir: String,
    tx: async_channel::Sender<TrayMsg>,
}

/// Icon theme names, installed by the packaging into the hicolor theme. The
/// tray uses these full-colour icons (tray hosts recolour `-symbolic` ones to
/// the bar's text colour, which would lose green/yellow/red); the window uses
/// the `-symbolic` variants, tinted by CSS.
pub fn icon_for(health: &Health) -> &'static str {
    match health {
        Health::Protected => "fsnitch-protected",
        Health::Degraded(_) => "fsnitch-degraded",
        Health::Unprotected(_) => "fsnitch-unprotected",
    }
}

/// One-line headline for tray tooltip and banner.
pub fn headline(health: &Health) -> &'static str {
    match health {
        Health::Protected => "Protected",
        Health::Degraded(_) => "Protection limited",
        Health::Unprotected(_) => "Not protected",
    }
}

pub fn details(health: &Health) -> String {
    match health {
        Health::Protected => "Daemon and prompt agent are running.".into(),
        Health::Degraded(reasons) => reasons.join("\n"),
        Health::Unprotected(reason) => reason.clone(),
    }
}

impl ksni::Tray for FsnitchTray {
    fn id(&self) -> String {
        "fsnitch".into()
    }

    fn title(&self) -> String {
        format!("fsnitch — {}", headline(&self.health))
    }

    fn icon_name(&self) -> String {
        icon_for(&self.health).into()
    }

    fn icon_theme_path(&self) -> String {
        self.icon_dir.clone()
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            title: format!("fsnitch — {}", headline(&self.health)),
            description: details(&self.health),
            ..Default::default()
        }
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        let _ = self.tx.send_blocking(TrayMsg::Open);
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::StandardItem;
        let item = |label: &str, icon: &str, msg: TrayMsg| -> ksni::MenuItem<Self> {
            StandardItem {
                label: label.into(),
                icon_name: icon.into(),
                activate: Box::new(move |this: &mut Self| {
                    let _ = this.tx.send_blocking(msg);
                }),
                ..Default::default()
            }
            .into()
        };
        let mut menu = vec![item("Open fsnitch", "fsnitch-protected", TrayMsg::Open)];
        if self.paused {
            menu.push(item(
                "Resume all paused paths",
                "media-playback-start-symbolic",
                TrayMsg::ResumeAll,
            ));
        }
        menu.push(ksni::MenuItem::Separator);
        menu.push(item("Quit", "application-exit-symbolic", TrayMsg::Quit));
        menu
    }
}

/// Start the tray service. It also comes up when the tray host (e.g. waybar)
/// starts later than we do.
pub fn spawn(
    icon_dir: String,
    tx: async_channel::Sender<TrayMsg>,
) -> Result<ksni::blocking::Handle<FsnitchTray>, ksni::Error> {
    FsnitchTray {
        health: Health::Unprotected("Connecting to the daemon…".into()),
        paused: false,
        icon_dir,
        tx,
    }
    .assume_sni_available(true)
    .spawn()
}

pub fn set_state(handle: &ksni::blocking::Handle<FsnitchTray>, health: Health, paused: bool) {
    handle.update(move |tray| {
        tray.health = health;
        tray.paused = paused;
    });
}
