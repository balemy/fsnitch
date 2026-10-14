//! The management window: sidebar of protected paths (+ log), status card, and
//! the current page. Also owns polling and the tray handle.

use crate::actions::{self, Outcome};
use crate::model::{self, Action, Health, Snapshot};
use crate::tray::{self, TrayMsg};
use crate::{client, dialogs, log_page, path_page, Config};
use adw::prelude::*;
use gtk::{gio, glib};
use gtk4 as gtk;
use libadwaita as adw;
use std::cell::{Cell, RefCell};
use std::path::{Path, PathBuf};
use std::rc::Rc;

const POLL_SECS: u32 = 3;

const CSS: &str = "
.fs-status { border-radius: 12px; padding: 12px 16px; margin: 12px 12px 0 12px; }
.fs-status.ok { background-color: alpha(@success_color, 0.14); }
.fs-status.ok .fs-status-icon, .fs-status.ok .fs-status-title { color: @success_color; }
.fs-status.warn { background-color: alpha(@warning_color, 0.18); }
.fs-status.warn .fs-status-icon, .fs-status.warn .fs-status-title { color: @warning_color; }
.fs-status.err { background-color: alpha(@error_color, 0.14); }
.fs-status.err .fs-status-icon, .fs-status.err .fs-status-title { color: @error_color; }
.fs-status-title { font-weight: bold; }
.fs-badge { font-size: smaller; padding: 1px 8px; border-radius: 999px;
            background-color: alpha(currentColor, 0.1); }
.fs-badge.temporary { background-color: alpha(@warning_color, 0.22); }
.fs-badge.paused { background-color: alpha(@warning_color, 0.22); }
";

/// Install the stylesheet and, for dev runs, the repo's icon directory.
pub fn init_display(icon_dir: &str) {
    let Some(display) = gtk::gdk::Display::default() else {
        return;
    };
    let provider = gtk::CssProvider::new();
    provider.load_from_string(CSS);
    gtk::style_context_add_provider_for_display(
        &display,
        &provider,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );
    if !icon_dir.is_empty() {
        gtk::IconTheme::for_display(&display).add_search_path(icon_dir);
    }
}

/// What the content area shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    Path(String),
    Log,
}

struct State {
    snapshot: Result<Snapshot, String>,
    /// `snapshot.coarse()` of what is rendered; None forces a rebuild.
    rendered: Option<Result<Snapshot, String>>,
    selection: Option<Selection>,
    /// Sidebar row index -> selection.
    rows: Vec<Selection>,
    log_blocked_only: bool,
}

pub struct Ui {
    pub config: Config,
    pub window: adw::ApplicationWindow,
    toasts: adw::ToastOverlay,
    split: adw::NavigationSplitView,
    sidebar: gtk::ListBox,
    content_page: adw::NavigationPage,
    content: gtk::Box,
    status: StatusCard,
    state: RefCell<State>,
    /// Suppresses selection handlers while the sidebar is rebuilt.
    rebuilding: Cell<bool>,
    fetching: Cell<bool>,
    tray: RefCell<Option<ksni::blocking::Handle<tray::FsnitchTray>>>,
    pub home: PathBuf,
}

impl Ui {
    pub fn new(app: &adw::Application, config: Config) -> Rc<Ui> {
        let window = adw::ApplicationWindow::builder()
            .application(app)
            .title("fsnitch")
            .default_width(920)
            .default_height(640)
            .hide_on_close(true)
            .build();

        // Sidebar.
        let sidebar = gtk::ListBox::new();
        sidebar.add_css_class("navigation-sidebar");
        sidebar.set_selection_mode(gtk::SelectionMode::Single);
        let add = gtk::Button::from_icon_name("list-add-symbolic");
        add.set_tooltip_text(Some("Protect a path"));
        let sidebar_header = adw::HeaderBar::new();
        sidebar_header.pack_start(&add);
        let sidebar_view = adw::ToolbarView::new();
        sidebar_view.add_top_bar(&sidebar_header);
        sidebar_view.set_content(Some(
            &gtk::ScrolledWindow::builder()
                .hscrollbar_policy(gtk::PolicyType::Never)
                .child(&sidebar)
                .build(),
        ));
        let sidebar_page = adw::NavigationPage::builder()
            .title("fsnitch")
            .child(&sidebar_view)
            .build();

        // Content: status card above the current page.
        let status = StatusCard::new();
        let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
        content.set_vexpand(true);
        let column = gtk::Box::new(gtk::Orientation::Vertical, 0);
        column.append(&status.root);
        column.append(&content);
        let content_view = adw::ToolbarView::new();
        content_view.add_top_bar(&adw::HeaderBar::new());
        content_view.set_content(Some(&column));
        let content_page = adw::NavigationPage::builder()
            .title("fsnitch")
            .child(&content_view)
            .build();

        let split = adw::NavigationSplitView::builder()
            .sidebar(&sidebar_page)
            .content(&content_page)
            .min_sidebar_width(220.0)
            .build();
        let toasts = adw::ToastOverlay::new();
        toasts.set_child(Some(&split));
        window.set_content(Some(&toasts));

        // Collapse to one pane on narrow windows.
        let bp = adw::Breakpoint::new(adw::BreakpointCondition::new_length(
            adw::BreakpointConditionLengthType::MaxWidth,
            560.0,
            adw::LengthUnit::Sp,
        ));
        bp.add_setter(&split, "collapsed", Some(&true.to_value()));
        window.add_breakpoint(bp);

        let ui = Rc::new(Ui {
            home: glib::home_dir(),
            config,
            window,
            toasts,
            split,
            sidebar,
            content_page,
            content,
            status,
            state: RefCell::new(State {
                snapshot: Err("Connecting to the daemon…".into()),
                rendered: None,
                selection: None,
                rows: Vec::new(),
                log_blocked_only: false,
            }),
            rebuilding: Cell::new(false),
            fetching: Cell::new(false),
            tray: RefCell::new(None),
        });

        {
            let ui = ui.clone();
            add.connect_clicked(move |_| dialogs::protect_path(&ui));
        }
        {
            let weak = Rc::downgrade(&ui);
            ui.sidebar.connect_row_selected(move |_, row| {
                let (Some(ui), Some(row)) = (weak.upgrade(), row) else {
                    return;
                };
                if ui.rebuilding.get() {
                    return;
                }
                let selection = ui.state.borrow().rows.get(row.index() as usize).cloned();
                if let Some(selection) = selection {
                    ui.select(selection);
                }
            });
        }
        {
            let ui2 = ui.clone();
            ui.status.button.connect_clicked(move |_| ui2.start_agent());
        }

        ui.start_tray();
        ui.render_all();
        ui.refresh();
        {
            let weak = Rc::downgrade(&ui);
            glib::timeout_add_seconds_local(POLL_SECS, move || match weak.upgrade() {
                Some(ui) => {
                    ui.refresh();
                    glib::ControlFlow::Continue
                }
                None => glib::ControlFlow::Break,
            });
        }
        ui
    }

    pub fn present(&self) {
        self.window.present();
    }

    fn start_tray(self: &Rc<Self>) {
        let (tx, rx) = async_channel::unbounded();
        match tray::spawn(self.config.icon_dir.clone(), tx) {
            Ok(handle) => *self.tray.borrow_mut() = Some(handle),
            Err(err) => {
                tracing::warn!("tray icon unavailable: {err}");
                // Without a tray there is no other way in: show the window.
                self.present();
            }
        }
        let ui = self.clone();
        glib::spawn_future_local(async move {
            while let Ok(msg) = rx.recv().await {
                match msg {
                    TrayMsg::Open => ui.present(),
                    TrayMsg::ResumeAll => ui.run_action(Action::Resume { path: None }),
                    TrayMsg::Quit => {
                        if let Some(handle) = ui.tray.borrow_mut().take() {
                            let _ = handle.shutdown();
                        }
                        if let Some(app) = ui.window.application() {
                            app.quit();
                        }
                    }
                }
            }
        });
    }

    /// Poll the status socket off the main thread and apply the result.
    pub fn refresh(self: &Rc<Self>) {
        if self.fetching.replace(true) {
            return;
        }
        let socket = self.config.status_socket.clone();
        let ui = self.clone();
        glib::spawn_future_local(async move {
            let result = gio::spawn_blocking(move || client::fetch(&socket))
                .await
                .unwrap_or_else(|_| Err("status reader crashed".into()));
            ui.fetching.set(false);
            ui.apply(result);
        });
    }

    fn apply(self: &Rc<Self>, snapshot: Result<Snapshot, String>) {
        let health = model::health(&snapshot, &self.home);
        let paused = snapshot.as_ref().is_ok_and(Snapshot::any_paused);
        if let Some(handle) = self.tray.borrow().as_ref() {
            tray::set_state(handle, health.clone(), paused);
        }
        let agent_missing = snapshot.as_ref().is_ok_and(|s| !s.agent_connected);
        self.status.show(&health, agent_missing);
        let coarse = snapshot
            .as_ref()
            .map(Snapshot::coarse)
            .map_err(Clone::clone);
        let changed = self.state.borrow().rendered.as_ref() != Some(&coarse);
        self.state.borrow_mut().snapshot = snapshot;
        if changed {
            self.state.borrow_mut().rendered = Some(coarse);
            self.render_all();
        }
    }

    /// Rebuild the sidebar and the current page from the stored snapshot.
    fn render_all(self: &Rc<Self>) {
        self.rebuilding.set(true);
        while let Some(child) = self.sidebar.first_child() {
            self.sidebar.remove(&child);
        }
        let mut rows = Vec::new();
        let state = self.state.borrow();
        if let Ok(snap) = &state.snapshot {
            for p in &snap.paths {
                self.sidebar.append(&self.sidebar_row(p));
                rows.push(Selection::Path(p.path.clone()));
            }
            self.sidebar.append(&sidebar_label_row(
                "document-open-recent-symbolic",
                "Log",
                None,
                None,
            ));
            rows.push(Selection::Log);
        }
        // Separator above "Log".
        let log_index = rows.len().saturating_sub(1) as i32;
        self.sidebar.set_header_func(move |row, _| {
            if row.index() == log_index && log_index > 0 {
                row.set_header(Some(&gtk::Separator::new(gtk::Orientation::Horizontal)));
            } else {
                row.set_header(None::<&gtk::Widget>);
            }
        });

        // Keep the selection if it still exists; default to the first path.
        let mut selection = state.selection.clone().filter(|s| rows.contains(s));
        if selection.is_none() && state.snapshot.is_ok() {
            selection = rows.first().cloned().filter(|s| *s != Selection::Log);
        }
        drop(state);
        if let Some(i) = selection
            .as_ref()
            .and_then(|s| rows.iter().position(|r| r == s))
        {
            self.sidebar
                .select_row(self.sidebar.row_at_index(i as i32).as_ref());
        }
        {
            let mut state = self.state.borrow_mut();
            state.rows = rows;
            state.selection = selection;
        }
        self.rebuilding.set(false);
        self.render_content();
    }

    fn sidebar_row(&self, p: &model::PathView) -> gtk::ListBoxRow {
        let icon = if Path::new(&p.path).is_dir() {
            "folder-symbolic"
        } else {
            "text-x-generic-symbolic"
        };
        let mode = path_page::mode_label(&p.mode);
        let badge = p
            .paused_secs
            .map(|secs| format!("paused · {}", model::fmt_remaining(secs)));
        sidebar_label_row(
            icon,
            &model::display_path(&p.path, &self.home),
            Some(mode),
            badge.as_deref(),
        )
    }

    fn select(self: &Rc<Self>, selection: Selection) {
        self.state.borrow_mut().selection = Some(selection);
        self.render_content();
        self.split.set_show_content(true);
    }

    pub fn render_content(self: &Rc<Self>) {
        while let Some(child) = self.content.first_child() {
            self.content.remove(&child);
        }
        let state = self.state.borrow();
        let (title, page): (String, gtk::Widget) = match (&state.snapshot, &state.selection) {
            // The status card above already shows the error itself.
            (Err(_), _) => (
                "fsnitch".into(),
                adw::StatusPage::builder()
                    .icon_name("fsnitch-unprotected-symbolic")
                    .title("Daemon not running")
                    .description("Start it with <tt>sudo systemctl start fsnitchd</tt>.")
                    .build()
                    .upcast(),
            ),
            (Ok(snap), Some(Selection::Log)) => (
                "Log".into(),
                log_page::build(self, &snap.events, state.log_blocked_only),
            ),
            (Ok(snap), Some(Selection::Path(path))) => {
                match snap.paths.iter().find(|p| &p.path == path) {
                    Some(view) => (
                        model::display_path(path, &self.home),
                        path_page::build(self, view),
                    ),
                    None => ("fsnitch".into(), self.empty_page()),
                }
            }
            (Ok(_), None) => ("fsnitch".into(), self.empty_page()),
        };
        drop(state);
        page.set_vexpand(true);
        self.content.append(&page);
        self.content_page.set_title(&title);
    }

    fn empty_page(self: &Rc<Self>) -> gtk::Widget {
        let button = gtk::Button::builder()
            .label("Protect a path…")
            .halign(gtk::Align::Center)
            .build();
        button.add_css_class("pill");
        button.add_css_class("suggested-action");
        let ui = self.clone();
        button.connect_clicked(move |_| dialogs::protect_path(&ui));
        adw::StatusPage::builder()
            .icon_name("fsnitch-protected-symbolic")
            .title("Nothing protected yet")
            .description(
                "Choose a file or folder — a password vault, SSH keys, a browser profile — \
                 and decide which programs may open it.",
            )
            .child(&button)
            .build()
            .upcast()
    }

    pub fn set_log_blocked_only(self: &Rc<Self>, blocked_only: bool) {
        self.state.borrow_mut().log_blocked_only = blocked_only;
        self.render_content();
    }

    pub fn toast(&self, text: &str) {
        self.toasts.add_toast(adw::Toast::new(text));
    }

    /// Run a policy change via pkexec, then re-poll and rebuild (also after a
    /// cancel, so widgets showing the attempted value snap back).
    pub fn run_action(self: &Rc<Self>, action: Action) {
        let argv = action.argv(&self.config.cli, self.config.control_socket.as_deref());
        let done = action.done_message();
        let ui = self.clone();
        glib::spawn_future_local(async move {
            let outcome = gio::spawn_blocking(move || actions::run(&argv))
                .await
                .unwrap_or_else(|_| Outcome::Failed("internal error".into()));
            match outcome {
                Outcome::Done => ui.toast(&done),
                Outcome::Cancelled => ui.toast("Cancelled"),
                Outcome::Failed(message) => ui.toast(&message),
            }
            ui.state.borrow_mut().rendered = None;
            ui.refresh();
        });
    }

    fn start_agent(self: &Rc<Self>) {
        let ui = self.clone();
        glib::spawn_future_local(async move {
            let ok = gio::spawn_blocking(|| {
                std::process::Command::new("systemctl")
                    .args(["--user", "start", "fsnitch-agent"])
                    .status()
                    .is_ok_and(|s| s.success())
            })
            .await
            .unwrap_or(false);
            if !ok {
                ui.toast(
                    "Could not start fsnitch-agent — see systemctl --user status fsnitch-agent",
                );
            }
            ui.refresh();
        });
    }
}

fn sidebar_label_row(
    icon: &str,
    title: &str,
    subtitle: Option<&str>,
    badge: Option<&str>,
) -> gtk::ListBoxRow {
    let row_box = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    row_box.set_margin_top(6);
    row_box.set_margin_bottom(6);
    row_box.append(&gtk::Image::from_icon_name(icon));
    let labels = gtk::Box::new(gtk::Orientation::Vertical, 2);
    labels.set_hexpand(true);
    let title_label = gtk::Label::builder()
        .label(title)
        .xalign(0.0)
        .ellipsize(gtk::pango::EllipsizeMode::Middle)
        .build();
    labels.append(&title_label);
    if let Some(subtitle) = subtitle {
        let sub = gtk::Label::builder().label(subtitle).xalign(0.0).build();
        sub.add_css_class("caption");
        sub.add_css_class("dim-label");
        labels.append(&sub);
    }
    row_box.append(&labels);
    if let Some(badge) = badge {
        let b = gtk::Label::new(Some(badge));
        b.add_css_class("fs-badge");
        b.add_css_class("paused");
        b.set_valign(gtk::Align::Center);
        row_box.append(&b);
    }
    gtk::ListBoxRow::builder().child(&row_box).build()
}

/// The coloured card at the top of the content area.
struct StatusCard {
    root: gtk::Box,
    icon: gtk::Image,
    title: gtk::Label,
    detail: gtk::Label,
    button: gtk::Button,
}

impl StatusCard {
    fn new() -> StatusCard {
        let root = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        root.add_css_class("fs-status");
        let icon = gtk::Image::from_icon_name("fsnitch-protected-symbolic");
        icon.set_pixel_size(24);
        icon.add_css_class("fs-status-icon");
        let labels = gtk::Box::new(gtk::Orientation::Vertical, 2);
        labels.set_hexpand(true);
        labels.set_valign(gtk::Align::Center);
        let title = gtk::Label::builder().xalign(0.0).build();
        title.add_css_class("fs-status-title");
        let detail = gtk::Label::builder().xalign(0.0).wrap(true).build();
        detail.add_css_class("caption");
        labels.append(&title);
        labels.append(&detail);
        let button = gtk::Button::with_label("Start agent");
        button.set_valign(gtk::Align::Center);
        button.set_visible(false);
        root.append(&icon);
        root.append(&labels);
        root.append(&button);
        StatusCard {
            root,
            icon,
            title,
            detail,
            button,
        }
    }

    fn show(&self, health: &Health, agent_missing: bool) {
        for class in ["ok", "warn", "err"] {
            self.root.remove_css_class(class);
        }
        let class = match health {
            Health::Protected => "ok",
            Health::Degraded(_) => "warn",
            Health::Unprotected(_) => "err",
        };
        self.root.add_css_class(class);
        self.icon
            .set_icon_name(Some(&format!("{}-symbolic", tray::icon_for(health))));
        let title = match health {
            Health::Protected => "Protected · daemon and prompt agent are running".to_string(),
            other => tray::headline(other).to_string(),
        };
        self.title.set_label(&title);
        let detail = match health {
            Health::Protected => String::new(),
            other => tray::details(other),
        };
        self.detail.set_visible(!detail.is_empty());
        self.detail.set_label(&detail);
        self.button.set_visible(agent_missing);
    }
}
