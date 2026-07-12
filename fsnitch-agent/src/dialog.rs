//! Dialog subprocess renderer: a GTK4 + wlr-layer-shell full-screen modal
//! overlay on wlroots, falling back to a normal centered window where
//! layer-shell is unavailable (e.g. GNOME). Reads one PromptRequest, returns the
//! chosen Verdict (None on dismiss/timeout). The connector, protocol, and
//! stdin/stdout verdict contract live in separate modules.

use fsnitch_core::protocol::{PromptRequest, Verdict};
use gtk::glib;
use gtk::prelude::*;
use gtk4 as gtk;
use gtk4_layer_shell::{Edge, KeyboardMode, Layer, LayerShell};
use std::cell::Cell;
use std::rc::Rc;
use std::time::{Duration, Instant};

const CSS: &str = "\
window { background: rgba(6,8,12,0.66); }
.card { background: #1b1e25; border: 1px solid #3a4150; border-radius: 16px; }
.accent { min-height: 6px; background: linear-gradient(90deg,#e0562f,#f0a020); border-radius: 16px 16px 0 0; }
.body { padding: 22px 24px 18px; }
.title { color: #ffffff; font-size: 16px; font-weight: 700; }
.lead { color: #98a0af; font-size: 12px; }
.facts { background: #12151b; border: 1px solid #2a2e37; border-radius: 9px; padding: 12px 14px; }
.k { color: #7f8798; }
.mono { font-family: monospace; color: #f0a86a; }
.tag { background: #2a2e37; color: #a9b1c2; border-radius: 12px; padding: 2px 8px; }
.q { color: #cdd2db; font-size: 13px; }
button.deny { background: #c0392b; color: #ffffff; font-weight: 700; }
button.allowbig { background: #2e7d32; color: #ffffff; font-weight: 700; }
button.big { font-size: 14px; padding: 10px 0; }
togglebutton.dur { font-size: 12px; padding: 4px 12px; color: #a9b1c2; background: #12151b; border: 1px solid #2a2e37; }
togglebutton.dur:checked { background: #3a4150; color: #ffffff; }
button.timed { font-size: 11px; min-height: 0; padding: 2px 10px; color: #a9b1c2; }
.foot { color: #727a88; font-size: 11px; }
";

/// A keyboard shortcut's intent. `Deny`/`Allow` apply the currently selected
/// duration; the capitalized shortcuts are quick "always" overrides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAction {
    Deny,
    Allow,
    DenyForever,
    AllowForever,
}

/// Pure keyboard mapping (unit-tested). Keyval names come from gdk::Key::name().
/// No Enter default; Esc and lowercase letters are the safe/quick actions.
pub fn map_key(name: &str) -> Option<KeyAction> {
    match name {
        "Escape" | "d" => Some(KeyAction::Deny),
        "D" => Some(KeyAction::DenyForever),
        "a" => Some(KeyAction::Allow),
        "A" => Some(KeyAction::AllowForever),
        _ => None,
    }
}

/// The selectable "how long does this decision last" choice. `Now` = a single
/// access (`*Once`); `For(secs)` = a timed verdict; `Forever` = persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Span {
    Now,
    For(u64),
    Forever,
}

impl Span {
    fn allow(self) -> Verdict {
        match self {
            Span::Now => Verdict::AllowOnce,
            Span::For(secs) => Verdict::AllowFor { secs },
            Span::Forever => Verdict::AllowForever,
        }
    }
    fn deny(self) -> Verdict {
        match self {
            Span::Now => Verdict::DenyOnce,
            Span::For(secs) => Verdict::DenyFor { secs },
            Span::Forever => Verdict::DenyForever,
        }
    }
}

/// Show the overlay for `req`; block until closed; return the chosen verdict.
pub fn run_dialog(req: PromptRequest) -> Option<Verdict> {
    // Silence one known-harmless environmental warning: GDK probes the
    // xdg-desktop-portal Inhibit interface, which many wlroots sessions don't
    // provide. GTK4/GDK use *structured* logging, which routes through the
    // writer func (not the legacy default handler), so we filter there and
    // forward everything else to GLib's default writer.
    glib::log_set_writer_func(|level, fields| {
        let message = fields
            .iter()
            .find(|f| f.key() == "MESSAGE")
            .and_then(|f| f.value_str());
        if message.is_some_and(|m| m.contains("portal.Inhibit")) {
            return glib::LogWriterOutput::Handled;
        }
        glib::log_writer_default(level, fields)
    });

    let result: Rc<Cell<Option<Verdict>>> = Rc::new(Cell::new(None));
    // NON_UNIQUE: every `--dialog` process is an independent one-shot window.
    // Without it, GTK's default D-Bus single-instance behavior would make a
    // second concurrent dialog (e.g. the systemd-service agent and a dev-run
    // agent at once) a "remote" instance whose `activate` never runs locally —
    // no window, silent None.
    let app = gtk::Application::builder()
        .application_id("com.balemy.fsnitch.agent")
        .flags(gtk::gio::ApplicationFlags::NON_UNIQUE)
        .build();

    {
        let result = result.clone();
        app.connect_activate(move |app| build_ui(app, &req, result.clone()));
    }

    // Pass only a program name — NOT our real argv (which contains --dialog,
    // --socket, …) so GTK doesn't try to parse those as its own options.
    let code = app.run_with_args(&["fsnitch-agent"]);
    tracing::debug!(?code, "dialog gtk app exited");
    result.get()
}

fn build_ui(app: &gtk::Application, req: &PromptRequest, result: Rc<Cell<Option<Verdict>>>) {
    let provider = gtk::CssProvider::new();
    provider.load_from_data(CSS);
    if let Some(display) = gtk::gdk::Display::default() {
        gtk::style_context_add_provider_for_display(
            &display,
            &provider,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    }

    // Backend name (e.g. "GdkWaylandDisplay" vs "GdkX11Display") — layer-shell
    // only works on Wayland, so this pinpoints a wrong-backend fallback.
    let backend = gtk::gdk::Display::default()
        .map(|d| d.type_().name().to_string())
        .unwrap_or_else(|| "none".into());

    if !gtk4_layer_shell::is_supported() {
        // No wlr-layer-shell (e.g. GNOME, or a non-Wayland backend): a normal
        // centered window with the same card.
        tracing::info!(
            layer_shell = false,
            %backend,
            "dialog mode: normal-window fallback"
        );
        build_fallback_window(app, req, &result);
        return;
    }

    // wlroots: one full-screen Overlay surface *per output*. Every output is
    // dimmed; only one hosts the interactive card + exclusive keyboard focus.
    // Answering (button/key) or the timeout quits the whole app, tearing down
    // every overlay at once.
    let monitors = monitor_list();
    tracing::info!(
        layer_shell = true,
        %backend,
        monitors = monitors.len(),
        "dialog mode: layer-shell overlay"
    );
    for (i, monitor) in monitors.iter().enumerate() {
        let g = monitor.geometry();
        let connector = monitor
            .connector()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "?".into());
        tracing::debug!(
            idx = i,
            %connector,
            x = g.x(),
            y = g.y(),
            width = g.width(),
            height = g.height(),
            scale = monitor.scale_factor(),
            "monitor"
        );
    }
    if monitors.is_empty() {
        // No monitor list available — let the compositor place a single overlay.
        build_overlay_window(app, req, &result, None, true);
        return;
    }
    // Host the card on the largest-area monitor (best guess for the main
    // screen); every other output gets a dim-only overlay.
    let card_idx = monitors
        .iter()
        .enumerate()
        .max_by_key(|(_, m)| {
            let g = m.geometry();
            i64::from(g.width()) * i64::from(g.height())
        })
        .map(|(i, _)| i)
        .unwrap_or(0);
    for (i, monitor) in monitors.iter().enumerate() {
        build_overlay_window(app, req, &result, Some(monitor), i == card_idx);
    }
}

/// Enumerate the connected outputs (empty if none are reported).
fn monitor_list() -> Vec<gtk::gdk::Monitor> {
    let mut out = Vec::new();
    if let Some(display) = gtk::gdk::Display::default() {
        let monitors = display.monitors();
        for i in 0..monitors.n_items() {
            if let Some(monitor) = monitors.item(i).and_then(|o| o.downcast().ok()) {
                out.push(monitor);
            }
        }
    }
    out
}

/// A full-screen `Overlay` layer surface pinned to `monitor` (or the compositor's
/// choice when `None`). `with_card` adds the interactive card + keyboard focus;
/// otherwise it is a dim-only backdrop.
fn build_overlay_window(
    app: &gtk::Application,
    req: &PromptRequest,
    result: &Rc<Cell<Option<Verdict>>>,
    monitor: Option<&gtk::gdk::Monitor>,
    with_card: bool,
) {
    let window = gtk::ApplicationWindow::new(app);
    window.set_decorated(false);
    window.init_layer_shell();
    window.set_layer(Layer::Overlay);
    window.set_namespace(Some("fsnitch"));

    // The root box fills the output. gtk4-layer-shell derives a surface's size
    // from its GTK content when opposite edges are NOT anchored, so a
    // `size_request` equal to the output geometry is what actually makes the
    // surface full-screen on this Sway — neither the all-four-anchor "stretch"
    // nor `set_default_size` did. The window's CSS background paints the dim
    // across the whole root; the card (if any) is centered on top.
    let root = gtk::Box::new(gtk::Orientation::Vertical, 0);
    if let Some(monitor) = monitor {
        window.set_monitor(Some(monitor));
        window.set_anchor(Edge::Top, true);
        window.set_anchor(Edge::Left, true);
        let g = monitor.geometry();
        root.set_size_request(g.width(), g.height());
    } else {
        // No geometry to size against: best-effort full-screen via all-four
        // anchors (works where the compositor honours the stretch).
        for edge in [Edge::Top, Edge::Bottom, Edge::Left, Edge::Right] {
            window.set_anchor(edge, true);
        }
    }

    if with_card {
        window.set_keyboard_mode(KeyboardMode::Exclusive);
        root.append(&build_card(app, req, result, &window));
    } else {
        // Dim-only overlay: no keyboard grab (the card window owns focus); the
        // empty sized root just carries the CSS backdrop.
        window.set_keyboard_mode(KeyboardMode::None);
    }
    window.set_child(Some(&root));
    window.present();
}

/// The non-layer-shell fallback: a normal, non-resizable centered window sized
/// to fit the whole card (~517px tall) so GTK never tries to squeeze it.
fn build_fallback_window(
    app: &gtk::Application,
    req: &PromptRequest,
    result: &Rc<Cell<Option<Verdict>>>,
) {
    let window = gtk::ApplicationWindow::new(app);
    window.set_decorated(false);
    window.set_default_size(640, 600);
    window.set_resizable(false);
    window.set_child(Some(&build_card(app, req, result, &window)));
    window.present();
}

/// Build the prompt card and wire its buttons/keyboard/countdown against
/// `window`. A chosen verdict (button or key) or the timeout quits the whole
/// `app` so every overlay window closes together. Returns the card widget for
/// the caller to place (centered) in the window's root.
fn build_card(
    app: &gtk::Application,
    req: &PromptRequest,
    result: &Rc<Cell<Option<Verdict>>>,
    window: &gtk::ApplicationWindow,
) -> gtk::Box {
    // Card: centered within a full-size root; expands so alignment can center it.
    let card = gtk::Box::new(gtk::Orientation::Vertical, 0);
    card.add_css_class("card");
    card.set_halign(gtk::Align::Center);
    card.set_valign(gtk::Align::Center);
    card.set_hexpand(true);
    card.set_vexpand(true);
    card.set_width_request(560);

    let accent = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    accent.add_css_class("accent");
    card.append(&accent);

    let body = gtk::Box::new(gtk::Orientation::Vertical, 8);
    body.add_css_class("body");

    let title = gtk::Label::new(Some("\u{26a0}  An app wants your protected files"));
    title.add_css_class("title");
    title.set_halign(gtk::Align::Start);
    body.append(&title);

    let lead = gtk::Label::new(Some(
        "An unrecognised program is trying to open a file you told fsnitch to protect.",
    ));
    lead.add_css_class("lead");
    lead.set_halign(gtk::Align::Start);
    lead.set_wrap(true);
    lead.set_xalign(0.0);
    body.append(&lead);

    // Facts grid (plain labels + monospace class; never set_markup on paths).
    let facts = gtk::Grid::new();
    facts.add_css_class("facts");
    facts.set_row_spacing(6);
    facts.set_column_spacing(14);
    facts.set_margin_top(4);
    add_fact(&facts, 0, "Process", {
        let l = mono(&format!("{}  (pid {})", req.program.display(), req.pid));
        l.set_hexpand(true);
        l
    });
    add_fact(&facts, 1, "File", {
        let l = mono(&req.file.display().to_string());
        l.set_hexpand(true);
        l
    });
    let path_lbl = mono(&req.path);
    path_lbl.set_hexpand(true);
    add_fact(&facts, 2, "Path", path_lbl);
    body.append(&facts);

    // Duration selector: one shared "how long does this decision last" choice
    // that both the Allow and Deny buttons read. Default: Now (a single access).
    let span: Rc<Cell<Span>> = Rc::new(Cell::new(Span::Now));

    let dur_label = gtk::Label::new(Some("Applies for"));
    dur_label.add_css_class("k");
    dur_label.set_halign(gtk::Align::Start);
    dur_label.set_margin_top(10);
    body.append(&dur_label);

    let dur_row = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    dur_row.add_css_class("linked"); // segmented look
    dur_row.set_margin_top(4);
    let spans: [(&str, Span); 4] = [
        ("Just now", Span::Now),
        ("15 min", Span::For(900)),
        ("1 hour", Span::For(3600)),
        ("Always", Span::Forever),
    ];
    let mut group: Option<gtk::ToggleButton> = None;
    for (text, choice) in spans {
        let tb = gtk::ToggleButton::with_label(text);
        tb.add_css_class("dur");
        if let Some(g) = &group {
            tb.set_group(Some(g));
        } else {
            group = Some(tb.clone());
        }
        if choice == Span::Now {
            tb.set_active(true);
        }
        let span = span.clone();
        tb.connect_toggled(move |b| {
            if b.is_active() {
                span.set(choice);
            }
        });
        dur_row.append(&tb);
    }
    body.append(&dur_row);

    // Primary decision: two big buttons that apply the selected duration.
    let decide = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    decide.set_homogeneous(true);
    decide.set_margin_top(10);
    let big = |label: &str, css: &str, pick: fn(Span) -> Verdict| {
        let b = gtk::Button::with_label(label);
        b.add_css_class(css);
        b.add_css_class("big");
        let result = result.clone();
        let app = app.clone();
        let span = span.clone();
        b.connect_clicked(move |_| {
            result.set(Some(pick(span.get())));
            app.quit();
        });
        b
    };
    decide.append(&big("Deny", "deny", Span::deny));
    decide.append(&big("Allow", "allowbig", Span::allow));
    body.append(&decide);

    // Path-wide pause (all programs), visually set apart from the per-app row.
    let pause_label = gtk::Label::new(Some("or pause the whole path — every program passes"));
    pause_label.add_css_class("foot");
    pause_label.set_halign(gtk::Align::Start);
    pause_label.set_margin_top(12);
    body.append(&pause_label);

    let pause_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    pause_row.set_margin_top(4);
    for (text, secs) in [("15 min", 900u64), ("1 hour", 3600), ("2 hours", 7200)] {
        let b = gtk::Button::with_label(text);
        b.add_css_class("timed");
        let result = result.clone();
        let app = app.clone();
        b.connect_clicked(move |_| {
            result.set(Some(Verdict::Pause { secs }));
            app.quit();
        });
        pause_row.append(&b);
    }
    body.append(&pause_row);

    // Countdown bar + footer.
    let bar = gtk::ProgressBar::new();
    bar.set_fraction(1.0);
    bar.set_margin_top(14);
    body.append(&bar);
    let foot = gtk::Label::new(Some(&format!(
        "No answer in {}s \u{2192} denied automatically",
        req.timeout_secs
    )));
    foot.add_css_class("foot");
    foot.set_halign(gtk::Align::Start);
    foot.set_margin_top(6);
    body.append(&foot);

    card.append(&body);

    // Keyboard: Esc/d = deny, a = allow (both at the selected duration);
    // D/A = quick always-deny/allow. Anything else is ignored (no Enter default).
    let key = gtk::EventControllerKey::new();
    {
        let result = result.clone();
        let app = app.clone();
        let span = span.clone();
        key.connect_key_pressed(move |_, keyval, _, _| {
            if let Some(action) = keyval.name().and_then(|n| map_key(n.as_str())) {
                let verdict = match action {
                    KeyAction::Deny => span.get().deny(),
                    KeyAction::Allow => span.get().allow(),
                    KeyAction::DenyForever => Verdict::DenyForever,
                    KeyAction::AllowForever => Verdict::AllowForever,
                };
                result.set(Some(verdict));
                app.quit();
                glib::Propagation::Stop
            } else {
                glib::Propagation::Proceed
            }
        });
    }
    window.add_controller(key);

    // Countdown: tick 4x/second; quit (no verdict) at the deadline.
    let total = Duration::from_secs(req.timeout_secs.max(1));
    let deadline = Instant::now() + total;
    {
        let window = window.clone();
        let app = app.clone();
        glib::timeout_add_local(Duration::from_millis(250), move || {
            // Stop ticking once the window is gone (answered/closed early).
            if !window.is_visible() {
                return glib::ControlFlow::Break;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                app.quit();
                return glib::ControlFlow::Break;
            }
            bar.set_fraction(remaining.as_secs_f64() / total.as_secs_f64());
            glib::ControlFlow::Continue
        });
    }

    // One-shot diagnostic: log the surface size the compositor actually gave us,
    // so a still-too-small overlay is immediately visible under RUST_LOG=debug.
    {
        let window = window.clone();
        glib::timeout_add_local_once(Duration::from_millis(700), move || {
            tracing::debug!(
                width = window.width(),
                height = window.height(),
                "card window allocated size"
            );
        });
    }

    card
}

fn mono(text: &str) -> gtk::Label {
    let l = gtk::Label::new(Some(text));
    l.add_css_class("mono");
    l.set_halign(gtk::Align::Start);
    l.set_wrap(true);
    l.set_xalign(0.0);
    l
}

fn add_fact(grid: &gtk::Grid, row: i32, key: &str, value: impl IsA<gtk::Widget>) {
    let k = gtk::Label::new(Some(key));
    k.add_css_class("k");
    k.set_halign(gtk::Align::Start);
    k.set_valign(gtk::Align::Start);
    grid.attach(&k, 0, row, 1, 1);
    grid.attach(&value, 1, row, 1, 1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_key_covers_shortcuts() {
        assert_eq!(map_key("Escape"), Some(KeyAction::Deny));
        assert_eq!(map_key("d"), Some(KeyAction::Deny));
        assert_eq!(map_key("D"), Some(KeyAction::DenyForever));
        assert_eq!(map_key("a"), Some(KeyAction::Allow));
        assert_eq!(map_key("A"), Some(KeyAction::AllowForever));
        assert_eq!(map_key("Return"), None);
        assert_eq!(map_key("x"), None);
    }

    #[test]
    fn span_maps_to_verdicts() {
        assert_eq!(Span::Now.allow(), Verdict::AllowOnce);
        assert_eq!(Span::Now.deny(), Verdict::DenyOnce);
        assert_eq!(Span::For(900).allow(), Verdict::AllowFor { secs: 900 });
        assert_eq!(Span::For(900).deny(), Verdict::DenyFor { secs: 900 });
        assert_eq!(Span::Forever.allow(), Verdict::AllowForever);
        assert_eq!(Span::Forever.deny(), Verdict::DenyForever);
    }
}
