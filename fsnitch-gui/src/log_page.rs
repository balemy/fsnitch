//! Recent accesses from the daemon's event log (the user's own events).

use crate::model::reason_label;
use crate::path_page::glib_markup_escape;
use crate::window::Ui;
use adw::prelude::*;
use fsnitch_core::eventlog::EventRecord;
use gtk4 as gtk;
use libadwaita as adw;
use std::path::Path;
use std::rc::Rc;

pub fn build(ui: &Rc<Ui>, events: &[EventRecord], blocked_only: bool) -> gtk::Widget {
    let page = adw::PreferencesPage::new();

    let filter_group = adw::PreferencesGroup::new();
    let filter = adw::SwitchRow::builder()
        .title("Blocked only")
        .active(blocked_only)
        .build();
    {
        let ui = ui.clone();
        filter.connect_active_notify(move |row| ui.set_log_blocked_only(row.is_active()));
    }
    filter_group.add(&filter);
    page.add(&filter_group);

    let shown: Vec<&EventRecord> = events
        .iter()
        .rev()
        .filter(|e| !blocked_only || e.decision != "allow")
        .collect();
    let group = adw::PreferencesGroup::builder()
        .title("Recent accesses")
        .description("Newest first. Only your own programs' accesses are shown.")
        .build();
    if shown.is_empty() {
        let empty = adw::ActionRow::builder().title("No events yet").build();
        empty.add_css_class("dim-label");
        group.add(&empty);
    }
    for event in shown {
        group.add(&event_row(event));
    }
    page.add(&group);
    page.upcast()
}

fn local_time(ts: &str) -> String {
    gtk::glib::DateTime::from_iso8601(ts, None)
        .and_then(|t| t.to_local())
        .and_then(|t| t.format("%d.%m. %H:%M:%S"))
        .map(|s| s.to_string())
        .unwrap_or_else(|_| ts.to_string())
}

fn event_row(event: &EventRecord) -> adw::ActionRow {
    let program = event
        .program
        .as_deref()
        .and_then(Path::file_name)
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown program".into());
    let subtitle = format!(
        "{}\n{} · {}",
        event.file.display(),
        local_time(&event.ts),
        reason_label(&event.source)
    );
    let row = adw::ActionRow::builder()
        .title(glib_markup_escape(&program))
        .subtitle(glib_markup_escape(&subtitle))
        .subtitle_lines(2)
        .build();
    if let Some(full) = &event.program {
        row.set_tooltip_text(Some(&full.display().to_string()));
    }
    let allowed = event.decision == "allow";
    let (icon, label, class) = if allowed {
        ("object-select-symbolic", "Allowed", "success")
    } else {
        ("action-unavailable-symbolic", "Denied", "error")
    };
    let image = gtk::Image::from_icon_name(icon);
    image.add_css_class(class);
    row.add_prefix(&image);
    let access = gtk::Label::new(Some(label));
    access.add_css_class(class);
    row.add_suffix(&access);
    row
}
