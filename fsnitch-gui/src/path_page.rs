//! One protected path: mode, pause, and the merged program list.

use crate::dialogs;
use crate::model::{fmt_remaining, Action, Origin, PathView, ProgramRow};
use crate::window::Ui;
use adw::prelude::*;
use gtk4 as gtk;
use libadwaita as adw;
use std::path::Path;
use std::rc::Rc;

const MODES: [&str; 3] = ["ask", "block", "watch"];
const PAUSES: [(&str, u64); 3] = [("15 min", 900), ("1 h", 3600), ("4 h", 14400)];

pub fn mode_label(mode: &str) -> &'static str {
    match mode {
        "block" => "Block",
        "watch" => "Watch only",
        _ => "Ask each time",
    }
}

fn mode_help(mode: &str) -> &'static str {
    match mode {
        "block" => "Programs not listed below are denied silently.",
        "watch" => "Every access is allowed and logged; listed denials still apply.",
        _ => "Programs not listed below trigger an allow / deny prompt.",
    }
}

pub fn build(ui: &Rc<Ui>, view: &PathView) -> gtk::Widget {
    let page = adw::PreferencesPage::new();
    page.add(&settings_group(ui, view));
    page.add(&programs_group(ui, view));
    if let Some(group) = danger_group(ui, view) {
        page.add(&group);
    }
    page.upcast()
}

fn settings_group(ui: &Rc<Ui>, view: &PathView) -> adw::PreferencesGroup {
    let group = adw::PreferencesGroup::builder().title("Protection").build();
    if !view.editable {
        group.set_description(Some(
            "Defined in a configuration file under /etc/fsnitch/paths.d — edit it there to \
             change the mode or the program list.",
        ));
    }

    let current = MODES.iter().position(|m| *m == view.mode).unwrap_or(0);
    let combo = adw::ComboRow::builder()
        .title("Mode")
        .subtitle(mode_help(&view.mode))
        .model(&gtk::StringList::new(&MODES.map(mode_label)))
        .selected(current as u32)
        .sensitive(view.editable)
        .build();
    {
        let ui = ui.clone();
        let path = view.path.clone();
        combo.connect_selected_notify(move |combo| {
            let selected = combo.selected() as usize;
            if selected != current && selected < MODES.len() {
                ui.run_action(Action::Protect {
                    path: path.clone(),
                    mode: MODES[selected].into(),
                });
            }
        });
    }
    group.add(&combo);

    let pause = adw::ActionRow::new();
    match view.paused_secs {
        Some(secs) => {
            pause.set_title("Paused");
            pause.set_subtitle(&format!(
                "Every program may open it — {} left.",
                fmt_remaining(secs)
            ));
            pause.add_prefix(&gtk::Image::from_icon_name("media-playback-pause-symbolic"));
            let resume = gtk::Button::with_label("Resume");
            resume.set_valign(gtk::Align::Center);
            resume.add_css_class("suggested-action");
            let ui = ui.clone();
            let path = view.path.clone();
            resume.connect_clicked(move |_| {
                ui.run_action(Action::Resume {
                    path: Some(path.clone()),
                })
            });
            pause.add_suffix(&resume);
        }
        None => {
            pause.set_title("Pause");
            pause.set_subtitle("Let every program in for a while.");
            let buttons = gtk::Box::new(gtk::Orientation::Horizontal, 0);
            buttons.add_css_class("linked");
            buttons.set_valign(gtk::Align::Center);
            for (label, secs) in PAUSES {
                let b = gtk::Button::with_label(label);
                let ui = ui.clone();
                let path = view.path.clone();
                b.connect_clicked(move |_| {
                    ui.run_action(Action::Pause {
                        path: path.clone(),
                        secs,
                    })
                });
                buttons.append(&b);
            }
            pause.add_suffix(&buttons);
        }
    }
    group.add(&pause);
    group
}

fn programs_group(ui: &Rc<Ui>, view: &PathView) -> adw::PreferencesGroup {
    let group = adw::PreferencesGroup::builder().title("Programs").build();
    let add = gtk::Button::builder()
        .icon_name("list-add-symbolic")
        .tooltip_text("Allow or deny a program")
        .sensitive(view.editable)
        .build();
    add.add_css_class("flat");
    {
        let ui = ui.clone();
        let path = view.path.clone();
        add.connect_clicked(move |_| dialogs::add_program(&ui, &path));
    }
    group.set_header_suffix(Some(&add));

    if view.programs.is_empty() {
        let empty = adw::ActionRow::builder()
            .title("No programs yet")
            .subtitle(match view.mode.as_str() {
                "ask" => "fsnitch asks the first time a program opens this path.",
                "block" => "Every program is denied. Add the ones that need access.",
                _ => "Accesses are only logged.",
            })
            .build();
        empty.add_css_class("dim-label");
        group.add(&empty);
    }
    for row in &view.programs {
        group.add(&program_row(ui, view, row));
    }
    group
}

fn badge(text: &str, extra: Option<&str>) -> gtk::Label {
    let label = gtk::Label::new(Some(text));
    label.add_css_class("fs-badge");
    if let Some(extra) = extra {
        label.add_css_class(extra);
    }
    label.set_valign(gtk::Align::Center);
    label
}

fn program_row(ui: &Rc<Ui>, view: &PathView, row: &ProgramRow) -> adw::ActionRow {
    let name = Path::new(&row.program)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| row.program.clone());
    let action_row = adw::ActionRow::builder()
        .title(glib_markup_escape(&name))
        .subtitle(glib_markup_escape(&row.program))
        .build();

    let (icon, access, class) = if row.allow {
        ("object-select-symbolic", "Allowed", "success")
    } else {
        ("action-unavailable-symbolic", "Denied", "error")
    };
    let image = gtk::Image::from_icon_name(icon);
    image.add_css_class(class);
    action_row.add_prefix(&image);

    if row.pinned {
        let pin = badge("sha256", None);
        pin.set_tooltip_text(Some("Pinned: only this exact binary matches"));
        action_row.add_suffix(&pin);
    }
    let origin = match row.origin {
        Origin::Fixed => badge("fixed", None),
        Origin::Remembered => badge("remembered", None),
        Origin::Temporary(secs) => {
            badge(&format!("{} left", fmt_remaining(secs)), Some("temporary"))
        }
    };
    action_row.add_suffix(&origin);
    let access_label = gtk::Label::new(Some(access));
    access_label.add_css_class(class);
    action_row.add_suffix(&access_label);

    let remove = gtk::Button::builder()
        .icon_name("user-trash-symbolic")
        .tooltip_text("Remove")
        .valign(gtk::Align::Center)
        // Fixed entries can only change on CLI-managed paths; dynamic
        // verdicts can always be forgotten.
        .sensitive(view.editable || row.origin != Origin::Fixed)
        .build();
    remove.add_css_class("flat");
    let action = match row.origin {
        Origin::Fixed => Action::RemoveFixed {
            path: view.path.clone(),
            program: row.program.clone(),
        },
        _ => Action::Forget {
            path: view.path.clone(),
            program: Some(row.program.clone()),
        },
    };
    {
        let ui = ui.clone();
        remove.connect_clicked(move |_| ui.run_action(action.clone()));
    }
    action_row.add_suffix(&remove);
    action_row
}

fn danger_group(ui: &Rc<Ui>, view: &PathView) -> Option<adw::PreferencesGroup> {
    let dynamic = view.programs.iter().any(|r| r.origin != Origin::Fixed);
    if !dynamic && !view.editable {
        return None;
    }
    let group = adw::PreferencesGroup::new();
    if dynamic {
        let row = adw::ActionRow::builder()
            .title("Forget answers")
            .subtitle("Programs you answered for will be asked again.")
            .build();
        let b = gtk::Button::with_label("Forget");
        b.set_valign(gtk::Align::Center);
        let ui = ui.clone();
        let path = view.path.clone();
        b.connect_clicked(move |_| {
            ui.run_action(Action::Forget {
                path: path.clone(),
                program: None,
            })
        });
        row.add_suffix(&b);
        group.add(&row);
    }
    if view.editable {
        let row = adw::ActionRow::builder()
            .title("Stop protecting")
            .subtitle("Every program will be able to open this path again.")
            .build();
        let b = gtk::Button::with_label("Stop protecting");
        b.set_valign(gtk::Align::Center);
        b.add_css_class("destructive-action");
        let ui = ui.clone();
        let path = view.path.clone();
        b.connect_clicked(move |_| dialogs::confirm_unprotect(&ui, &path));
        row.add_suffix(&b);
        group.add(&row);
    }
    Some(group)
}

/// ActionRow titles/subtitles are markup.
pub fn glib_markup_escape(text: &str) -> String {
    gtk::glib::markup_escape_text(text).to_string()
}
