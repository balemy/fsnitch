//! Dialogs: protect a path, add a program, confirm unprotect.

use crate::model::Action;
use crate::path_page::mode_label;
use crate::window::Ui;
use adw::prelude::*;
use gtk::{gio, glib};
use gtk4 as gtk;
use libadwaita as adw;
use std::path::{Path, PathBuf};
use std::rc::Rc;

const MODES: [&str; 3] = ["ask", "block", "watch"];
/// (label, seconds) — None = permanent.
const DURATIONS: [(&str, Option<u64>); 3] = [
    ("Permanently", None),
    ("For 15 minutes", Some(900)),
    ("For 1 hour", Some(3600)),
];

fn boxed_list() -> gtk::ListBox {
    let list = gtk::ListBox::new();
    list.add_css_class("boxed-list");
    list.set_selection_mode(gtk::SelectionMode::None);
    list
}

/// `~/x` -> `$HOME/x`; anything else unchanged.
fn expand_home(text: &str, home: &Path) -> PathBuf {
    match text.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None if text == "~" => home.to_path_buf(),
        None => PathBuf::from(text),
    }
}

/// A file-chooser button that writes the chosen path into `entry`.
fn browse_button(
    ui: &Rc<Ui>,
    entry: &adw::EntryRow,
    icon: &str,
    tip: &str,
    folder: bool,
    start: &Path,
) {
    let button = gtk::Button::builder()
        .icon_name(icon)
        .tooltip_text(tip)
        .valign(gtk::Align::Center)
        .build();
    button.add_css_class("flat");
    let window = ui.window.clone();
    let entry2 = entry.clone();
    let start = gio::File::for_path(start);
    button.connect_clicked(move |_| {
        let dialog = gtk::FileDialog::builder()
            .modal(true)
            .initial_folder(&start)
            .build();
        let entry = entry2.clone();
        let done = move |result: Result<gio::File, glib::Error>| {
            if let Some(path) = result.ok().and_then(|f| f.path()) {
                entry.set_text(&path.display().to_string());
            }
        };
        if folder {
            dialog.select_folder(Some(&window), gio::Cancellable::NONE, done);
        } else {
            dialog.open(Some(&window), gio::Cancellable::NONE, done);
        }
    });
    entry.add_suffix(&button);
}

pub fn protect_path(ui: &Rc<Ui>) {
    let dialog = adw::AlertDialog::new(
        Some("Protect a path"),
        Some("fsnitch will guard this file or folder and everything below it."),
    );
    let list = boxed_list();
    let entry = adw::EntryRow::builder().title("File or folder").build();
    browse_button(
        ui,
        &entry,
        "folder-symbolic",
        "Choose a folder",
        true,
        &ui.home,
    );
    browse_button(
        ui,
        &entry,
        "text-x-generic-symbolic",
        "Choose a file",
        false,
        &ui.home,
    );
    let mode = adw::ComboRow::builder()
        .title("Mode")
        .model(&gtk::StringList::new(&MODES.map(mode_label)))
        .build();
    list.append(&entry);
    list.append(&mode);
    dialog.set_extra_child(Some(&list));
    dialog.add_responses(&[("cancel", "_Cancel"), ("protect", "_Protect")]);
    dialog.set_response_appearance("protect", adw::ResponseAppearance::Suggested);
    dialog.set_default_response(Some("protect"));
    dialog.set_close_response("cancel");
    dialog.set_response_enabled("protect", false);
    {
        let dialog = dialog.clone();
        let home = ui.home.clone();
        entry.connect_changed(move |e| {
            let path = expand_home(e.text().trim(), &home);
            dialog.set_response_enabled("protect", path.is_absolute() && path.exists());
        });
    }
    let ui2 = ui.clone();
    dialog.connect_response(Some("protect"), move |_, _| {
        let path = expand_home(entry.text().trim(), &ui2.home);
        let path = std::fs::canonicalize(&path).unwrap_or(path);
        ui2.run_action(Action::Protect {
            path: path.display().to_string(),
            mode: MODES[(mode.selected() as usize).min(MODES.len() - 1)].into(),
        });
    });
    dialog.present(Some(&ui.window));
}

/// Resolve what the user typed to the real binary the daemon will see
/// (`git` -> PATH lookup; symlinks resolved, e.g. python -> python3.13).
fn resolve_program(text: &str, home: &Path) -> Option<PathBuf> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let path = expand_home(text, home);
    let path = if path.is_absolute() {
        path
    } else {
        glib::find_program_in_path(text)?
    };
    let real = std::fs::canonicalize(path).ok()?;
    real.is_file().then_some(real)
}

pub fn add_program(ui: &Rc<Ui>, path: &str) {
    let shown = crate::model::display_path(path, &ui.home);
    let dialog = adw::AlertDialog::new(Some("Add a program"), Some(&shown));
    let list = boxed_list();
    let entry = adw::EntryRow::builder()
        .title("Program (e.g. /usr/bin/git or git)")
        .build();
    browse_button(
        ui,
        &entry,
        "document-open-symbolic",
        "Choose a program",
        false,
        Path::new("/usr/bin"),
    );
    let access = adw::ComboRow::builder()
        .title("Access")
        .model(&gtk::StringList::new(&["Allow", "Deny"]))
        .build();
    let duration = adw::ComboRow::builder()
        .title("Duration")
        .model(&gtk::StringList::new(&DURATIONS.map(|(label, _)| label)))
        .build();
    let pin = adw::SwitchRow::builder()
        .title("Pin by sha256")
        .subtitle("Only this exact binary matches; an update needs approval again.")
        .build();
    for row in [
        entry.upcast_ref::<gtk::Widget>(),
        access.upcast_ref(),
        duration.upcast_ref(),
        pin.upcast_ref(),
    ] {
        list.append(row);
    }
    // Deny is always permanent and unpinned; a timed allow can't be pinned.
    let sync = {
        let (access, duration, pin) = (access.clone(), duration.clone(), pin.clone());
        move || {
            let allow = access.selected() == 0;
            duration.set_sensitive(allow);
            pin.set_sensitive(allow && duration.selected() == 0);
        }
    };
    {
        let sync = sync.clone();
        access.connect_selected_notify(move |_| sync());
    }
    duration.connect_selected_notify(move |_| sync());

    dialog.set_extra_child(Some(&list));
    dialog.add_responses(&[("cancel", "_Cancel"), ("add", "_Add")]);
    dialog.set_response_appearance("add", adw::ResponseAppearance::Suggested);
    dialog.set_default_response(Some("add"));
    dialog.set_close_response("cancel");
    dialog.set_response_enabled("add", false);
    {
        let dialog = dialog.clone();
        let home = ui.home.clone();
        entry.connect_changed(move |e| {
            dialog.set_response_enabled("add", resolve_program(&e.text(), &home).is_some());
        });
    }
    let ui2 = ui.clone();
    let path = path.to_string();
    dialog.connect_response(Some("add"), move |_, _| {
        let Some(program) = resolve_program(&entry.text(), &ui2.home) else {
            return;
        };
        let program = program.display().to_string();
        let action = if access.selected() == 0 {
            let secs = DURATIONS[(duration.selected() as usize).min(DURATIONS.len() - 1)].1;
            Action::Allow {
                path: path.clone(),
                program,
                pin: secs.is_none() && pin.is_active(),
                secs,
            }
        } else {
            Action::Deny {
                path: path.clone(),
                program,
            }
        };
        ui2.run_action(action);
    });
    dialog.present(Some(&ui.window));
}

pub fn confirm_unprotect(ui: &Rc<Ui>, path: &str) {
    let dialog = adw::AlertDialog::new(
        Some("Stop protecting this path?"),
        Some(&format!(
            "{}\n\nEvery program will be able to open it again, and the answers you gave \
             for it are deleted.",
            crate::model::display_path(path, &ui.home)
        )),
    );
    dialog.add_responses(&[("cancel", "_Cancel"), ("unprotect", "_Stop protecting")]);
    dialog.set_response_appearance("unprotect", adw::ResponseAppearance::Destructive);
    dialog.set_default_response(Some("cancel"));
    dialog.set_close_response("cancel");
    let ui2 = ui.clone();
    let path = path.to_string();
    dialog.connect_response(Some("unprotect"), move |_, _| {
        ui2.run_action(Action::Unprotect { path: path.clone() });
    });
    dialog.present(Some(&ui.window));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_is_expanded() {
        let home = Path::new("/home/u");
        assert_eq!(expand_home("~/.ssh", home), PathBuf::from("/home/u/.ssh"));
        assert_eq!(expand_home("~", home), PathBuf::from("/home/u"));
        assert_eq!(expand_home("/etc", home), PathBuf::from("/etc"));
    }

    #[test]
    fn programs_resolve_through_path_and_symlinks() {
        let sh = resolve_program("sh", Path::new("/")).expect("sh is on PATH");
        assert!(sh.is_absolute());
        assert_eq!(sh, std::fs::canonicalize(&sh).unwrap());
        assert!(resolve_program("", Path::new("/")).is_none());
        assert!(resolve_program("/nonexistent/x", Path::new("/")).is_none());
    }
}
