# UX and Accessibility Design Journal

This journal documents critical, repository-specific UX and accessibility design learnings.

## 2026-03-01 - Preventing Accidental Loss in Quarantine and Enhancing Header Bar Discoverability
**Learning:** In desktop environments, actions like "Delete permanently" on a quarantined file should always require validation to prevent accidental data loss. Furthermore, Libadwaita/GTK4 header bar elements, such as icon-only menu buttons, can pose accessibility hurdles and lack mouse-hover context if they lack tooltips.
**Action:** Always wrap destructive operations in `Adw.MessageDialog` with a `DESTRUCTIVE` style presentation for confirmation, and ensure all icon-only headers/buttons include localized tooltip text.

## 2026-03-05 - Dynamic Screen Reader Context for Repeating Actions and Button Feedback
**Learning:** Standard icon-only list action buttons (e.g., 'Restore' and 'Delete permanently' in the quarantine list) suffer from severe screen-reader ambiguity when many rows are present. Setting a static `accessible-name` on the button means the screen reader says the exact same generic string for every row. Dynamically composing a contextual `accessible-name` (e.g., combining the action with the row's specific file name) dramatically improves accessibility. Also, disabling interactive trigger buttons and presenting dynamic labels during asynchronous scan states clarifies app state.
**Action:** Set dynamic, context-specific properties for `accessible-name` and `tooltip-text` using file details, and manage scan button sensitivity during long background processing.

## 1. Zero-Privilege UI Model
- Keep high-privilege operations isolated in a small helper utility.
- Build the main application UI as a standard user process, showing non-blocking toasts and disabling controls appropriately during background processing.

## 2. Non-blocking Async Tasks
- Heavy I/O tasks (e.g. signature updates or scanner loops) must not run in the main GTK4 thread.
- Move these tasks to Python background threads, and dispatch final UI changes securely via `GLib.idle_add()`.
