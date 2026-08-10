# UX and Accessibility Design Journal

This journal documents critical, repository-specific UX and accessibility design learnings.

## 1. Zero-Privilege UI Model
- Keep high-privilege operations isolated in a small helper utility.
- Build the main application UI as a standard user process, showing non-blocking toasts and disabling controls appropriately during background processing.

## 2. Non-blocking Async Tasks
- Heavy I/O tasks (e.g. signature updates or scanner loops) must not run in the main GTK4 thread.
- Move these tasks to Python background threads, and dispatch final UI changes securely via `GLib.idle_add()`.
