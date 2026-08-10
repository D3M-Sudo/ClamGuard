# Palette's Journal

This journal stores critical UX/accessibility learnings for ClamGuard.
Only add entries for critical learnings, not routine work.

## 2026-03-01 - Preventing Accidental Loss in Quarantine and Enhancing Header Bar Discoverability
**Learning:** In desktop environments, actions like "Delete permanently" on a quarantined file should always require validation to prevent accidental data loss. Furthermore, Libadwaita/GTK4 header bar elements, such as icon-only menu buttons, can pose accessibility hurdles and lack mouse-hover context if they lack tooltips.
**Action:** Always wrap destructive operations in `Adw.MessageDialog` with a `DESTRUCTIVE` style presentation for confirmation, and ensure all icon-only headers/buttons include localized tooltip text.
