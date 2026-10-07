---
name: world-time-reminder
description: Build, install, or diagnose the local Windows taskbar Beijing clock and exact-hour first-duty reminder. Use when the user asks to manage the taskbar world time display, its Beijing-time reminder schedule, or its installation.
---

# World Time Reminder

Use the packaged PowerShell scripts rather than editing installed copies directly.

- Build with `scripts/Build-WorldTimeReminder.ps1`.
- Install or repair the current-user task with `scripts/Install-WorldTimeReminder.ps1 -RunNow`.
- Run `tests/Test-WorldTimeReminder.ps1` after source or task-template changes.
- The app only reminds at Beijing `07:00-11:00`, `14:00-17:00`, and `20:00-23:00`, within the first five seconds of the hour. It intentionally skips an hour missed during sleep or resume.
- The full-screen reminder accepts `Y` or `y` plus Enter (or the close button), and otherwise closes after 16 minutes.
