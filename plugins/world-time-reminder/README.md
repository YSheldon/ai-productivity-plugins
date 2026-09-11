# World Time Reminder

`world-time-taskbar.exe` is a single Windows desktop application that combines:

- a compact taskbar display of Beijing time;
- exact-hour rest reminders at `07:00-11:00`, `14:00-17:00`, and `20:00-23:00` Beijing time;
- a full-screen black reminder that accepts `Y` or `y` plus Enter, or closes automatically after 16 minutes.

The clock process checks the Beijing clock once per second. It only shows a reminder in the first five seconds of a configured hour, so a laptop waking up at `15:32` does not show a late `15:00` reminder.

## Install

On Windows PowerShell 5.1 with .NET Framework 4.x:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\plugins\world-time-reminder\scripts\Install-WorldTimeReminder.ps1 -RunNow
```

Installation builds the executable under `%LOCALAPPDATA%\Programs\WorldTimeReminder` and registers one current-user `WorldTimeReminder` task. That task starts after logon and is retriggered every minute if the program exits. A single-instance mutex prevents duplicate clock windows.

The installer removes the legacy `FirstDutyRestReminder` task, its Startup launcher, and the legacy Beijing taskbar Startup shortcut only after the new unified task is registered.

## Verify

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\plugins\world-time-reminder\tests\Test-WorldTimeReminder.ps1
```

## Uninstall

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\plugins\world-time-reminder\scripts\Uninstall-WorldTimeReminder.ps1
```
