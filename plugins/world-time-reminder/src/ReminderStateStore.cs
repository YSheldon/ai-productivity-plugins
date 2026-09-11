using System;
using System.IO;
using System.Text;

internal sealed class ReminderStateStore
{
    private readonly string stateDirectory;
    private readonly string statePath;
    private readonly string logPath;

    internal ReminderStateStore()
    {
        stateDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "WorldTimeReminder");
        statePath = Path.Combine(stateDirectory, "last-reminder.txt");
        logPath = Path.Combine(stateDirectory, "reminder.log");
    }

    internal bool TryReserve(string reminderKey)
    {
        try
        {
            Directory.CreateDirectory(stateDirectory);
            string previousKey = File.Exists(statePath) ? File.ReadAllText(statePath).Trim() : string.Empty;
            if (String.Equals(previousKey, reminderKey, StringComparison.Ordinal))
            {
                return false;
            }

            File.WriteAllText(statePath, reminderKey + Environment.NewLine, new UTF8Encoding(false));
            WriteLog("reserved key=" + reminderKey);
            return true;
        }
        catch (Exception exception)
        {
            WriteLog("state failure: " + exception.Message);
            return true;
        }
    }

    internal void WriteLog(string message)
    {
        try
        {
            Directory.CreateDirectory(stateDirectory);
            string timestamp = TimeZoneInfo.ConvertTime(DateTimeOffset.UtcNow, ReminderSchedule.BeijingTimeZone).ToString("o");
            File.AppendAllText(logPath, timestamp + " " + message + Environment.NewLine, new UTF8Encoding(false));
        }
        catch
        {
        }
    }
}
