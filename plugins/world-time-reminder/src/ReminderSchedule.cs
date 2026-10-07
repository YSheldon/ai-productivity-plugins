using System;
using System.Globalization;

internal static class ReminderSchedule
{
    private static readonly int[] ReminderHours = { 7, 8, 9, 10, 11, 14, 15, 16, 17, 20, 21, 22, 23 };
    private const int ExactMinuteGraceSeconds = 5;

    internal static readonly TimeZoneInfo BeijingTimeZone = TimeZoneInfo.FindSystemTimeZoneById("China Standard Time");

    internal static bool IsExactReminderMoment(DateTimeOffset utcNow, out DateTimeOffset beijingNow, out string reminderKey)
    {
        beijingNow = TimeZoneInfo.ConvertTime(utcNow, BeijingTimeZone);
        reminderKey = beijingNow.ToString("yyyy-MM-dd-HH", CultureInfo.InvariantCulture);

        return beijingNow.Minute == 0
            && beijingNow.Second <= ExactMinuteGraceSeconds
            && Array.IndexOf(ReminderHours, beijingNow.Hour) >= 0;
    }

    internal static int CheckUtcArgument(string value)
    {
        DateTimeOffset utcNow;
        if (!DateTimeOffset.TryParse(
                value,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out utcNow))
        {
            return 2;
        }

        DateTimeOffset beijingNow;
        string reminderKey;
        return IsExactReminderMoment(utcNow, out beijingNow, out reminderKey) ? 10 : 0;
    }
}
