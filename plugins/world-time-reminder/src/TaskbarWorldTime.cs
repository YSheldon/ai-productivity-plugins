using System;
using System.Drawing;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Windows.Forms;

internal sealed class TaskbarWorldTime : Form
{
    private const string ClockTimeFormat = "HH:mm";
    private const string ClockDateFormat = "M/d";
    private const int ClockWidth = 69;
    private const int ClockHeight = 32;
    private const int HorizontalOffset = -13;
    private const string ClockFontName = "Segoe UI";
    private const float ClockFontSize = 9.0f;

    private static readonly IntPtr HwndTopmost = new IntPtr(-1);

    private const int WsExToolWindow = 0x00000080;
    private const int WsExNoActivate = 0x08000000;
    private const int SwShowNoActivate = 4;
    private const uint SwpNoActivate = 0x0010;
    private const uint SwpShowWindow = 0x0040;

    private readonly Label label;
    private readonly NotifyIcon notifyIcon;
    private readonly Timer clockTimer;
    private readonly ReminderStateStore reminderState;

    protected override CreateParams CreateParams
    {
        get
        {
            CreateParams createParams = base.CreateParams;
            createParams.ExStyle |= WsExToolWindow | WsExNoActivate;
            return createParams;
        }
    }

    internal TaskbarWorldTime()
    {
        reminderState = new ReminderStateStore();

        Width = ClockWidth;
        Height = ClockHeight;
        FormBorderStyle = FormBorderStyle.None;
        ShowInTaskbar = false;
        StartPosition = FormStartPosition.Manual;
        TopMost = true;
        BackColor = Color.FromArgb(32, 32, 32);

        label = new Label
        {
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleCenter,
            ForeColor = Color.White,
            Font = new Font(ClockFontName, ClockFontSize, FontStyle.Regular),
            BackColor = Color.FromArgb(32, 32, 32)
        };
        Controls.Add(label);

        ContextMenuStrip menu = new ContextMenuStrip();
        ToolStripMenuItem showItem = new ToolStripMenuItem("\u91cd\u65b0\u663e\u793a\u5230\u4efb\u52a1\u680f");
        showItem.Click += delegate { RestoreToTaskbar(); };
        ToolStripMenuItem exitItem = new ToolStripMenuItem("\u9000\u51fa\u4e16\u754c\u65f6\u95f4");
        exitItem.Click += delegate { Close(); };
        menu.Items.Add(showItem);
        menu.Items.Add(exitItem);

        notifyIcon = new NotifyIcon
        {
            Icon = SystemIcons.Information,
            ContextMenuStrip = menu,
            Text = "\u4e16\u754c\u65f6\u95f4",
            Visible = true
        };
        notifyIcon.DoubleClick += delegate { RestoreToTaskbar(); };

        clockTimer = new Timer { Interval = 1000 };
        clockTimer.Tick += delegate
        {
            UpdateClock();
            KeepOnTaskbar();
            TryShowReminder();
        };

        Load += delegate
        {
            reminderState.WriteLog("started");
            UpdateClock();
            KeepOnTaskbar();
            TryShowReminder();
            clockTimer.Start();
        };

        FormClosed += delegate
        {
            clockTimer.Stop();
            notifyIcon.Visible = false;
            notifyIcon.Dispose();
            reminderState.WriteLog("stopped");
        };
    }

    private void RestoreToTaskbar()
    {
        if (WindowState == FormWindowState.Minimized)
        {
            WindowState = FormWindowState.Normal;
        }

        Show();
        ShowWindow(Handle, SwShowNoActivate);
        UpdateClock();
        KeepOnTaskbar();
    }

    private void KeepOnTaskbar()
    {
        Rectangle bounds = Screen.PrimaryScreen.Bounds;
        Rectangle workArea = Screen.PrimaryScreen.WorkingArea;

        int x;
        int y;

        if (workArea.Bottom < bounds.Bottom)
        {
            int taskbarHeight = bounds.Bottom - workArea.Bottom;
            Width = ClockWidth;
            Height = ClockHeight;
            x = bounds.Right - Width + HorizontalOffset;
            y = workArea.Bottom + ((taskbarHeight - Height) / 2);
        }
        else if (workArea.Top > bounds.Top)
        {
            int taskbarHeight = workArea.Top - bounds.Top;
            Width = ClockWidth;
            Height = ClockHeight;
            x = bounds.Right - Width + HorizontalOffset;
            y = bounds.Top + ((taskbarHeight - Height) / 2);
        }
        else if (workArea.Right < bounds.Right)
        {
            int taskbarWidth = bounds.Right - workArea.Right;
            Width = Math.Max(ClockWidth, taskbarWidth - 8);
            Height = ClockHeight;
            x = workArea.Right + ((taskbarWidth - Width) / 2);
            y = bounds.Bottom - Height - 120;
        }
        else
        {
            int taskbarWidth = workArea.Left - bounds.Left;
            Width = Math.Max(ClockWidth, taskbarWidth - 8);
            Height = ClockHeight;
            x = bounds.Left + ((taskbarWidth - Width) / 2);
            y = bounds.Bottom - Height - 120;
        }

        SetWindowPos(
            Handle,
            HwndTopmost,
            Math.Max(bounds.Left, x),
            Math.Max(bounds.Top, y),
            Width,
            Height,
            SwpNoActivate | SwpShowWindow);
    }

    private void UpdateClock()
    {
        DateTimeOffset beijingNow = TimeZoneInfo.ConvertTime(DateTimeOffset.UtcNow, ReminderSchedule.BeijingTimeZone);
        string time = beijingNow.ToString(ClockTimeFormat, CultureInfo.InvariantCulture);
        string date = beijingNow.ToString(ClockDateFormat, CultureInfo.InvariantCulture);
        label.Text = time + Environment.NewLine + date;
        notifyIcon.Text = "\u5317\u4eac\u65f6\u95f4 " + time + " " + date;
    }

    private void TryShowReminder()
    {
        DateTimeOffset beijingNow;
        string reminderKey;
        if (!ReminderSchedule.IsExactReminderMoment(DateTimeOffset.UtcNow, out beijingNow, out reminderKey))
        {
            return;
        }

        if (!reminderState.TryReserve(reminderKey))
        {
            return;
        }

        using (ReminderDialog dialog = new ReminderDialog())
        {
            dialog.ShowDialog(this);
        }
    }

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr handle, int command);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetWindowPos(
        IntPtr handle,
        IntPtr insertAfter,
        int x,
        int y,
        int width,
        int height,
        uint flags);

    [STAThread]
    private static void Main(string[] args)
    {
        if (args.Length == 2 && String.Equals(args[0], "--check-utc", StringComparison.Ordinal))
        {
            Environment.Exit(ReminderSchedule.CheckUtcArgument(args[1]));
            return;
        }

        bool createdNew;
        using (System.Threading.Mutex singleInstance = new System.Threading.Mutex(true, "Local\\WorldTimeReminder", out createdNew))
        {
            if (!createdNew)
            {
                return;
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new TaskbarWorldTime());
        }
    }
}
