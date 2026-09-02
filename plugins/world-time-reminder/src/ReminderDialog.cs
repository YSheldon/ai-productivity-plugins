using System;
using System.Drawing;
using System.Windows.Forms;

internal sealed class ReminderDialog : Form
{
    private const int AutoCloseMinutes = 16;
    private readonly TextBox confirmationInput;
    private readonly Timer autoCloseTimer;
    private bool closeAuthorized;

    internal ReminderDialog()
    {
        Text = "First Duty Rest Reminder";
        BackColor = Color.Black;
        ForeColor = Color.White;
        FormBorderStyle = FormBorderStyle.None;
        WindowState = FormWindowState.Maximized;
        StartPosition = FormStartPosition.Manual;
        TopMost = true;
        KeyPreview = true;
        ShowInTaskbar = true;

        Font mainFont = new Font("Microsoft YaHei UI", 28.0f, FontStyle.Bold);
        Font instructionFont = new Font("Microsoft YaHei UI", 14.0f, FontStyle.Regular);

        TableLayoutPanel root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            BackColor = Color.Black,
            ColumnCount = 1,
            RowCount = 3
        };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100.0f));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 50.0f));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 50.0f));

        TableLayoutPanel message = new TableLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            BackColor = Color.Black,
            ColumnCount = 1,
            RowCount = 3,
            Anchor = AnchorStyles.None,
            Padding = new Padding(80)
        };
        message.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

        Label restLabel = new Label
        {
            AutoSize = true,
            Text = "\u95ed\u773c\u4f11\u606f\u3002",
            Font = mainFont,
            ForeColor = Color.White,
            BackColor = Color.Black,
            Anchor = AnchorStyles.None,
            Margin = new Padding(0)
        };

        FlowLayoutPanel dutyLine = new FlowLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            BackColor = Color.Black,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            Anchor = AnchorStyles.None,
            Margin = new Padding(0, 12, 0, 0)
        };
        dutyLine.Controls.Add(CreateMessagePart("\u770b\u770b\u624b\u673a\u6709\u6ca1\u6709\u672a\u5b8c\u6210\u7684", mainFont, Color.White));
        dutyLine.Controls.Add(CreateMessagePart("\u7b2c\u4e00\u8981\u52a1", mainFont, Color.FromArgb(255, 246, 190)));
        dutyLine.Controls.Add(CreateMessagePart("\u3002", mainFont, Color.White));

        TableLayoutPanel confirmation = new TableLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            BackColor = Color.Black,
            ColumnCount = 1,
            RowCount = 2,
            Anchor = AnchorStyles.None,
            Margin = new Padding(0, 32, 0, 0)
        };
        confirmation.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

        Label instructionLabel = new Label
        {
            AutoSize = true,
            Text = "\u8f93\u5165 Y \u540e\u6309 Enter \u6216\u70b9\u51fb\u5173\u95ed\uff1b16\u5206\u949f\u540e\u81ea\u52a8\u5173\u95ed",
            Font = instructionFont,
            ForeColor = Color.White,
            BackColor = Color.Black,
            Anchor = AnchorStyles.None,
            Margin = new Padding(0, 0, 0, 8)
        };

        confirmationInput = new TextBox
        {
            Width = 220,
            BackColor = Color.FromArgb(24, 24, 24),
            ForeColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Microsoft YaHei UI", 16.0f, FontStyle.Regular),
            TextAlign = HorizontalAlignment.Center,
            Margin = new Padding(0)
        };

        Button closeButton = new Button
        {
            Text = "\u5173\u95ed",
            BackColor = Color.Black,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Font = instructionFont,
            Size = new Size(68, 34),
            Margin = new Padding(12, 0, 0, 0),
            TabStop = false
        };
        closeButton.FlatAppearance.BorderColor = Color.White;
        closeButton.Click += delegate { TryClose(); };

        FlowLayoutPanel confirmationRow = new FlowLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            BackColor = Color.Black,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            Anchor = AnchorStyles.None,
            Margin = new Padding(0)
        };
        confirmationRow.Controls.Add(confirmationInput);
        confirmationRow.Controls.Add(closeButton);

        confirmation.Controls.Add(instructionLabel, 0, 0);
        confirmation.Controls.Add(confirmationRow, 0, 1);
        message.Controls.Add(restLabel, 0, 0);
        message.Controls.Add(dutyLine, 0, 1);
        message.Controls.Add(confirmation, 0, 2);
        root.Controls.Add(message, 0, 1);
        Controls.Add(root);

        AcceptButton = closeButton;
        FormClosing += OnFormClosing;
        Shown += delegate { confirmationInput.Focus(); };

        autoCloseTimer = new Timer { Interval = AutoCloseMinutes * 60 * 1000 };
        autoCloseTimer.Tick += delegate
        {
            autoCloseTimer.Stop();
            closeAuthorized = true;
            Close();
        };
        FormClosed += delegate
        {
            autoCloseTimer.Stop();
            autoCloseTimer.Dispose();
        };
        Shown += delegate { autoCloseTimer.Start(); };
    }

    private static Label CreateMessagePart(string text, Font font, Color color)
    {
        return new Label
        {
            AutoSize = true,
            Text = text,
            Font = font,
            ForeColor = color,
            BackColor = Color.Black,
            Margin = new Padding(0)
        };
    }

    private void TryClose()
    {
        if (String.Equals(confirmationInput.Text.Trim(), "Y", StringComparison.OrdinalIgnoreCase))
        {
            closeAuthorized = true;
            Close();
            return;
        }

        System.Media.SystemSounds.Beep.Play();
        confirmationInput.Focus();
        confirmationInput.SelectAll();
    }

    private void OnFormClosing(object sender, FormClosingEventArgs eventArgs)
    {
        if (!closeAuthorized)
        {
            eventArgs.Cancel = true;
            confirmationInput.Focus();
        }
    }
}
