using Ilac.Shared.Models;
using Ilac.Shared.Services;

namespace Ilac.Checker;

public partial class Form1 : Form
{
    private int _aiQuestionsLeft = 5;
    private readonly ScanConfig _config = new();
    private bool _isBuilding;
    private int _activeSection = -1;
    private readonly string[] _sectionNames = { "Webhook", "Browser", "Forensic", "Bypass", "Advanced" };

    private readonly Panel _sidebar = new();
    private readonly Panel _contentPanel = new();
    private readonly List<Button> _sectionBtns = new();
    private readonly Label _statusLabel = new();
    private readonly ProgressBar _progressBar = new();
    private readonly Panel _statusBar = new();
    private readonly Panel _accentBar = new();
    private TextBox? _webhookInput;
    private TextBox? _aiQuestionInput;
    private TextBox? _groqInput;
    private Button? _buildBtn;
    private System.Windows.Forms.Timer? _animTimer;
    private Panel? _currentPanel;
    private float _animProgress;
    private int _animDividerTarget;

    static readonly Color C_BG = Color.FromArgb(0, 0, 0);
    static readonly Color C_PANEL = Color.FromArgb(10, 10, 10);
    static readonly Color C_PANEL2 = Color.FromArgb(20, 20, 20);
    static readonly Color C_PANEL3 = Color.FromArgb(30, 30, 30);
    static readonly Color C_ACCENT = Color.FromArgb(240, 240, 240);
    static readonly Color C_ACCENT2 = Color.FromArgb(255, 255, 255);
    static readonly Color C_TEXT = Color.FromArgb(230, 230, 230);
    static readonly Color C_SUBTLE = Color.FromArgb(120, 120, 120);
    static readonly Color C_BLOOD = Color.FromArgb(200, 200, 200);

    private Image? _bgImage;
    private float _bgAlpha = 0.12f;

    public Form1()
    {
        Size = new Size(1120, 740);
        MinimumSize = new Size(980, 620);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = C_BG;
        DoubleBuffered = true;
        FormBorderStyle = FormBorderStyle.None;
        Text = "ilac.cc MTA Cheat Checker";
        Font = new Font("Georgia", 9);

        // Load icon at runtime
        try
        {
            var iconPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "app.ico");
            if (File.Exists(iconPath))
                Icon = new Icon(iconPath);
        }
        catch { }

        // Load background image — pre-blend with black for transparency effect
        try
        {
            var bgPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "bg.jpg");
            if (File.Exists(bgPath))
            {
                var rawImg = Image.FromFile(bgPath);
                var bmp = new Bitmap(ClientSize.Width, ClientSize.Height);
                using (var g = Graphics.FromImage(bmp))
                {
                    g.Clear(C_BG);
                    var cm = new System.Drawing.Imaging.ColorMatrix { Matrix33 = 0.12f };
                    var ia = new System.Drawing.Imaging.ImageAttributes();
                    ia.SetColorMatrix(cm);
                    g.DrawImage(rawImg, new Rectangle(0, 0, bmp.Width, bmp.Height),
                        0, 0, rawImg.Width, rawImg.Height, GraphicsUnit.Pixel, ia);
                }
                BackgroundImage = bmp;
                BackgroundImageLayout = ImageLayout.Stretch;
            }
        }
        catch { }

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 3,
            BackColor = Color.Transparent
        };
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 54));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 228));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        BuildHeader(layout);
        BuildSidebar(layout);
        BuildContent(layout);
        BuildStatusBar(layout);

        Controls.Add(layout);

        _animTimer = new System.Windows.Forms.Timer { Interval = 15 };
        _animTimer.Tick += AnimTick;

        Resize += (_, _) => _accentBar.Width = _contentPanel.ClientSize.Width - 40;
    }

    private void BuildHeader(TableLayoutPanel layout)
    {
        var header = new Panel { Dock = DockStyle.Fill, BackColor = C_PANEL };
        header.Paint += (_, e) =>
        {
            using var pen = new Pen(C_ACCENT, 1);
            e.Graphics.DrawLine(pen, 0, header.Height - 1, header.Width, header.Height - 1);
        };

        var titleLbl = new Label
        {
            Text = "ilac.cc",
            Font = new Font("Georgia", 16, FontStyle.Bold),
            ForeColor = C_ACCENT,
            AutoSize = true,
            Location = new Point(16, 14)
        };
        header.Controls.Add(titleLbl);
        var subLbl = new Label
        {
            Text = "MTA Cheat Checker",
            Font = new Font("Georgia", 8, FontStyle.Italic),
            ForeColor = C_SUBTLE,
            AutoSize = true,
            Location = new Point(120, 22)
        };
        header.Controls.Add(subLbl);

        var closeBtn = new Button
        {
            Text = "\u2715",
            Font = new Font("Georgia", 10),
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.Transparent,
            ForeColor = C_SUBTLE,
            Size = new Size(38, 36),
            Cursor = Cursors.Hand,
            FlatAppearance = { BorderSize = 0, MouseOverBackColor = C_BLOOD, MouseDownBackColor = C_ACCENT }
        };
        var minBtn = new Button
        {
            Text = "\u2013",
            Font = new Font("Georgia", 10),
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.Transparent,
            ForeColor = C_SUBTLE,
            Size = new Size(38, 36),
            Cursor = Cursors.Hand,
            FlatAppearance = { BorderSize = 0, MouseOverBackColor = C_PANEL2, MouseDownBackColor = C_PANEL3 }
        };
        closeBtn.Click += (_, _) => Close();
        minBtn.Click += (_, _) => WindowState = FormWindowState.Minimized;
        closeBtn.Location = new Point(Width - 44, 10);
        minBtn.Location = new Point(Width - 86, 10);
        header.Controls.Add(closeBtn);
        header.Controls.Add(minBtn);

        bool drag = false; Point dragStart = default;
        header.MouseDown += (_, e) => { if (e.Button == MouseButtons.Left) { drag = true; dragStart = e.Location; } };
        header.MouseMove += (_, e) => { if (drag) Location = new Point(Location.X + e.X - dragStart.X, Location.Y + e.Y - dragStart.Y); };
        header.MouseUp += (_, _) => drag = false;

        Resize += (_, _) =>
        {
            closeBtn.Location = new Point(Width - 44, 10);
            minBtn.Location = new Point(Width - 86, 10);
        };

        layout.Controls.Add(header, 0, 0);
        layout.SetColumnSpan(header, 2);
    }

    private void BuildSidebar(TableLayoutPanel layout)
    {
        _sidebar.Dock = DockStyle.Fill;
        _sidebar.BackColor = C_PANEL;
        _sidebar.Paint += (_, e) =>
        {
            using var pen = new Pen(C_PANEL2);
            e.Graphics.DrawLine(pen, _sidebar.Width - 1, 0, _sidebar.Width - 1, _sidebar.Height);
        };

        var logoLbl = new Label
        {
            Text = "ilac.cc",
            Font = new Font("Georgia", 22, FontStyle.Bold),
            ForeColor = C_ACCENT,
            Location = new Point(20, 18),
            AutoSize = true
        };
        _sidebar.Controls.Add(logoLbl);
        _sidebar.Controls.Add(new Label
        {
            Text = "",
            Font = new Font("Georgia", 8, FontStyle.Italic),
            ForeColor = C_SUBTLE,
            Location = new Point(22, 52),
            AutoSize = true
        });
        _sidebar.Controls.Add(new Panel { BackColor = C_PANEL2, Bounds = new Rectangle(16, 76, 196, 1) });

        for (int i = 0; i < 5; i++)
        {
            var idx = i;
            var btn = new Button
            {
                Text = "  " + _sectionNames[i],
                Font = new Font("Georgia", 10),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.Transparent,
                ForeColor = C_SUBTLE,
                Size = new Size(200, 40),
                Location = new Point(14, 90 + i * 44),
                TextAlign = ContentAlignment.MiddleLeft,
                Cursor = Cursors.Hand,
                FlatAppearance = { BorderSize = 0, MouseOverBackColor = C_PANEL2, MouseDownBackColor = C_PANEL3 }
            };
            btn.Click += (_, _) => SwitchSection(idx);
            _sidebar.Controls.Add(btn);
            _sectionBtns.Add(btn);
        }

        _buildBtn = new Button
        {
            Text = "  BUILD CLIENT",
            Font = new Font("Georgia", 11, FontStyle.Bold),
            FlatStyle = FlatStyle.Flat,
            BackColor = C_TEXT,
            ForeColor = Color.Black,
            Size = new Size(200, 46),
            Location = new Point(14, 90 + 5 * 44 + 18),
            TextAlign = ContentAlignment.MiddleLeft,
            Cursor = Cursors.Hand,
            FlatAppearance = { BorderSize = 0, MouseOverBackColor = Color.White, MouseDownBackColor = C_PANEL3 }
        };
        _buildBtn.Click += BuildClient;
        _sidebar.Controls.Add(_buildBtn);

        _sidebar.Controls.Add(new Label
        {
            Text = "Author: madaruw",
            Font = new Font("Georgia", 7, FontStyle.Italic),
            ForeColor = C_SUBTLE,
            Location = new Point(20, _buildBtn.Bottom + 14),
            AutoSize = true
        });

        layout.Controls.Add(_sidebar, 0, 1);
    }

    private void BuildContent(TableLayoutPanel layout)
    {
        _contentPanel.Dock = DockStyle.Fill;
        _contentPanel.BackColor = C_BG;
        _contentPanel.AutoScroll = false;
        _contentPanel.Padding = new Padding(10);
        layout.Controls.Add(_contentPanel, 1, 1);
    }

    private void BuildStatusBar(TableLayoutPanel layout)
    {
        _statusBar.Dock = DockStyle.Fill;
        _statusBar.BackColor = C_PANEL;
        _statusBar.Paint += (_, e) =>
        {
            using var pen = new Pen(C_PANEL2);
            e.Graphics.DrawLine(pen, 0, 0, _statusBar.Width, 0);
        };

        _statusLabel.Text = "Ready";
        _statusLabel.Font = new Font("Georgia", 8);
        _statusLabel.ForeColor = C_SUBTLE;
        _statusLabel.AutoSize = true;
        _statusLabel.Location = new Point(12, 7);
        _statusBar.Controls.Add(_statusLabel);

        _progressBar.Style = ProgressBarStyle.Marquee;
        _progressBar.Size = new Size(180, 10);
        _progressBar.Visible = false;
        _progressBar.ForeColor = C_ACCENT;
        _progressBar.BackColor = C_PANEL2;
        _progressBar.Location = new Point(Width - 200, 10);
        _statusBar.Controls.Add(_progressBar);

        layout.Controls.Add(_statusBar, 1, 2);
        layout.SetColumnSpan(_statusBar, 2);

        Resize += (_, _) => _progressBar.Location = new Point(Width - 200, 10);
    }

    protected override void OnLoad(EventArgs e)
    {
        base.OnLoad(e);
        SwitchSection(0);
        try
        {
            var cfgPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ilac.cc", "webhook.txt");
            if (File.Exists(cfgPath) && _webhookInput != null)
            {
                _webhookInput.Text = File.ReadAllText(cfgPath).Trim();
                Sts("Saved webhook loaded");
            }
            var keyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ilac.cc", "groq_key.txt");
            if (File.Exists(keyPath))
            {
                _config.GroqApiKey = File.ReadAllText(keyPath).Trim();
            }
        }
        catch { }
    }

    private void SwitchSection(int idx)
    {
        if (idx == _activeSection) return;
        // Save current input values before switching
        var savedWebhook = _webhookInput?.Text ?? "";
        var savedAiQuestion = _aiQuestionInput?.Text ?? "";
        _activeSection = idx;
        for (int i = 0; i < _sectionBtns.Count; i++)
        {
            _sectionBtns[i].ForeColor = i == idx ? C_ACCENT2 : C_SUBTLE;
            _sectionBtns[i].BackColor = i == idx ? C_PANEL2 : Color.Transparent;
        }
        ShowSection(idx);
        // Restore saved values
        if (_webhookInput != null && !string.IsNullOrEmpty(savedWebhook)) _webhookInput.Text = savedWebhook;
        if (_aiQuestionInput != null && !string.IsNullOrEmpty(savedAiQuestion)) _aiQuestionInput.Text = savedAiQuestion;
    }

    private void ShowSection(int idx)
    {
        _contentPanel.Controls.Clear();
        var p = idx switch
        {
            0 => SectionWebhook(),
            1 => SectionBrowser(),
            2 => SectionForensic(),
            3 => SectionBypass(),
            4 => SectionAdvanced(),
            _ => new Panel()
        };
        p.Width = Math.Max(600, _contentPanel.ClientSize.Width - 4);
        _contentPanel.Controls.Add(p);
        _currentPanel = p;

        _animProgress = 0;
        _animDividerTarget = 0;
        p.Location = new Point(28, p.Location.Y);
        _animTimer?.Start();
    }

    private void AnimTick(object? sender, EventArgs e)
    {
        if (_currentPanel == null) { _animTimer?.Stop(); return; }
        _animProgress += 0.09f;
        if (_animProgress >= 1f) _animProgress = 1f;

        var eased = 1f - (1f - _animProgress) * (1f - _animProgress) * (1f - _animProgress);
        var x = (int)(28 * (1f - eased));
        _currentPanel.Location = new Point(x, _currentPanel.Location.Y);

        if (_accentBar.Parent == _currentPanel)
        {
            _animDividerTarget = Math.Min(640, _currentPanel.ClientSize.Width - 40);
            _accentBar.Width = (int)(_animDividerTarget * eased);
        }

        if (_animProgress >= 1f)
        {
            _currentPanel.Location = new Point(0, _currentPanel.Location.Y);
            if (_accentBar.Parent == _currentPanel) _accentBar.Width = _animDividerTarget;
            _animTimer?.Stop();
        }
    }

    private Panel SectionWebhook()
    {
        var p = Base("Webhook Configuration", "Where scan results are delivered.");
        int y = 80;
        Lbl(p, "Discord Webhook URL", y);
        _webhookInput = Tb(p, y + 24, 520); y += 60;

        var saveBtn = Btn(p, y, "Save Webhook", Color.FromArgb(40, 80, 120), (_, _) =>
        {
            try
            {
                if (string.IsNullOrEmpty(_webhookInput?.Text)) { Sts("Enter webhook URL first"); return; }
                var cfgPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ilac.cc", "webhook.txt");
                Directory.CreateDirectory(Path.GetDirectoryName(cfgPath)!);
                File.WriteAllText(cfgPath, _webhookInput.Text);
                Sts("Webhook saved");
            }
            catch (Exception ex) { Sts("Save error: " + ex.Message); }
        });
        p.Controls.Add(saveBtn);

        var loadBtn = Btn(p, y, "Load Saved", Color.FromArgb(60, 60, 84), (_, _) =>
        {
            try
            {
                var cfgPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ilac.cc", "webhook.txt");
                if (File.Exists(cfgPath) && _webhookInput != null)
                { _webhookInput.Text = File.ReadAllText(cfgPath).Trim(); Sts("Webhook loaded"); }
                else Sts("No saved webhook found");
            }
            catch (Exception ex) { Sts("Load error: " + ex.Message); }
        });
        loadBtn.Location = new Point(170, y);
        loadBtn.Width = 110;
        p.Controls.Add(loadBtn);
        y += 46;

        var testBtn = Btn(p, y, "Test Webhook", Color.FromArgb(0, 120, 60), async (_, _) =>
        {
            if (string.IsNullOrEmpty(_webhookInput?.Text)) { Sts("Enter webhook URL"); return; }
            var ok = await new WebhookService().SendScanStarted(_webhookInput.Text, Environment.MachineName, Environment.UserName);
            Sts(ok ? "Webhook OK" : "Failed");
        });
        p.Controls.Add(testBtn); y += 56;

        // AI Soru kutusu
        Lbl(p, "AI'a Soru (tespit hakkinda sor)", y);
        _aiQuestionInput = Tb(p, y + 24, 460); y += 58;
        var aiSendBtn = new Button
        {
            Text = $"Gonder ({_aiQuestionsLeft} hak)",
            Font = new Font("Georgia", 9, FontStyle.Bold),
            BackColor = Color.FromArgb(40, 160, 60),
            ForeColor = Color.White,
            Size = new Size(140, 34),
            Location = new Point(24, y),
            Cursor = Cursors.Hand,
            FlatStyle = FlatStyle.Flat,
            FlatAppearance = { BorderSize = 0, MouseOverBackColor = Color.FromArgb(60, 200, 80), MouseDownBackColor = Color.FromArgb(30, 120, 45) }
        };
        aiSendBtn.Click += async (_, _) =>
        {
            if (_aiQuestionsLeft <= 0)
            {
                Sts("Soru hakkiniz bitti. Yeni tarama yapin.");
                return;
            }
            if (string.IsNullOrEmpty(_aiQuestionInput?.Text) || string.IsNullOrEmpty(_webhookInput?.Text))
            { Sts("Webhook URL ve soru gerekli"); return; }
            Sts("AI analiz ediliyor...");
            aiSendBtn.Text = "Analiz...";
            aiSendBtn.Enabled = false;
            try
            {
                var groq = new GroqService();
                var answer = await groq.AskQuestion(_config.GroqApiKey, _aiQuestionInput.Text);
                _aiQuestionsLeft--;
                var webhook = new WebhookService();
                await webhook.SendAiAnalysis(_webhookInput.Text, $"**Soru ({5 - _aiQuestionsLeft}/5):** {_aiQuestionInput.Text}\n\n**Cevap:**\n{answer}");
                Sts($"AI cevap gonderildi ({_aiQuestionsLeft} hak kaldi)");
            }
            catch (Exception ex) { Sts("AI hatasi: " + ex.Message); }
            finally { aiSendBtn.Text = $"Gonder ({_aiQuestionsLeft} hak)"; aiSendBtn.Enabled = true; }
        };
        p.Controls.Add(aiSendBtn); y += 50;

        Info(p, y, "Sorunuz AI tarafindan analiz edilip Discord'a gonderilir."); y += 50;
        p.Height = y; return p;
    }

    private Panel SectionBrowser()
    {
        var p = Base("Browser History", "Chrome, Edge, Firefox, Opera GX, Brave, Vivaldi");
        int y = 80;
        Chk(p, "Enable Scan", y, _config.ScanBrowserHistory, v => _config.ScanBrowserHistory = v); y += 34;
        Chk(p, "Include Hidden URLs", y, _config.IncludeHiddenUrls, v => _config.IncludeHiddenUrls = v); y += 34;
        Chk(p, "Detect Deleted History", y, _config.DetectDeletedHistory, v => _config.DetectDeletedHistory = v); y += 34;
        Trk(p, "Max Age (days)", y, _config.MaxBrowserDays, 1, 365, v => _config.MaxBrowserDays = v); y += 62;
        Lbl(p, "Browsers Scanned", y); y += 26;
        foreach (var b in new[] { "Chrome", "Edge", "Firefox", "Opera GX", "Brave", "Vivaldi" })
        { Chk(p, b, y, true, null); y += 30; }
        Info(p, y, "Scans URL history AND keyword search terms. URL-decoded matching."); y += 54;
        p.Height = y; return p;
    }

    private Panel SectionForensic()
    {
        var p = Base("Forensic Scans", "Windows forensic artifact analysis");
        int y = 80;

        var scanners = new (string Label, Action<bool> Set)[]
        {
            ("Prefetch (.pf)", v => _config.ScanPrefetch = v),
            ("BAM", v => _config.ScanBAM = v),
            ("AmCache", v => _config.ScanAmCache = v),
            ("ShimCache", v => _config.ScanShimCache = v),
            ("Loaded Modules", v => _config.ScanLoadedModules = v),
            ("Processes", v => _config.ScanProcesses = v),
            ("Registry", v => _config.ScanRegistry = v),
            ("Event Logs", v => _config.ScanEventLogs = v),
            ("File System", v => _config.ScanFileSystem = v),
            ("USN Journal", v => _config.ScanUSNJournal = v),
            ("Deleted Files", v => _config.ScanDeletedFiles = v),
            ("Show ALL deleted", v => _config.ShowAllDeletedFiles = v),
            ("Network", v => _config.ScanNetwork = v),
            ("Hosts File", v => _config.ScanHostsFile = v),
            ("Drivers", v => _config.ScanDrivers = v),
            ("Services", v => _config.ScanServices = v),
            ("Scheduled Tasks", v => _config.ScanScheduledTasks = v),
            ("Boot Config", v => _config.ScanIntegrity = v),
            ("USB History", v => _config.ScanUSBHistory = v),
            ("Jumplists", v => _config.ScanJumplists = v),
            ("PcaClient", v => _config.ScanPcaClient = v),
        };

        int col = 0;
        int colWidth = 300;
        int rowHeight = 24;
        foreach (var (label, set) in scanners)
        {
            int x = 24 + (col % 2) * colWidth;
            int yy = y + (col / 2) * rowHeight;
            var c = new CheckBox
            {
                Text = label,
                Font = new Font("Georgia", 8),
                ForeColor = C_TEXT,
                Location = new Point(x, yy),
                AutoSize = true,
                Checked = true,
                FlatStyle = FlatStyle.Flat,
                BackColor = C_BG
            };
            c.CheckedChanged += (_, _) => set(c.Checked);
            p.Controls.Add(c);
            col++;
        }
        y += ((scanners.Length + 1) / 2) * rowHeight + 10;

        Info(p, y, "24 scanners active."); y += 30;
        p.Height = y; return p;
    }

    private Panel SectionBypass()
    {
        var p = Base("Bypass Detection", "Anti-forensic & evasion techniques");
        int y = 80;
        var toggles = new (string Label, Action<bool> Set)[]
        {
            ("Prefetch Deletion", v => _config.ScanPrefetch = v),
            ("BAM Tampering", v => _config.ScanBAM = v),
            ("Log Clearing", v => _config.ScanEventLogs = v),
            ("Time Changes", v => _config.ScanIntegrity = v),
            ("Test Signing", v => _config.ScanIntegrity = v),
            ("USN Journal Clear", v => _config.ScanUSNJournal = v),
            ("DMA Hardware", v => _config.ScanDrivers = v),
            ("Unsigned Drivers", v => _config.ScanDrivers = v),
            ("Hosts Redirect", v => _config.ScanHostsFile = v),
            ("Task Persistence", v => _config.ScanScheduledTasks = v),
            ("USB Execution", v => _config.ScanUSBHistory = v),
            ("VHD Mounting", v => _config.ScanFileSystem = v),
            ("Fileless/PS Exec", v => _config.ScanEventLogs = v),
            ("Injected Modules", v => _config.ScanLoadedModules = v),
        };
        int col = 0;
        int colWidth = 300;
        int rowHeight = 24;
        foreach (var (label, set) in toggles)
        {
            int x = 24 + (col % 2) * colWidth;
            int yy = y + (col / 2) * rowHeight;
            var c = new CheckBox
            {
                Text = label,
                Font = new Font("Georgia", 8),
                ForeColor = C_TEXT,
                Location = new Point(x, yy),
                AutoSize = true,
                Checked = true,
                FlatStyle = FlatStyle.Flat,
                BackColor = C_BG
            };
            c.CheckedChanged += (_, _) => set(c.Checked);
            p.Controls.Add(c);
            col++;
        }
        y += ((toggles.Length + 1) / 2) * rowHeight + 20;
        Info(p, y, "Toggling off disables the underlying scan."); y += 30;
        p.Height = y; return p;
    }

    private Panel SectionAdvanced()
    {
        var p = Base("Advanced Settings", "Fine-tune the scanner");
        int y = 80;
        Chk(p, "Silent Mode (no console output)", y, _config.SilentMode, v => _config.SilentMode = v); y += 34;
        Chk(p, "Scan All User Profiles", y, true, null); y += 34;
        Chk(p, "Enable AI Analysis (Groq)", y, _config.EnableAiAnalysis, v => _config.EnableAiAnalysis = v); y += 44;

        // Groq API Key
        Lbl(p, "Groq API Key", y); y += 24;
        _groqInput = Tb(p, y, 460); _groqInput.Text = _config.GroqApiKey; y += 32;
        var groqSaveBtn = new Button
        {
            Text = "Kaydet",
            Font = new Font("Georgia", 9, FontStyle.Bold),
            BackColor = Color.FromArgb(40, 160, 60),
            ForeColor = Color.White,
            Size = new Size(80, 30),
            Location = new Point(490, y - 32),
            Cursor = Cursors.Hand,
            FlatStyle = FlatStyle.Flat,
            FlatAppearance = { BorderSize = 0 }
        };
        groqSaveBtn.Click += (_, _) =>
        {
            try
            {
                var keyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ilac.cc", "groq_key.txt");
                Directory.CreateDirectory(Path.GetDirectoryName(keyPath)!);
                File.WriteAllText(keyPath, _groqInput?.Text ?? "");
                _config.GroqApiKey = _groqInput?.Text ?? "";
                Sts("Groq API key kaydedildi");
            }
            catch (Exception ex) { Sts("Kayit hatasi: " + ex.Message); }
        };
        p.Controls.Add(groqSaveBtn); y += 20;

        Info(p, y, "Key kaydedilir, uygulamayi kapsaniz bile saklanir."); y += 40;

        Lbl(p, "Custom Keywords (comma-separated)", y);
        Tb(p, y + 24, 520, true, 64); y += 96;
        Lbl(p, "Output Directory", y);
        var outDir = Tb(p, y + 24, 420); y += 64;
        var dirBtn = Btn(p, y, "Browse...", C_PANEL2, (_, _) =>
        {
            var dlg = new FolderBrowserDialog();
            if (dlg.ShowDialog() == DialogResult.OK && outDir != null)
                outDir.Text = dlg.SelectedPath;
        });
        p.Controls.Add(dirBtn); y += 48;
        Info(p, y, "ilac.cc  Author: madaruw"); y += 30;
        p.Height = y; return p;
    }

    private async void BuildClient(object? s, EventArgs e)
    {
        if (_isBuilding) return;
        _config.WebhookUrl = _webhookInput?.Text ?? "";
        if (string.IsNullOrEmpty(_config.WebhookUrl))
        {
            MessageBox.Show("Enter a webhook URL first.", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        _isBuilding = true;
        _buildBtn!.Enabled = false;
        _buildBtn.BackColor = C_PANEL2;
        _progressBar.Visible = true;
        Sts("Building client...");
        _buildBtn.Text = "  BUILDING...";

        try
        {
            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "ilac_builds");
            Directory.CreateDirectory(dir);
            var outPath = Path.Combine(dir, $"ilac_client_{DateTime.Now:yyyyMMdd_HHmmss}");
            var (success, error) = await new ClientBuilderService().BuildClient(outPath, _config.WebhookUrl, _config);
            if (success)
            {
                var exe = Directory.GetFiles(outPath, "*.exe").FirstOrDefault() ?? outPath;
                Sts("Built: " + Path.GetFileName(exe));
                // Delete PDB files if any
                foreach (var pdb in Directory.GetFiles(outPath, "*.pdb"))
                    try { File.Delete(pdb); } catch { }
                // Open build folder
                try { System.Diagnostics.Process.Start("explorer.exe", outPath); } catch { }
                MessageBox.Show("Client EXE built successfully!\n\n" + exe, "Build Complete",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                Sts("Build failed");
                MessageBox.Show(error ?? "Unknown error", "Build Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
        catch (Exception ex)
        {
            Sts("Error: " + ex.Message);
            MessageBox.Show(ex.ToString(), "Exception", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            _isBuilding = false;
            _buildBtn!.Enabled = true;
            _buildBtn.BackColor = C_TEXT;
            _progressBar.Visible = false;
            _buildBtn.Text = "  BUILD CLIENT";
        }
    }

    private Panel Base(string title, string sub)
    {
        var p = new Panel { BackColor = C_BG };
        p.Controls.Add(new Label
        {
            Text = title,
            Font = new Font("Georgia", 18, FontStyle.Bold),
            ForeColor = C_TEXT,
            Location = new Point(20, 12),
            AutoSize = true
        });
        p.Controls.Add(new Label
        {
            Text = sub,
            Font = new Font("Georgia", 9, FontStyle.Italic),
            ForeColor = C_SUBTLE,
            Location = new Point(22, 44),
            AutoSize = true
        });
        _accentBar.Parent = p;
        _accentBar.BackColor = C_ACCENT;
        _accentBar.Bounds = new Rectangle(22, 66, 0, 2);
        if (!p.Controls.Contains(_accentBar)) p.Controls.Add(_accentBar);
        return p;
    }

    private static void Lbl(Panel p, string t, int y)
    {
        p.Controls.Add(new Label
        {
            Text = t,
            Font = new Font("Georgia", 9, FontStyle.Bold),
            ForeColor = C_TEXT,
            Location = new Point(24, y),
            AutoSize = true
        });
    }

    private static TextBox Tb(Panel p, int y, int w, bool multi = false, int h = 28)
    {
        var tb = new TextBox
        {
            Font = new Font("Consolas", 10),
            ForeColor = C_TEXT,
            BackColor = C_PANEL,
            BorderStyle = BorderStyle.FixedSingle,
            Location = new Point(24, y),
            Width = w,
            Height = multi ? h : 28,
            Multiline = multi
        };
        p.Controls.Add(tb);
        return tb;
    }

    private static CheckBox Chk(Panel p, string t, int y, bool init, Action<bool>? cb)
    {
        var c = new CheckBox
        {
            Text = t,
            Font = new Font("Georgia", 9),
            ForeColor = C_TEXT,
            Location = new Point(26, y),
            AutoSize = true,
            Checked = init,
            FlatStyle = FlatStyle.Flat,
            BackColor = C_BG
        };
        if (cb != null) c.CheckedChanged += (_, _) => cb(c.Checked);
        p.Controls.Add(c);
        return c;
    }

    private static Button Btn(Panel p, int y, string t, Color c, EventHandler h)
    {
        var b = new Button
        {
            Text = t,
            Font = new Font("Georgia", 9, FontStyle.Bold),
            BackColor = c,
            ForeColor = Color.White,
            Size = new Size(140, 34),
            Location = new Point(24, y),
            Cursor = Cursors.Hand,
            FlatStyle = FlatStyle.Flat,
            FlatAppearance = { BorderSize = 0, MouseOverBackColor = ControlColor(c, 1.2f), MouseDownBackColor = ControlColor(c, 0.8f) }
        };
        b.Click += h;
        p.Controls.Add(b);
        return b;
    }

    private static void Info(Panel p, int y, string t)
    {
        p.Controls.Add(new Label
        {
            Text = t,
            Font = new Font("Georgia", 8, FontStyle.Italic),
            ForeColor = C_SUBTLE,
            Location = new Point(26, y),
            AutoSize = true,
            MaximumSize = new Size(640, 0)
        });
    }

    private static void Trk(Panel p, string lbl, int y, int val, int min, int max, Action<int> cb)
    {
        var l = new Label
        {
            Text = $"{lbl}: {val}",
            Font = new Font("Georgia", 8),
            ForeColor = C_SUBTLE,
            Location = new Point(26, y),
            AutoSize = true
        };
        p.Controls.Add(l);
        var s = new TrackBar
        {
            Location = new Point(26, y + 18),
            Size = new Size(320, 32),
            Minimum = min,
            Maximum = max,
            Value = Math.Clamp(val, min, max),
            TickStyle = TickStyle.None,
            BackColor = C_BG
        };
        s.ValueChanged += (_, _) => { l.Text = $"{lbl}: {s.Value}"; cb(s.Value); };
        p.Controls.Add(s);
    }

    private static Color ControlColor(Color c, float factor)
    {
        int r = Math.Clamp((int)(c.R * factor), 0, 255);
        int g = Math.Clamp((int)(c.G * factor), 0, 255);
        int b = Math.Clamp((int)(c.B * factor), 0, 255);
        return Color.FromArgb(r, g, b);
    }

    private void Sts(string t)
    {
        _statusLabel.Text = t;
        _statusLabel.ForeColor = t.Contains("OK") || t.Contains("Built") ? C_ACCENT2 :
                                 t.Contains("fail", StringComparison.OrdinalIgnoreCase) ||
                                 t.Contains("error", StringComparison.OrdinalIgnoreCase) ? C_BLOOD :
                                 C_SUBTLE;
    }
}
