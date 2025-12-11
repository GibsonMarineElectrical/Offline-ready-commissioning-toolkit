using System.Diagnostics;
using System.Net;
using System.Text;
using System.Windows.Forms;
using Microsoft.AspNetCore.StaticFiles;

namespace FileWebBrowser;

public static class Program
{
    private const string MutexName = "Global\\DataGatewayMutex";

    [STAThread]
    public static void Main(string[] args)
    {
        Logger.Log("Startup: app launched.");
        PreventSleep.On();
        ProcessTweaks.TryLowerPriority();
        ProcessTweaks.TryMinimizeConsole();

        try
        {
            var argsDict = ParseArgs(args);

            using var mutex = EnsureSingleInstance();
            if (mutex is null)
            {
                Logger.Log("Startup aborted: another instance detected.");
                return;
            }

            AppDomain.CurrentDomain.UnhandledException += (_, e) => Logger.Log($"UnhandledException: {e.ExceptionObject}");
            Application.ThreadException += (_, e) => Logger.Log($"ThreadException: {e.Exception}");
            TaskScheduler.UnobservedTaskException += (_, e) =>
            {
                Logger.Log($"UnobservedTaskException: {e.Exception}");
                e.SetObserved();
            };

            if (Environment.UserInteractive)
            {
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);

                var selected = PromptForOptions(argsDict);
                if (selected is null)
                {
                    Logger.Log("Startup cancelled by user.");
                    return;
                }

                var options = new ServerOptions(selected.Root, selected.Port);
                Application.Run(new StatusForm(options));
                Logger.Log("UI loop ended.");
            }
            else
            {
                var options = ResolveOptions(argsDict);
                Logger.Log($"Service/console run. Port={options.Port}, Root={options.Root}");
                RunServerLoop(options, CancellationToken.None).GetAwaiter().GetResult();
            }
        }
        finally
        {
            PreventSleep.Off();
            Logger.Log("Shutdown.");
        }
    }

    private static ServerOptions? PromptForOptions(Dictionary<string, string> argsDict)
    {
        var defaultRoot = argsDict.TryGetValue("root", out var rootArg) && Directory.Exists(rootArg)
            ? rootArg
            : Helpers.GetExeDirectory();
        var defaultPort = argsDict.TryGetValue("port", out var portArg) && int.TryParse(portArg, out var parsedPort) && parsedPort is >= 1 and <= 65535
            ? parsedPort
            : 1885;

        using var folderDialog = new FolderBrowserDialog
        {
            Description = "Select the folder to serve (read-only)",
            SelectedPath = defaultRoot,
            ShowNewFolderButton = false
        };

        if (folderDialog.ShowDialog() != DialogResult.OK || !Directory.Exists(folderDialog.SelectedPath))
        {
            return null;
        }

        var port = PromptForPort(defaultPort);
        if (port is null)
        {
            return null;
        }

        return new ServerOptions(folderDialog.SelectedPath, port.Value);
    }

    private static int? PromptForPort(int defaultPort)
    {
        using var form = new Form
        {
            Text = "Port",
            FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterScreen,
            ClientSize = new Size(260, 120),
            MinimizeBox = false,
            MaximizeBox = false
        };

        var label = new Label { Text = "Port (1-65535):", Location = new Point(12, 15), AutoSize = true };
        var input = new TextBox { Location = new Point(12, 38), Width = 100, Text = defaultPort.ToString() };
        var ok = new Button { Text = "OK", DialogResult = DialogResult.OK, Location = new Point(120, 75), Width = 60 };
        var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Location = new Point(190, 75), Width = 60 };
        ok.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
        cancel.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;

        form.Controls.AddRange(new Control[] { label, input, ok, cancel });
        form.AcceptButton = ok;
        form.CancelButton = cancel;

        var result = form.ShowDialog();
        if (result != DialogResult.OK)
        {
            return null;
        }

        if (int.TryParse(input.Text, out var port) && port is >= 1 and <= 65535)
        {
            return port;
        }

        MessageBox.Show("Please enter a valid TCP port number (1-65535).", "Invalid Port", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        return null;
    }

    internal static async Task RunServerLoop(ServerOptions options, CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                using var app = ServerBuilder.Build(options);
                Logger.Log($"Server starting on 127.0.0.1:{options.Port} root={options.Root}");
                await app.RunAsync(token);
                Logger.Log("Server stopped.");
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Logger.Log($"Server error: {ex}");
            }

            if (!token.IsCancellationRequested)
            {
                Logger.Log("Restarting server in 2 seconds...");
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(2), token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
    }

    private static ServerOptions ResolveOptions(Dictionary<string, string> argsDict)
    {
        var root = argsDict.TryGetValue("root", out var rootArg) && !string.IsNullOrWhiteSpace(rootArg)
            ? rootArg
            : Helpers.GetExeDirectory();

        var port = argsDict.TryGetValue("port", out var portArg) && int.TryParse(portArg, out var parsedPort) && parsedPort is >= 1 and <= 65535
            ? parsedPort
            : 1885;

        return new ServerOptions(root, port);
    }

    private static Dictionary<string, string> ParseArgs(string[] args)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < args.Length; i++)
        {
            var raw = args[i];
            if (!raw.StartsWith("--"))
            {
                continue;
            }

            var trimmed = raw.TrimStart('-');
            var parts = trimmed.Split('=', 2);

            if (parts.Length == 2 && !string.IsNullOrWhiteSpace(parts[1]))
            {
                dict[parts[0]] = parts[1];
            }
            else if (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
            {
                dict[parts[0]] = args[++i];
            }
            else
            {
                dict[parts[0]] = "true";
            }
        }

        return dict;
    }

    private static Mutex? EnsureSingleInstance()
    {
        var mutex = new Mutex(initiallyOwned: true, name: MutexName, createdNew: out var created);
        if (created)
        {
            return mutex;
        }

        var message = "GME Gateway File Viewer is already running.";
        MessageBox.Show(message, "Already running", MessageBoxButtons.OK, MessageBoxIcon.Information);
        mutex.Dispose();
        return null;
    }
}

internal sealed class StatusForm : Form
{
    private readonly ServerOptions _options;
    private readonly CancellationTokenSource _cts = new();
    private Task? _serverLoopTask;
    private NotifyIcon? _tray;
    private bool _allowExit;

    private Label? _status;
    private Button? _openButton;

    public StatusForm(ServerOptions options)
    {
        _options = options;
        Text = "GME Gateway File Viewer";
        Icon = TrayIconFactory.GetAppIcon();
        ClientSize = new Size(420, 160);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = true;
        StartPosition = FormStartPosition.CenterScreen;
    }

    protected override void OnLoad(EventArgs e)
    {
        base.OnLoad(e);

        InitializeUi();
        InitializeTrayIcon();

        _serverLoopTask = Task.Run(() => Program.RunServerLoop(_options, _cts.Token));
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (!_allowExit && e.CloseReason == CloseReason.UserClosing)
        {
            // Allow closing to fully stop service/app
            _allowExit = true;
        }

        base.OnFormClosing(e);
        _cts.Cancel();
        if (_tray is not null)
        {
            _tray.Visible = false;
            _tray.Dispose();
        }

        try
        {
            _serverLoopTask?.GetAwaiter().GetResult();
        }
        catch
        {
            // best effort
        }

        // Ensure process terminates (closes console/host window)
        Environment.Exit(0);
    }

    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e);
        if (WindowState == FormWindowState.Minimized)
        {
            Hide();
            ShowInTaskbar = false;
        }
    }

    private void InitializeUi()
    {
        var url = $"http://127.0.0.1:{_options.Port}/browse";
        var info = new Label
        {
            AutoSize = true,
            Location = new Point(12, 12),
            Text = $"Serving: {_options.Root}\nURL: {url}"
        };

        _status = new Label
        {
            AutoSize = true,
            Location = new Point(12, 80),
            Text = "Running..."
        };

        _openButton = new Button
        {
            Text = "Open in browser",
            Location = new Point(12, 110),
            Width = 130
        };
        _openButton.Click += (_, _) => OpenBrowser(url);

        Controls.Add(info);
        Controls.Add(_status);
        Controls.Add(_openButton);
    }

    private void InitializeTrayIcon()
    {
        var menu = new ContextMenuStrip();
        var openItem = new ToolStripMenuItem("Open");
        openItem.Click += (_, _) => ShowWindow();
        var exitItem = new ToolStripMenuItem("Exit");
        exitItem.Click += (_, _) =>
        {
            _allowExit = true;
            Close();
        };
        menu.Items.Add(openItem);
        menu.Items.Add(exitItem);

        _tray = new NotifyIcon
        {
            Icon = TrayIconFactory.Create("DG"),
            Text = "GME Gateway File Viewer (running)",
            Visible = true,
            ContextMenuStrip = menu
        };
        _tray.DoubleClick += (_, _) => ShowWindow();
    }

    private void ShowWindow()
    {
        if (InvokeRequired)
        {
            Invoke(new Action(ShowWindow));
            return;
        }

        ShowInTaskbar = true;
        WindowState = FormWindowState.Normal;
        Show();
        Activate();
        OpenBrowser($"http://127.0.0.1:{_options.Port}/browse");
    }

    private void OpenBrowser(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true });
        }
        catch
        {
            // ignore
        }
    }
}

internal static class ServerBuilder
{
    public static WebApplication Build(ServerOptions options)
    {
        var builder = WebApplication.CreateBuilder();

        var normalizedRoot = ServerHelpers.NormalizeRoot(options.Root);
        if (!Directory.Exists(normalizedRoot))
        {
            throw new DirectoryNotFoundException($"Root directory '{normalizedRoot}' does not exist.");
        }

        builder.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, options.Port));
        builder.WebHost.UseUrls($"http://127.0.0.1:{options.Port}");

        var app = builder.Build();

        app.Use(async (context, next) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            await next();
        });

        app.Use(async (context, next) =>
        {
            try
            {
                await next();
            }
            catch (Exception ex)
            {
                Logger.Log($"Request error: {ex}");
                throw;
            }
        });

        app.MapGet("/", () => Results.Redirect("/browse"));

        app.MapGet("/browse", async context =>
        {
            var relative = context.Request.Query["path"].ToString();

            if (!ServerHelpers.TryResolvePath(normalizedRoot, relative, out var fullPath, out var safeRelative))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsync("Invalid path.");
                return;
            }

            if (!Directory.Exists(fullPath))
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                await context.Response.WriteAsync("Folder not found.");
                return;
            }

            List<string> directories;
            List<string> files;
            try
            {
                directories = Directory.GetDirectories(fullPath)
                    .OrderBy(Path.GetFileName)
                    .ToList();
                files = Directory.GetFiles(fullPath)
                    .OrderBy(Path.GetFileName)
                    .ToList();
            }
            catch (UnauthorizedAccessException)
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsync("Access denied to this folder.");
                return;
            }

            var html = ServerHelpers.BuildDirectoryHtml(normalizedRoot, safeRelative, directories, files);
            context.Response.ContentType = "text/html; charset=utf-8";
            await context.Response.WriteAsync(html);
        });

        app.MapGet("/health", () => Results.Ok(new { status = "ok", root = normalizedRoot }));

        return app;
    }
}

internal static class ServerHelpers
{
    public static string NormalizeRoot(string root)
    {
        var fullPath = Path.GetFullPath(root);
        return fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
    }

    public static bool TryResolvePath(string normalizedRoot, string? relativePath, out string fullPath, out string safeRelative)
    {
        var sanitized = (relativePath ?? string.Empty)
            .Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);

        fullPath = Path.GetFullPath(Path.Combine(normalizedRoot, sanitized));

        if (!fullPath.StartsWith(normalizedRoot, StringComparison.OrdinalIgnoreCase))
        {
            safeRelative = string.Empty;
            return false;
        }

        safeRelative = Path.GetRelativePath(normalizedRoot, fullPath);
        if (safeRelative == ".")
        {
            safeRelative = string.Empty;
        }

        return true;
    }

    public static string BuildDirectoryHtml(string normalizedRoot, string relativePath, IEnumerable<string> directories, IEnumerable<string> files)
    {
        var sb = new StringBuilder();
        sb.Append("""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GME Gateway File Viewer</title>
  <style>
    :root {
      color-scheme: light dark;
      --bg: #0f172a;
      --panel: #111827;
      --text: #e5e7eb;
      --accent: #38bdf8;
      --muted: #94a3b8;
      --border: #1f2937;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
      background: radial-gradient(circle at 20% 20%, #0b1221, #0a1020 45%, #080d1a);
      color: var(--text);
      min-height: 100vh;
      user-select: none;
      -webkit-user-select: none;
    }
    header {
      padding: 16px 22px;
      background: linear-gradient(135deg, #0b1727, #0e2439);
      border-bottom: 1px solid var(--border);
      box-shadow: 0 10px 30px rgba(0,0,0,0.35);
      position: sticky;
      top: 0;
      z-index: 2;
    }
    .wrap { max-width: 1100px; margin: 0 auto; padding: 18px 22px 40px; }
    h1 { margin: 0; font-size: 20px; letter-spacing: 0.4px; }
    .crumbs {
      margin: 10px 0 6px;
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      font-size: 13px;
      color: var(--muted);
    }
    .crumbs a {
      color: var(--accent);
      text-decoration: none;
    }
    .panel {
      background: rgba(17, 24, 39, 0.85);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 18px 50px rgba(0,0,0,0.45);
      backdrop-filter: blur(6px);
    }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 12px 14px; text-align: left; }
    th { font-size: 12px; text-transform: uppercase; letter-spacing: 0.6px; color: var(--muted); border-bottom: 1px solid var(--border); }
    tr + tr td { border-top: 1px solid var(--border); }
    tr:hover td { background: rgba(56, 189, 248, 0.06); }
    a { color: var(--text); text-decoration: none; }
    .type { font-size: 12px; color: var(--muted); }
    .up { color: var(--accent); }
    .note { margin-top: 12px; color: var(--muted); font-size: 13px; }
  </style>
</head>
<body>
  <header>
    <h1>GME Gateway File Viewer</h1>
    <div class="crumbs">
""");

        var breadcrumbs = BuildBreadcrumbs(relativePath);
        for (var i = 0; i < breadcrumbs.Count; i++)
        {
            var crumb = breadcrumbs[i];
            if (!string.IsNullOrEmpty(crumb.href))
            {
                sb.Append($"""<a href="{crumb.href}">{WebUtility.HtmlEncode(crumb.label)}</a>""");
            }
            else
            {
                sb.Append(WebUtility.HtmlEncode(crumb.label));
            }

            if (i < breadcrumbs.Count - 1)
            {
                sb.Append("<span>/</span>");
            }
        }

        sb.Append("""
    </div>
  </header>
  <div class="wrap">
    <div class="panel">
      <table>
        <thead>
          <tr><th>Name</th><th>Type</th><th>Last Modified</th></tr>
        </thead>
        <tbody>
""");

        if (!string.IsNullOrEmpty(relativePath))
        {
            var parent = Path.GetDirectoryName(relativePath) ?? string.Empty;
            sb.Append($"""
          <tr>
            <td><a class="up" href="/browse?path={Uri.EscapeDataString(parent)}">Parent folder</a></td>
            <td class="type">Up</td>
            <td></td>
          </tr>
""");
        }

        foreach (var dir in directories)
        {
            var name = Path.GetFileName(dir);
            var childRelative = Path.GetRelativePath(normalizedRoot, dir);
            var link = $"/browse?path={Uri.EscapeDataString(childRelative)}";
            sb.Append($"""
          <tr>
            <td><a href="{link}">[DIR] {WebUtility.HtmlEncode(name)}</a></td>
            <td class="type">Folder</td>
            <td>{FormatTimestamp(Directory.GetLastWriteTime(dir))}</td>
          </tr>
""");
        }

        foreach (var file in files)
        {
            var name = Path.GetFileName(file);
            sb.Append($"""
          <tr>
            <td>{WebUtility.HtmlEncode(name)}</td>
            <td class="type">{WebUtility.HtmlEncode(Path.GetExtension(file).TrimStart('.').ToUpperInvariant())}</td>
            <td>{FormatTimestamp(System.IO.File.GetLastWriteTime(file))}</td>
          </tr>
""");
        }

        sb.Append("""
        </tbody>
      </table>
    </div>
    <div class="note">Read-only: uploads, deletes, and clipboard are blocked in this view. Files are not clickable.</div>
    <div class="note">Designed and built by Dan Gibson &amp; Codex 2025 (Gibson Marine Electrical LTD)</div>
  </div>
  <script>
    document.addEventListener('contextmenu', e => e.preventDefault());
    document.addEventListener('copy', e => { e.preventDefault(); });
    document.addEventListener('cut', e => { e.preventDefault(); });
    document.addEventListener('keydown', e => {
      const key = e.key.toLowerCase();
      if ((e.ctrlKey || e.metaKey) && (key === 'c' || key === 'x')) {
        e.preventDefault();
      }
    });
  </script>
</body>
</html>
""");

        return sb.ToString();
    }

    private static List<(string label, string href)> BuildBreadcrumbs(string relativePath)
    {
        var crumbs = new List<(string label, string href)> { ("Root", "/browse") };

        if (string.IsNullOrEmpty(relativePath))
        {
            return crumbs;
        }

        var segments = relativePath.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);
        var current = string.Empty;
        foreach (var segment in segments)
        {
            current = Path.Combine(current, segment);
            crumbs.Add((segment, $"/browse?path={Uri.EscapeDataString(current)}"));
        }

        return crumbs;
    }

    private static string FormatTimestamp(DateTime timestamp)
    {
        return timestamp.ToString("yyyy-MM-dd HH:mm");
    }
}

internal static class TrayIconFactory
{
    public static Icon Create(string initials)
    {
        using var bmp = new Bitmap(32, 32);
        using (var g = Graphics.FromImage(bmp))
        {
            g.Clear(Color.FromArgb(15, 23, 42));
            using var brush = new SolidBrush(Color.FromArgb(56, 189, 248));
            using var font = new Font("Segoe UI", 12, FontStyle.Bold, GraphicsUnit.Pixel);
            var size = g.MeasureString(initials, font);
            g.DrawString(initials, font, brush, (32 - size.Width) / 2, (32 - size.Height) / 2);
        }

        var hIcon = bmp.GetHicon();
        return Icon.FromHandle(hIcon);
    }

    public static Icon GetAppIcon()
    {
        try
        {
            var exe = Environment.ProcessPath;
            if (!string.IsNullOrEmpty(exe))
            {
                var assoc = Icon.ExtractAssociatedIcon(exe);
                if (assoc is not null)
                {
                    return assoc;
                }
            }
        }
        catch
        {
            // ignore
        }

        return SystemIcons.Application;
    }
}

internal static class Logger
{
    private static readonly object Sync = new();
    private static readonly string LogPath = InitLogPath();

    public static void Log(string message)
    {
        try
        {
            var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {message}";
            lock (Sync)
            {
                File.AppendAllText(LogPath, line + Environment.NewLine);
            }
        }
        catch
        {
            // ignore logging errors
        }
    }

    private static string InitLogPath()
    {
        try
        {
            var exeDir = Path.GetDirectoryName(Environment.ProcessPath) ?? AppContext.BaseDirectory;
            return Path.Combine(exeDir, "data-gateway.log");
        }
        catch
        {
            return Path.Combine(AppContext.BaseDirectory, "data-gateway.log");
        }
    }
}

internal static class ProcessTweaks
{
    public static void TryLowerPriority()
    {
        try
        {
            Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.BelowNormal;
        }
        catch
        {
            // ignore
        }
    }

    public static void TryMinimizeConsole()
    {
        try
        {
            var handle = GetConsoleWindow();
            if (handle != IntPtr.Zero)
            {
                ShowWindow(handle, SW_MINIMIZE);
            }
        }
        catch
        {
            // ignore
        }
    }

    private const int SW_MINIMIZE = 6;

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
}

internal static class Helpers
{
    public static string GetExeDirectory()
    {
        try
        {
            return Path.GetDirectoryName(Environment.ProcessPath) ?? Directory.GetCurrentDirectory();
        }
        catch
        {
            return Directory.GetCurrentDirectory();
        }
    }
}

internal static class PreventSleep
{
    [Flags]
    private enum ExecutionState : uint
    {
        EsSystemRequired = 0x00000001,
        EsDisplayRequired = 0x00000002,
        EsContinuous = 0x80000000
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern ExecutionState SetThreadExecutionState(ExecutionState esFlags);

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct PROCESS_POWER_THROTTLING_STATE
    {
        public uint Version;
        public uint ControlMask;
        public uint StateMask;
    }

    private enum PROCESS_INFORMATION_CLASS
    {
        ProcessPowerThrottling = 24
    }

    private const uint PROCESS_POWER_THROTTLING_CURRENT_VERSION = 1;
    private const uint PROCESS_POWER_THROTTLING_EXECUTION_SPEED = 0x1;

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern bool SetProcessInformation(IntPtr hProcess, PROCESS_INFORMATION_CLASS infoClass, ref PROCESS_POWER_THROTTLING_STATE info, uint infoSize);

    public static void On()
    {
        try
        {
            SetThreadExecutionState(ExecutionState.EsContinuous | ExecutionState.EsSystemRequired | ExecutionState.EsDisplayRequired);
            DisablePowerThrottling();
        }
        catch
        {
            // ignore
        }
    }

    public static void Off()
    {
        try
        {
            SetThreadExecutionState(ExecutionState.EsContinuous);
        }
        catch
        {
            // ignore
        }
    }

    private static void DisablePowerThrottling()
    {
        try
        {
            var state = new PROCESS_POWER_THROTTLING_STATE
            {
                Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION,
                ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
                StateMask = 0
            };
            SetProcessInformation(Process.GetCurrentProcess().Handle, PROCESS_INFORMATION_CLASS.ProcessPowerThrottling, ref state, (uint)System.Runtime.InteropServices.Marshal.SizeOf<PROCESS_POWER_THROTTLING_STATE>());
        }
        catch
        {
            // ignore
        }
    }
}

internal record ServerOptions(string Root, int Port);

internal record InteractiveOptions(string Root, int Port, bool InstallService);
