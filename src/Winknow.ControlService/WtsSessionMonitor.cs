using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using Winknow.Ipc.Session;

namespace Winknow.ControlService;

/// <summary>
/// WTS 会话变更监视器（ADR-002 动态 SID 授权的事件源）。
///
/// 在专用线程上创建 message-only 窗口并 WTSRegisterSessionNotification(
/// NOTIFY_FOR_ALL_SESSIONS)，接收 WM_WTSSESSION_CHANGE 广播；登录/注销回调
/// DynamicSidAuthorizer。查询会话用户 SID 使用 WTSQueryUserToken（需要
/// SE_TCB 特权，ControlService 以 LocalSystem 运行天然具备）。
/// </summary>
internal sealed class WtsSessionMonitor : IDisposable
{
    private const int WtsRegisterNotifyForAllSessions = 1; // NOTIFY_FOR_ALL_SESSIONS
    private const int WmQuit = 0x0012;

    private readonly Action<WtsSessionChangeKind, int> _onChange;
    private readonly ILogger<WtsSessionMonitor>? _logger;
    private readonly Thread _thread;
    private readonly ManualResetEventSlim _started = new(false);
    private IntPtr _hwnd = IntPtr.Zero;
    private uint _wmWtsSessionChange;
    private WndProcDelegate? _wndProc;
    private bool _disposed;

    /// <summary>创建 WTS 会话监视器。</summary>
    /// <param name="onChange">会话变更回调（回调应快速返回，不做阻塞操作）。</param>
    /// <param name="logger">日志记录器。</param>
    public WtsSessionMonitor(Action<WtsSessionChangeKind, int> onChange, ILogger<WtsSessionMonitor>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(onChange);
        _onChange = onChange;
        _logger = logger;
        _thread = new Thread(RunMessageLoop)
        {
            IsBackground = true,
            Name = "Winknow.WtsSessionMonitor",
        };
    }

    private delegate IntPtr WndProcDelegate(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    /// <summary>启动监视线程并注册 WTS 会话通知。</summary>
    /// <exception cref="InvalidOperationException">窗口创建或通知注册失败。</exception>
    public void Start()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _thread.Start();
        if (!_started.Wait(TimeSpan.FromSeconds(10)) || _hwnd == IntPtr.Zero)
        {
            throw new InvalidOperationException("WTS session monitor failed to initialize its message window.");
        }

        _logger?.LogInformation("WTS session change monitor started (all sessions)");
    }

    /// <summary>停止监视线程并注销通知。</summary>
    public void Stop()
    {
        if (_hwnd != IntPtr.Zero)
        {
            _ = PostMessage(_hwnd, WmQuit, IntPtr.Zero, IntPtr.Zero);
        }

        if (_thread.IsAlive)
        {
            _thread.Join(TimeSpan.FromSeconds(5));
        }
    }

    /// <summary>
    /// 查询会话用户 SID（WTSQueryUserToken → WindowsIdentity）。
    /// 需要 SE_TCB 特权；失败（如会话已注销）返回 null。
    /// </summary>
    /// <param name="sessionId">WTS 会话 ID。</param>
    /// <returns>用户 SID 字符串；失败返回 null。</returns>
    public static string? QuerySessionUserSid(int sessionId)
    {
        if (!WTSQueryUserToken(sessionId, out var token))
        {
            return null;
        }

        try
        {
            using var identity = new WindowsIdentity(token);
            return identity.User?.Value;
        }
        catch
        {
            return null;
        }
        finally
        {
            _ = CloseHandle(token);
        }
    }

    /// <summary>
    /// 枚举当前 Active 会话及其用户 SID（服务重启后恢复既有登录会话授权用）。
    /// </summary>
    /// <returns>(会话 ID, 用户 SID 或 null) 列表。</returns>
    public static IReadOnlyList<(int SessionId, string? Sid)> EnumerateActiveSessionsWithSid()
    {
        var result = new List<(int, string?)>();
        if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out var buffer, out var count))
        {
            return result;
        }

        try
        {
            var structSize = Marshal.SizeOf<WtsSessionInfo>();
            for (var i = 0; i < count; i++)
            {
                var info = Marshal.PtrToStructure<WtsSessionInfo>(buffer + i * structSize);
                if (info.State != WtsConnectState.Active)
                {
                    continue;
                }

                result.Add((info.SessionId, QuerySessionUserSid(info.SessionId)));
            }
        }
        finally
        {
            WTSFreeMemory(buffer);
        }

        return result;
    }

    private void RunMessageLoop()
    {
        _wmWtsSessionChange = RegisterWindowMessage("WM_WTSSESSION_CHANGE");
        _wndProc = WndProc;

        var className = "WinknowWtsMonitor_" + Environment.ProcessId.ToString("X");
        var classData = new WndClassEx
        {
            Size = (uint)Marshal.SizeOf<WndClassEx>(),
            LpfnWndProc = Marshal.GetFunctionPointerForDelegate(_wndProc),
            HInstance = Marshal.GetHINSTANCE(typeof(WtsSessionMonitor).Module),
            LpszClassName = className,
        };

        if (RegisterClassEx(ref classData) == 0)
        {
            FailStart("RegisterClassEx failed");
            return;
        }

        // message-only 窗口（父句柄 HWND_MESSAGE）：仅接收定向投递的消息
        _hwnd = CreateWindowEx(
            0, className, string.Empty, 0, 0, 0, 0, 0,
            new IntPtr(-3), classData.HInstance, IntPtr.Zero);
        if (_hwnd == IntPtr.Zero)
        {
            FailStart("CreateWindowEx failed");
            return;
        }

        if (!WTSRegisterSessionNotification(_hwnd, WtsRegisterNotifyForAllSessions))
        {
            _ = DestroyWindow(_hwnd);
            _hwnd = IntPtr.Zero;
            FailStart("WTSRegisterSessionNotification failed");
            return;
        }

        _started.Set();

        while (GetMessage(out var msg, IntPtr.Zero, 0, 0) > 0)
        {
            _ = TranslateMessage(ref msg);
            _ = DispatchMessage(ref msg);
        }

        _ = WTSUnRegisterSessionNotification(_hwnd);
        _ = DestroyWindow(_hwnd);
        _hwnd = IntPtr.Zero;

        void FailStart(string reason)
        {
            _logger?.LogError("WTS session monitor init failed: {Reason} (win32 error {Error})",
                reason, Marshal.GetLastWin32Error());
            _started.Set();
        }
    }

    private IntPtr WndProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam)
    {
        if (msg == _wmWtsSessionChange)
        {
            var kind = (WtsSessionChangeKind)wParam.ToInt64();
            if (Enum.IsDefined(kind))
            {
                try
                {
                    _onChange(kind, (int)lParam.ToInt64());
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "WTS session change handler failed");
                }
            }

            return IntPtr.Zero;
        }

        return DefWindowProc(hWnd, msg, wParam, lParam);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        Stop();
        _started.Dispose();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WtsSessionInfo
    {
        public int SessionId;
        public IntPtr WinStationName;
        public WtsConnectState State;
    }

    private enum WtsConnectState
    {
        Active = 0,
        Connected = 1,
        ConnectQuery = 2,
        Shadow = 3,
        Disconnected = 4,
        Idle = 5,
        Listen = 6,
        Reset = 7,
        Down = 8,
        Init = 9,
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WndClassEx
    {
        public uint Size;
        public uint Style;
        public IntPtr LpfnWndProc;
        public int CbClsExtra;
        public int CbWndExtra;
        public IntPtr HInstance;
        public IntPtr HIcon;
        public IntPtr HCursor;
        public IntPtr HbrBackground;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? MenuName;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string LpszClassName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeMessage
    {
        public IntPtr Hwnd;
        public uint Message;
        public IntPtr WParam;
        public IntPtr LParam;
        public uint Time;
        public int PointX;
        public int PointY;
    }

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern ushort RegisterClassEx(ref WndClassEx lpwcx);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateWindowEx(
        uint exStyle, string className, string windowName, uint style,
        int x, int y, int width, int height, IntPtr parent, IntPtr instance, IntPtr param);

    [DllImport("user32.dll")]
    private static extern bool DestroyWindow(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern int GetMessage(out NativeMessage msg, IntPtr hWnd, uint min, uint max);

    [DllImport("user32.dll")]
    private static extern bool TranslateMessage(ref NativeMessage msg);

    [DllImport("user32.dll")]
    private static extern IntPtr DispatchMessage(ref NativeMessage msg);

    [DllImport("user32.dll")]
    private static extern IntPtr DefWindowProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool PostMessage(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint RegisterWindowMessage(string name);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSRegisterSessionNotification(IntPtr hWnd, int flags);

    [DllImport("wtsapi32.dll")]
    private static extern bool WTSUnRegisterSessionNotification(IntPtr hWnd);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(int sessionId, out IntPtr token);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSEnumerateSessions(
        IntPtr server, int reserved, int version, out IntPtr sessionInfo, out int count);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
