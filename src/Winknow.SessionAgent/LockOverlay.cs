using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace Winknow.SessionAgent;

/// <summary>
/// 锁屏遮罩组件：SessionAgent 本就跑在学生桌面会话，天然画遮罩；
/// 标准用户杀不掉 SYSTEM 服务下发的窗口。
///
/// 窗口在专用 UI 线程创建并由 GetMessage 消息循环驱动——Win32 窗口只有在
/// 创建线程上持续泵消息才能完成绘制（WM_PAINT）与输入拦截；Show/Hide 通过
/// 向 UI 线程投递消息实现，可在任意线程调用。
/// </summary>
public sealed class LockOverlay : IDisposable
{
    // 自定义驱动消息（WM_APP 区间）
    private const uint WmAppShow = 0x8000 + 0x0001;
    private const uint WmAppHide = 0x8000 + 0x0002;

    private readonly ILogger<LockOverlay>? _logger;
    private readonly object _sync = new();
    private readonly ManualResetEventSlim _windowCreated = new(false);
    private Thread? _uiThread;
    private uint _uiThreadId;
    private IntPtr _hwnd;
    private WndProc? _wndProcDelegate;
    private volatile bool _isLocked;
    private volatile bool _disposed;

    /// <summary>
    /// 创建锁屏遮罩。
    /// </summary>
    /// <param name="logger">可选的日志记录器。</param>
    public LockOverlay(ILogger<LockOverlay>? logger = null)
    {
        _logger = logger;
    }

    /// <summary>当前锁定状态（Show/Hide 请求已提交）。</summary>
    public bool IsLocked => _isLocked;

    /// <summary>遮罩窗口句柄（IntPtr.Zero 表示窗口尚未创建或已销毁）。</summary>
    public IntPtr WindowHandle => Volatile.Read(ref _hwnd);

    /// <summary>
    /// 显示锁屏遮罩（投递到 UI 线程异步生效）。
    /// </summary>
    public bool Show()
    {
        lock (_sync)
        {
            if (_disposed)
            {
                return false;
            }

            if (_isLocked)
            {
                _logger?.LogWarning("Lock overlay already shown");
                return true;
            }

            EnsureUiThread();
        }

        if (!WaitForWindow())
        {
            return false;
        }

        if (!PostMessage(WindowHandle, WmAppShow, IntPtr.Zero, IntPtr.Zero))
        {
            _logger?.LogError("Failed to post show message: {Error}", Marshal.GetLastWin32Error());
            return false;
        }

        _isLocked = true;
        _logger?.LogInformation("Lock overlay show requested");
        return true;
    }

    /// <summary>
    /// 隐藏锁屏遮罩（投递到 UI 线程异步生效）。
    /// </summary>
    public bool Hide()
    {
        if (!_isLocked)
        {
            _logger?.LogWarning("Lock overlay not shown");
            return true;
        }

        var hwnd = WindowHandle;
        if (hwnd != IntPtr.Zero && !PostMessage(hwnd, WmAppHide, IntPtr.Zero, IntPtr.Zero))
        {
            _logger?.LogError("Failed to post hide message: {Error}", Marshal.GetLastWin32Error());
            return false;
        }

        _isLocked = false;
        _logger?.LogInformation("Lock overlay hide requested");
        return true;
    }

    private void EnsureUiThread()
    {
        if (_uiThread is { IsAlive: true })
        {
            return;
        }

        _windowCreated.Reset();
        _uiThread = new Thread(UiThreadMain)
        {
            Name = "Winknow.LockOverlay.UI",
            IsBackground = true,
        };
        _uiThread.Start();
    }

    private bool WaitForWindow()
        => _windowCreated.Wait(TimeSpan.FromSeconds(5)) && WindowHandle != IntPtr.Zero;

    /// <summary>
    /// UI 线程主体：创建遮罩窗口并运行消息循环，直到收到 WM_QUIT。
    /// </summary>
    private void UiThreadMain()
    {
        _uiThreadId = GetCurrentThreadId();

        var screenWidth = GetSystemMetrics(SmCxScreen);
        var screenHeight = GetSystemMetrics(SmCyScreen);

        _wndProcDelegate = WindowProc;
        var hwnd = CreateWindowEx(
            (uint)(WsExTopmost | WsExToolwindow),
            "STATIC",
            "Winknow Lock Screen",
           style: unchecked((uint)WsPopup), // 创建时不可见，由 WmAppShow 显式显示
            0, 0,
            screenWidth, screenHeight,
            IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

        if (hwnd == IntPtr.Zero)
        {
            _logger?.LogError("Failed to create lock overlay window: {Error}", Marshal.GetLastWin32Error());
            _windowCreated.Set();
            return;
        }

        var oldWndProc = SetWindowLongPtr(hwnd, GlpWndProc, Marshal.GetFunctionPointerForDelegate(_wndProcDelegate));
        if (oldWndProc == IntPtr.Zero)
        {
            _logger?.LogError("Failed to set window procedure: {Error}", Marshal.GetLastWin32Error());
            DestroyWindow(hwnd);
            _windowCreated.Set();
            return;
        }

        Volatile.Write(ref _hwnd, hwnd);
        _windowCreated.Set();

        while (GetMessage(out var msg, IntPtr.Zero, 0, 0) > 0)
        {
            switch (msg.message)
            {
                case WmAppShow:
                    ShowWindow(hwnd, SwShow);
                    SetForegroundWindow(hwnd);
                    UpdateWindow(hwnd);
                    InvalidateRect(hwnd, IntPtr.Zero, true);
                    break;

                case WmAppHide:
                    ShowWindow(hwnd, SwHide);
                    break;

                default:
                    TranslateMessage(ref msg);
                    DispatchMessage(ref msg);
                    break;
            }
        }

        Volatile.Write(ref _hwnd, IntPtr.Zero);
        _wndProcDelegate = null;
        _isLocked = false;
    }

    /// <summary>
    /// 窗口过程函数：绘制黑色背景并吞掉键盘/鼠标输入。
    /// </summary>
    private IntPtr WindowProc(IntPtr hWnd, uint uMsg, IntPtr wParam, IntPtr lParam)
    {
        switch (uMsg)
        {
            case WmPaint:
                OnPaint(hWnd);
                return IntPtr.Zero;

            case WmEraseBkgnd:
                return new IntPtr(1); // 表示已处理

            case WmKeyDown:
            case WmKeyUp:
            case WmSysKeyDown:
            case WmSysKeyUp:
            case WmLButtonDown:
            case WmLButtonUp:
            case WmRButtonDown:
            case WmRButtonUp:
            case WmMButtonDown:
            case WmMButtonUp:
                // 阻止所有键盘和鼠标输入
                return IntPtr.Zero;

            default:
                return DefWindowProc(hWnd, uMsg, wParam, lParam);
        }
    }

    /// <summary>
    /// 绘制黑色背景。
    /// </summary>
    private void OnPaint(IntPtr hWnd)
    {
        var ps = BeginPaint(hWnd, out var paintStruct);
        if (ps == IntPtr.Zero)
        {
            return;
        }

        try
        {
            var blackBrush = CreateSolidBrush(RgbBlack);
            var previous = SelectObject(ps, blackBrush);

            var rect = paintStruct.rcPaint;
            PatBlt(ps, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, Patcopy);

            if (previous != IntPtr.Zero)
            {
                SelectObject(ps, previous);
            }

            DeleteObject(blackBrush);
        }
        finally
        {
            EndPaint(hWnd, ref paintStruct);
        }
    }

    /// <summary>
    /// 释放资源：停止 UI 线程并销毁窗口。
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _isLocked = false;

        var thread = _uiThread;
        if (thread is { IsAlive: true } && _uiThreadId != 0)
        {
            PostThreadMessage(_uiThreadId, WmQuit, IntPtr.Zero, IntPtr.Zero);
            thread.Join(TimeSpan.FromSeconds(2));
        }

        _windowCreated.Dispose();
    }

    private delegate IntPtr WndProc(IntPtr hWnd, uint uMsg, IntPtr wParam, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential)]
    private struct MSG
    {
        public IntPtr hwnd;
        public uint message;
        public IntPtr wParam;
        public IntPtr lParam;
        public uint time;
        public int ptX;
        public int ptY;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PAINTSTRUCT
    {
        public IntPtr hdc;
        public bool fErase;
        public RECT rcPaint;
        public bool fRestore;
        public bool fIncUpdate;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] rgbReserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT
    {
        public int left;
        public int top;
        public int right;
        public int bottom;
    }

    private const uint WmQuit = 0x0012;
    private const uint WmPaint = 0x000F;
    private const uint WmEraseBkgnd = 0x0014;
    private const uint WmKeyDown = 0x0100;
    private const uint WmKeyUp = 0x0101;
    private const uint WmSysKeyDown = 0x0104;
    private const uint WmSysKeyUp = 0x0105;
    private const uint WmLButtonDown = 0x0201;
    private const uint WmLButtonUp = 0x0202;
    private const uint WmRButtonDown = 0x0204;
    private const uint WmRButtonUp = 0x0205;
    private const uint WmMButtonDown = 0x0207;
    private const uint WmMButtonUp = 0x0208;

    private const int WsPopup = unchecked((int)0x80000000);
    private const int WsExTopmost = 0x00000008;
    private const int WsExToolwindow = 0x00000080;
    private const int SwShow = 5;
    private const int SwHide = 0;
    private const int GlpWndProc = -4;
    private const int SmCxScreen = 0;
    private const int SmCyScreen = 1;

    private const uint Patcopy = 0x00F00021;
    private const uint RgbBlack = 0x00000000;

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr CreateWindowEx(
        uint dwExStyle, string lpszClassName, string lpszWindowName,
        uint style, int x, int y, int nWidth, int nHeight,
        IntPtr hWndParent, IntPtr hMenu, IntPtr hInstance, IntPtr lpParam);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr DefWindowProc(IntPtr hWnd, uint uMsg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetWindowLongPtr(IntPtr hWnd, int nIndex, IntPtr dwNewLong);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool UpdateWindow(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyWindow(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool InvalidateRect(IntPtr hWnd, IntPtr lpRect, bool bErase);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern int GetSystemMetrics(int nIndex);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern int GetMessage(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool TranslateMessage(ref MSG lpMsg);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr DispatchMessage(ref MSG lpMsg);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool PostMessage(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool PostThreadMessage(uint threadId, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern IntPtr CreateSolidBrush(uint crColor);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern IntPtr SelectObject(IntPtr hdc, IntPtr h);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern bool PatBlt(IntPtr hdc, int nXLeft, int nYLeft, int nWidth, int nHeight, uint dwRop);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern bool DeleteObject(IntPtr hObject);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr BeginPaint(IntPtr hWnd, out PAINTSTRUCT lpPaint);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool EndPaint(IntPtr hWnd, ref PAINTSTRUCT lpPaint);
}
