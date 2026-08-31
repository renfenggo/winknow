using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace Winknow.SessionAgent;

/// <summary>
/// 锁屏遮罩组件：SessionAgent本就跑在学生桌面会话，天然画遮罩；
/// 标准用户杀不掉SYSTEM服务下发的窗口。
/// </summary>
public sealed class LockOverlay
{
    private readonly ILogger<LockOverlay>? _logger;
    private IntPtr _hwnd = IntPtr.Zero;
    private IntPtr _oldWndProc = IntPtr.Zero;
    private bool _isLocked = false;
    private WndProc? _wndProcDelegate;

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

    // 窗口样式常量
    private const int WS_POPUP = unchecked((int)0x80000000);
    private const int WS_VISIBLE = 0x10000000;
    private const int WS_EX_TOPMOST = 0x00000008;
    private const int WS_EX_TOOLWINDOW = 0x00000080;
    private const int SW_SHOW = 5;
    private const int GWLP_WNDPROC = -4;

    // 消息常量
    private const uint WM_PAINT = 0x000F;
    private const uint WM_ERASEBKGND = 0x0014;
    private const uint WM_KEYDOWN = 0x0100;
    private const uint WM_KEYUP = 0x0101;
    private const uint WM_SYSKEYDOWN = 0x0104;
    private const uint WM_SYSKEYUP = 0x0105;
    private const uint WM_LBUTTONDOWN = 0x0201;
    private const uint WM_LBUTTONUP = 0x0202;
    private const uint WM_RBUTTONDOWN = 0x0204;
    private const uint WM_RBUTTONUP = 0x0205;
    private const uint WM_MBUTTONDOWN = 0x0207;
    private const uint WM_MBUTTONUP = 0x0208;

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern IntPtr CreateSolidBrush(uint crColor);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern IntPtr SelectObject(IntPtr hdc, IntPtr h);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern bool PatBlt(IntPtr hdc, int nXLeft, int nYLeft, int nWidth, int nHeight, uint dwRop);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr BeginPaint(IntPtr hWnd, out PAINTSTRUCT lpPaint);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool EndPaint(IntPtr hWnd, ref PAINTSTRUCT lpPaint);

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

    private const uint PATCOPY = 0x00F00021;
    private const uint COLOR_WINDOW = 5;
    private const uint COLOR_WINDOWTEXT = 8;

    // 黑色背景
    private const uint RGB_BLACK = 0x00000000;

    private delegate IntPtr WndProc(IntPtr hWnd, uint uMsg, IntPtr wParam, IntPtr lParam);

    /// <summary>
    /// 创建锁屏遮罩。
    /// </summary>
    /// <param name="logger">可选的日志记录器。</param>
    public LockOverlay(ILogger<LockOverlay>? logger = null)
    {
        _logger = logger;
    }

    /// <summary>当前锁定状态。</summary>
    public bool IsLocked => _isLocked;

    /// <summary>
    /// 显示锁屏遮罩。
    /// </summary>
    public bool Show()
    {
        if (_isLocked)
        {
            _logger?.LogWarning("Lock overlay already shown");
            return true;
        }

        try
        {
            // 获取屏幕尺寸
            var screenWidth = GetSystemMetrics(0);
            var screenHeight = GetSystemMetrics(1);

            // 创建全屏遮罩窗口
            _wndProcDelegate = WindowProc;
            _hwnd = CreateWindowEx(
                unchecked((uint)(WS_EX_TOPMOST | WS_EX_TOOLWINDOW)),
                "STATIC",
                "Winknow Lock Screen",
                unchecked((uint)(WS_POPUP | WS_VISIBLE)),
                0, 0,
                (int)screenWidth, (int)screenHeight,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

            if (_hwnd == IntPtr.Zero)
            {
                _logger?.LogError("Failed to create lock overlay window: {Error}", Marshal.GetLastWin32Error());
                return false;
            }

            // 设置窗口过程
            _oldWndProc = SetWindowLongPtr(_hwnd, GWLP_WNDPROC, Marshal.GetFunctionPointerForDelegate(_wndProcDelegate));
            if (_oldWndProc == IntPtr.Zero)
            {
                _logger?.LogError("Failed to set window procedure: {Error}", Marshal.GetLastWin32Error());
                DestroyWindow(_hwnd);
                _hwnd = IntPtr.Zero;
                return false;
            }

            // 显示并置顶
            ShowWindow(_hwnd, SW_SHOW);
            SetForegroundWindow(_hwnd);
            UpdateWindow(_hwnd);
            InvalidateRect(_hwnd, IntPtr.Zero, true);

            _isLocked = true;
            _logger?.LogInformation("Lock overlay shown successfully");
            return true;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to show lock overlay");
            return false;
        }
    }

    /// <summary>
    /// 隐藏锁屏遮罩。
    /// </summary>
    public bool Hide()
    {
        if (!_isLocked)
        {
            _logger?.LogWarning("Lock overlay not shown");
            return true;
        }

        try
        {
            if (_hwnd != IntPtr.Zero)
            {
                // 恢复原始窗口过程
                if (_oldWndProc != IntPtr.Zero)
                {
                    SetWindowLongPtr(_hwnd, GWLP_WNDPROC, _oldWndProc);
                }

                // 销毁窗口
                DestroyWindow(_hwnd);
                _hwnd = IntPtr.Zero;
                _oldWndProc = IntPtr.Zero;
                _wndProcDelegate = null;
            }

            _isLocked = false;
            _logger?.LogInformation("Lock overlay hidden successfully");
            return true;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to hide lock overlay");
            return false;
        }
    }

    /// <summary>
    /// 窗口过程函数。
    /// </summary>
    private IntPtr WindowProc(IntPtr hWnd, uint uMsg, IntPtr wParam, IntPtr lParam)
    {
        switch (uMsg)
        {
            case WM_PAINT:
                OnPaint(hWnd);
                return IntPtr.Zero;

            case WM_ERASEBKGND:
                return new IntPtr(1); // 表示已处理

            case WM_KEYDOWN:
            case WM_KEYUP:
            case WM_SYSKEYDOWN:
            case WM_SYSKEYUP:
            case WM_LBUTTONDOWN:
            case WM_LBUTTONUP:
            case WM_RBUTTONDOWN:
            case WM_RBUTTONUP:
            case WM_MBUTTONDOWN:
            case WM_MBUTTONUP:
                // 阻止所有键盘和鼠标输入
                return IntPtr.Zero;

            default:
                return DefWindowProc(hWnd, uMsg, wParam, lParam);
        }
    }

    /// <summary>
    /// 绘制黑色背景和提示文本。
    /// </summary>
    private void OnPaint(IntPtr hWnd)
    {
        var ps = BeginPaint(hWnd, out var paintStruct);
        if (ps == IntPtr.Zero)
            return;

        try
        {
            // 填充黑色背景
            var blackBrush = CreateSolidBrush(RGB_BLACK);
            SelectObject(ps, blackBrush);

            var rect = paintStruct.rcPaint;
            PatBlt(ps, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, PATCOPY);

            // TODO 绘制提示文本（需要字体和文本绘制API）
            // "设备已锁定，请联系教师获取解锁码"
        }
        finally
        {
            EndPaint(hWnd, ref paintStruct);
        }
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern int GetSystemMetrics(int nIndex);

    /// <summary>
    /// 释放资源。
    /// </summary>
    public void Dispose()
    {
        if (_isLocked)
        {
            Hide();
        }
    }
}