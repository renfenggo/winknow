using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace Winknow.SessionAgent;

/// <summary>
/// 锁屏遮罩组件：SessionAgent 本就跑在学生桌面会话，天然画遮罩；
/// 标准用户杀不掉 SYSTEM 服务下发的窗口。
///
/// P2-03 增强：
/// - 覆盖整个虚拟桌面（多显示器，含负坐标副屏），不再只盖主屏；
/// - 响应 WM_DISPLAYCHANGE（热插拔/分辨率变化）自动重设覆盖范围；
/// - 绘制锁定提示文本（"设备已锁定，请联系教师获取解锁码"）。
/// 注意：窗口句柄只允许在创建它的线程（主消息泵线程）上操作。
/// </summary>
public sealed class LockOverlay : IDisposable
{
    private readonly ILogger<LockOverlay>? _logger;
    private IntPtr _hwnd = IntPtr.Zero;
    private IntPtr _oldWndProc = IntPtr.Zero;
    private bool _isLocked = false;
    private string _reason = DefaultReason;
    private WndProc? _wndProcDelegate;

    private const string DefaultReason = "设备已锁定，请联系教师获取解锁码";

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
    private static extern bool SetWindowPos(
        IntPtr hWnd, IntPtr hWndInsertAfter, int x, int y, int cx, int cy, uint uFlags);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool GetClientRect(IntPtr hWnd, out RECT lpRect);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern int GetSystemMetrics(int nIndex);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern IntPtr CreateSolidBrush(uint crColor);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern IntPtr SelectObject(IntPtr hdc, IntPtr h);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern bool DeleteObject(IntPtr hObject);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern bool PatBlt(IntPtr hdc, int nXLeft, int nYLeft, int nWidth, int nHeight, uint dwRop);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern IntPtr GetStockObject(int fnObject);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern int SetTextColor(IntPtr hdc, uint crColor);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern int SetBkMode(IntPtr hdc, int iBkMode);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern int DrawTextW(IntPtr hdc, string lpchText, int cchText, ref RECT lprc, uint format);

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

    // 窗口样式常量
    private const int WS_POPUP = unchecked((int)0x80000000);
    private const int WS_VISIBLE = 0x10000000;
    private const int WS_EX_TOPMOST = 0x00000008;
    private const int WS_EX_TOOLWINDOW = 0x00000080;
    private const int SW_SHOW = 5;
    private const int GWLP_WNDPROC = -4;

    // SetWindowPos
    private static readonly IntPtr HWND_TOPMOST = new(-1);
    private const uint SWP_NOACTIVATE = 0x0010;
    private const uint SWP_SHOWWINDOW = 0x0040;

    // GetSystemMetrics 索引（虚拟桌面）
    private const int SM_XVIRTUALSCREEN = 76;
    private const int SM_YVIRTUALSCREEN = 77;
    private const int SM_CXVIRTUALSCREEN = 78;
    private const int SM_CYVIRTUALSCREEN = 79;

    // 消息常量
    private const uint WM_PAINT = 0x000F;
    private const uint WM_ERASEBKGND = 0x0014;
    private const uint WM_DISPLAYCHANGE = 0x007E;
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

    private const uint PATCOPY = 0x00F00021;

    // 颜色（COLORREF：0x00BBGGRR）
    private const uint RGB_BLACK = 0x00000000;
    private const uint RGB_WHITE = 0x00FFFFFF;

    // 文本绘制
    private const int DEFAULT_GUI_FONT = 17;
    private const int TRANSPARENT_BKMODE = 1;
    private const uint DT_CENTER = 0x0001;
    private const uint DT_VCENTER = 0x0004;
    private const uint DT_SINGLELINE = 0x0020;

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
    /// 显示锁屏遮罩（覆盖整个虚拟桌面）。
    /// 必须在消息泵线程调用。
    /// </summary>
    /// <param name="reason">展示给学生的锁定提示；为空时使用默认文案。</param>
    public bool Show(string? reason = null)
    {
        if (_isLocked)
        {
            // 已锁定时仅更新提示文案并重绘
            if (!string.IsNullOrEmpty(reason) && reason != _reason)
            {
                _reason = reason;
                if (_hwnd != IntPtr.Zero)
                {
                    InvalidateRect(_hwnd, IntPtr.Zero, true);
                }
            }
            return true;
        }

        try
        {
            _reason = string.IsNullOrWhiteSpace(reason) ? DefaultReason : reason;

            // 覆盖整个虚拟桌面（多显示器，含负坐标副屏）
            GetVirtualDesktopBounds(out var x, out var y, out var width, out var height);

            _wndProcDelegate = WindowProc;
            _hwnd = CreateWindowEx(
                unchecked((uint)(WS_EX_TOPMOST | WS_EX_TOOLWINDOW)),
                "STATIC",
                "Winknow Lock Screen",
                unchecked((uint)(WS_POPUP | WS_VISIBLE)),
                x, y, width, height,
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
            _logger?.LogInformation(
                "Lock overlay shown (virtual desktop {X},{Y} {Width}x{Height})", x, y, width, height);
            return true;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to show lock overlay");
            return false;
        }
    }

    /// <summary>
    /// 隐藏锁屏遮罩（已授权解锁）。
    /// 必须在消息泵线程调用。
    /// </summary>
    public bool Hide()
    {
        if (!_isLocked)
        {
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
            _reason = DefaultReason;
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

            case WM_DISPLAYCHANGE:
                // 显示器热插拔/分辨率变化：按最新虚拟桌面重设覆盖范围
                OnDisplayChange();
                return IntPtr.Zero;

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
                // 阻止到遮罩窗口的所有键盘和鼠标输入
                return IntPtr.Zero;

            default:
                return DefWindowProc(hWnd, uMsg, wParam, lParam);
        }
    }

    /// <summary>
    /// 显示配置变化：重设窗口到最新虚拟桌面边界并保持置顶。
    /// </summary>
    private void OnDisplayChange()
    {
        if (_hwnd == IntPtr.Zero)
        {
            return;
        }

        GetVirtualDesktopBounds(out var x, out var y, out var width, out var height);
        SetWindowPos(_hwnd, HWND_TOPMOST, x, y, width, height, SWP_NOACTIVATE | SWP_SHOWWINDOW);
        InvalidateRect(_hwnd, IntPtr.Zero, true);
        _logger?.LogInformation(
            "Display change detected, overlay repositioned to virtual desktop {X},{Y} {Width}x{Height}",
            x, y, width, height);
    }

    /// <summary>
    /// 取虚拟桌面（所有显示器的并集）边界。
    /// </summary>
    private static void GetVirtualDesktopBounds(out int x, out int y, out int width, out int height)
    {
        x = GetSystemMetrics(SM_XVIRTUALSCREEN);
        y = GetSystemMetrics(SM_YVIRTUALSCREEN);
        width = GetSystemMetrics(SM_CXVIRTUALSCREEN);
        height = GetSystemMetrics(SM_CYVIRTUALSCREEN);
        if (width <= 0 || height <= 0)
        {
            // 单屏或虚拟桌面不可用时的兜底：主屏尺寸
            x = 0;
            y = 0;
            width = GetSystemMetrics(0);
            height = GetSystemMetrics(1);
        }
    }

    /// <summary>
    /// 绘制黑色背景和居中提示文本。
    /// </summary>
    private void OnPaint(IntPtr hWnd)
    {
        var ps = BeginPaint(hWnd, out var paintStruct);
        if (ps == IntPtr.Zero)
            return;

        var blackBrush = CreateSolidBrush(RGB_BLACK);
        try
        {
            SelectObject(ps, blackBrush);

            var rect = paintStruct.rcPaint;
            PatBlt(ps, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, PATCOPY);

            // 居中提示文本（白色，透明底，系统 GUI 字体）
            if (GetClientRect(hWnd, out var client))
            {
                var font = GetStockObject(DEFAULT_GUI_FONT);
                var oldFont = SelectObject(ps, font);
                SetBkMode(ps, TRANSPARENT_BKMODE);
                SetTextColor(ps, RGB_WHITE);

                DrawTextW(ps, _reason, -1, ref client, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

                SelectObject(ps, oldFont);
            }
        }
        finally
        {
            DeleteObject(blackBrush);
            EndPaint(hWnd, ref paintStruct);
        }
    }

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
