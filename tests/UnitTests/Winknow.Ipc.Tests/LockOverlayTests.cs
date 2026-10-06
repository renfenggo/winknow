using System.Runtime.InteropServices;
using Winknow.SessionAgent;

namespace Winknow.Ipc.Tests;

/// <summary>
/// M2-7 LockOverlay 消息循环测试：遮罩窗口必须在专用 UI 线程上由 GetMessage
/// 泵驱动才能完成显示/隐藏（原实现无消息循环，窗口创建后不绘制）。
/// 需要交互桌面会话（本地开发环境满足；无桌面的服务会话中窗口无法创建）。
/// </summary>
public sealed class LockOverlayTests
{
    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    private static async Task<bool> WaitForAsync(Func<bool> condition, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (condition())
            {
                return true;
            }

            await Task.Delay(50);
        }

        return condition();
    }

    [Fact]
    public async Task Overlay_ShowMakesWindowVisible_HideHidesIt()
    {
        using var overlay = new LockOverlay();

        Assert.True(overlay.Show());
        Assert.True(overlay.IsLocked);
        var visible = await WaitForAsync(() => IsWindowVisible(overlay.WindowHandle), TimeSpan.FromSeconds(5));
        Assert.True(visible, "overlay window should become visible after Show (message pump driven).");

        Assert.True(overlay.Hide());
        Assert.False(overlay.IsLocked);
        var hidden = await WaitForAsync(() => !IsWindowVisible(overlay.WindowHandle), TimeSpan.FromSeconds(5));
        Assert.True(hidden, "overlay window should become invisible after Hide.");
    }

    [Fact]
    public async Task Overlay_DisposeStopsUiThreadAndDestroysWindow()
    {
        var overlay = new LockOverlay();
        Assert.True(overlay.Show());
        Assert.True(await WaitForAsync(() => IsWindowVisible(overlay.WindowHandle), TimeSpan.FromSeconds(5)));

        overlay.Dispose();
        overlay.Dispose(); // 幂等

        Assert.False(overlay.IsLocked);
        Assert.Equal(IntPtr.Zero, overlay.WindowHandle);
        Assert.False(overlay.Show(), "Show after Dispose must be rejected.");
    }

    [Fact]
    public void Overlay_HideWithoutShow_IsNoOpSuccess()
    {
        using var overlay = new LockOverlay();
        Assert.False(overlay.IsLocked);
        Assert.True(overlay.Hide());
    }
}
