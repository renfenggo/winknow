using System.Windows;
using System.Windows.Controls;
using Winknow.AdminUI;
using Winknow.Core;
using Winknow.Licensing;

internal static class Program
{
    [STAThread]
    private static int Main()
    {
        // Instantiate the real WPF page without showing a window or issuing IPC.
        var application = new Application();
        var page = new ClassroomPage(new TeacherLicenseServer());
        var grid = (DataGrid)page.FindName("DevicesGrid");
        var lockButton = (Button)page.FindName("LockButton");
        var unlockButton = (Button)page.FindName("UnlockButton");
        if (grid.Items.Count > 0)
        {
            // This used to cast DeviceViewModel to DeviceStatusInfo and throw.
            grid.SelectedIndex = 0;
            Check(!lockButton.IsEnabled && !unlockButton.IsEnabled, "remote/demo device must not control the local desktop");
        }

        var local = new DeviceViewModel { DeviceId = DeviceId.Generate(), StudentName = "local-test", Status = DeviceStatus.Online };
        var remote = new DeviceViewModel { DeviceId = "other-test-device", StudentName = "remote-test", Status = DeviceStatus.Online };
        grid.ItemsSource = new[] { local, remote };
        grid.SelectedItem = local;
        Check(lockButton.IsEnabled && !unlockButton.IsEnabled, "local online device should allow a lock request");
        grid.SelectedItem = null;
        local.Status = DeviceStatus.Locked;
        grid.SelectedItem = local;
        Check(!lockButton.IsEnabled && unlockButton.IsEnabled, "local locked device should allow an unlock request");
        grid.SelectedItem = remote;
        Check(!lockButton.IsEnabled && !unlockButton.IsEnabled, "remote device must not enable local control");
        grid.SelectedItem = null;
        Check(!lockButton.IsEnabled && !unlockButton.IsEnabled, "empty selection must disable control");
        application.Shutdown();
        Console.WriteLine("Classroom WPF smoke PASS: selection, local lock/unlock state, remote target rejection, empty selection.");
        return 0;
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}
