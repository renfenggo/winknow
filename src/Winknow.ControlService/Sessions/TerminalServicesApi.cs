using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Extensions.Logging;

namespace Winknow.ControlService.Sessions;

/// <summary>
/// 终端服务 API 的 P/Invoke 实现（需 SYSTEM 身份）。
///
/// 会话枚举：WTSEnumerateSessionsW 轮询（~2 秒差异检测，见 WtsSessionMonitor）。
/// 会话内启动：WTSQueryUserToken（取用户主令牌）→ CreateEnvironmentBlock（用户环境变量）
///             → CreateProcessAsUserW（在目标会话桌面启动 Agent）。
/// 全部封装在本类，Worker 不直接调用 CreateProcessAsUser（架构约束）。
/// </summary>
public sealed class TerminalServicesApi : ITerminalServicesApi
{
    private readonly ILogger<TerminalServicesApi>? _logger;

    /// <summary>创建终端服务 API。</summary>
    public TerminalServicesApi(ILogger<TerminalServicesApi>? logger = null)
    {
        _logger = logger;
    }

    /// <inheritdoc/>
    public IReadOnlyList<WtsSession> EnumerateSessions()
    {
        var sessions = new List<WtsSession>();

        IntPtr buffer = IntPtr.Zero;
        try
        {
            if (!WTSEnumerateSessionsW(IntPtr.Zero, 0, 1, out buffer, out var count))
            {
                var error = Marshal.GetLastWin32Error();
                _logger?.LogWarning("WTSEnumerateSessionsW failed: {Error}", new Win32Exception(error).Message);
                return sessions;
            }

            var current = buffer;
            var structSize = Marshal.SizeOf<WTS_SESSION_INFO>();
            for (var i = 0; i < count; i++)
            {
                var info = Marshal.PtrToStructure<WTS_SESSION_INFO>(current);
                sessions.Add(new WtsSession(info.SessionId, MapState(info.State)));
                current += structSize;
            }
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                WTSFreeMemory(buffer);
            }
        }

        return sessions;
    }

    /// <inheritdoc/>
    public bool TryGetSessionUserSid(int sessionId, out string userSid)
    {
        userSid = string.Empty;

        if (!WTSQueryUserToken(sessionId, out var token))
        {
            // 服务会话（session 0）或无用户登录时无主令牌，属预期
            return false;
        }

        try
        {
            using var identity = new WindowsIdentity(token);
            userSid = identity.User?.Value ?? string.Empty;
            return userSid.Length > 0;
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "WindowsIdentity(token) failed for session {SessionId}", sessionId);
            return false;
        }
        finally
        {
            CloseHandle(token);
        }
    }

    /// <inheritdoc/>
    public bool TryLaunchProcessInSession(int sessionId, string exePath, out int pid, out string error)
    {
        pid = 0;
        error = string.Empty;

        if (!WTSQueryUserToken(sessionId, out var token))
        {
            error = $"WTSQueryUserToken failed for session {sessionId}: " +
                new Win32Exception(Marshal.GetLastWin32Error()).Message;
            return false;
        }

        IntPtr environment = IntPtr.Zero;
        try
        {
            if (!CreateEnvironmentBlock(out environment, token, bInherit: false))
            {
                error = "CreateEnvironmentBlock failed: " + new Win32Exception(Marshal.GetLastWin32Error()).Message;
                return false;
            }

            var commandLine = $"\"{exePath}\"";
            var si = new STARTUPINFOW
            {
                cb = Marshal.SizeOf<STARTUPINFOW>(),
                lpDesktop = @"winsta0\default",
            };

            // CREATE_NO_WINDOW 不适用 WinExe；Agent 需要在交互桌面可见（锁屏遮罩），
            // 用 CREATE_UNICODE_ENVIRONMENT 标记环境块为 Unicode。
            if (!CreateProcessAsUserW(
                    token,
                    exePath,
                    commandLine,
                    IntPtr.Zero, IntPtr.Zero,
                    bInheritHandles: false,
                    CREATE_UNICODE_ENVIRONMENT,
                    environment,
                    lpCurrentDirectory: Path.GetDirectoryName(exePath) ?? string.Empty,
                    ref si,
                    out var pi))
            {
                error = "CreateProcessAsUserW failed: " + new Win32Exception(Marshal.GetLastWin32Error()).Message;
                return false;
            }

            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            pid = (int)pi.dwProcessId;
            return true;
        }
        finally
        {
            if (environment != IntPtr.Zero)
            {
                DestroyEnvironmentBlock(environment);
            }

            CloseHandle(token);
        }
    }

    private static WtsSessionState MapState(int state) => state switch
    {
        0 => WtsSessionState.Active,
        1 => WtsSessionState.Connected,
        4 => WtsSessionState.Disconnected,
        5 => WtsSessionState.Idle,
        6 => WtsSessionState.Listen,
        _ => WtsSessionState.Other
    };

    private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFOW
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WTS_SESSION_INFO
    {
        public int SessionId;
        [MarshalAs(UnmanagedType.LPStr)]
        public string pWinStationName;
        public int State;
    }

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSEnumerateSessionsW(
        IntPtr hServer, int Reserved, int Version, out IntPtr ppSessionInfo, out int pCount);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr pMemory);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(int sessionId, out IntPtr token);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

    [DllImport("userenv.dll")]
    private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessAsUserW(
        IntPtr hToken,
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        int dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFOW lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
