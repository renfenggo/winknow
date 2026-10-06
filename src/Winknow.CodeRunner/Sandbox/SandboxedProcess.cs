using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Winknow.CodeRunner.Sandbox;

/// <summary>
/// 沙箱进程启动参数。
/// </summary>
public sealed class SandboxedProcessStartInfo
{
    /// <summary>可执行文件完整路径。</summary>
    public string FileName { get; init; } = string.Empty;

    /// <summary>命令行参数（不含程序名）。</summary>
    public string Arguments { get; init; } = string.Empty;

    /// <summary>工作目录（空 = 继承父进程）。</summary>
    public string? WorkingDirectory { get; init; }

    /// <summary>受限令牌（null = 以调用方令牌启动，仅测试用）。</summary>
    public SafeAccessTokenHandle? Token { get; init; }

    /// <summary>是否重定向 stdout/stderr（管道捕获）。</summary>
    public bool RedirectOutput { get; init; }

    /// <summary>是否提供 stdin 管道（供写入后关闭）。</summary>
    public bool ProvideStdin { get; init; }
}

/// <summary>
/// 沙箱进程：CREATE_SUSPENDED 启动 → 等调用方 Assign 进 Job → ResumeThread。
/// 支持 stdin 注入与 stdout/stderr 管道捕获（按需读取，管道写端随进程树关闭而 EOF）。
/// 沙箱令牌路径：生产（服务上下文持有 SeAssignPrimaryTokenPrivilege）用 CreateProcessAsUser
/// 完整受限令牌；非特权环境（开发/测试）返回 ERROR_PRIVILEGE_NOT_HELD 时降级——
/// 以调用方令牌启动后把子进程完整性降为 Low（工作区外只读隔离仍成立）。
/// </summary>
public sealed class SandboxedProcess : IDisposable
{
    internal const uint CreateSuspended = 0x0000_0004;
    internal const uint CreateNoWindow = 0x0800_0000;
    internal const uint StartfUseStdHandles = 0x0000_0100;

    private IntPtr _process;
    private IntPtr _thread;
    private IntPtr _stdoutRead = IntPtr.Zero;
    private IntPtr _stderrRead = IntPtr.Zero;
    private IntPtr _stdinWrite = IntPtr.Zero;
    private bool _resumed;
    private bool _exitCodeRead;
    private uint _exitCode;

    private SandboxedProcess(IntPtr process, IntPtr thread, int id,
        IntPtr stdoutRead, IntPtr stderrRead, IntPtr stdinWrite, bool usedRestrictedToken)
    {
        _process = process;
        _thread = thread;
        Id = id;
        _stdoutRead = stdoutRead;
        _stderrRead = stderrRead;
        _stdinWrite = stdinWrite;
        UsedRestrictedToken = usedRestrictedToken;
    }

    /// <summary>进程 ID。</summary>
    public int Id { get; }

    /// <summary>是否以完整受限令牌启动（false = 低完整性降级路径，见类注释）。</summary>
    public bool UsedRestrictedToken { get; }

    /// <summary>进程主句柄（供 JobObject.Assign 使用；外部不得关闭）。</summary>
    internal IntPtr ProcessHandle => _process;

    /// <summary>
    /// 以挂起态启动进程（调用方随后 Assign 到 Job，再 Resume）。
    /// </summary>
    /// <param name="startInfo">启动参数。</param>
    /// <returns>挂起态进程。</returns>
    public static SandboxedProcess Start(SandboxedProcessStartInfo startInfo)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(startInfo.FileName);

        var stdoutRead = IntPtr.Zero;
        var stdoutWrite = IntPtr.Zero;
        var stderrRead = IntPtr.Zero;
        var stderrWrite = IntPtr.Zero;
        var stdinRead = IntPtr.Zero;
        var stdinWrite = IntPtr.Zero;

        try
        {
            var inherit = false;
            if (startInfo.RedirectOutput)
            {
                (stdoutRead, stdoutWrite) = CreatePipe(inheritableWrite: true);
                (stderrRead, stderrWrite) = CreatePipe(inheritableWrite: true);
                inherit = true;
            }

            if (startInfo.ProvideStdin)
            {
                (stdinRead, stdinWrite) = CreatePipe(inheritableWrite: false);
                // 读端可继承给子进程，写端留在父进程
                NativeMethods.SetHandleInformation(stdinRead, 0x0000_0001, 0x0000_0001);
                inherit = true;
            }

            var si = new NativeMethods.STARTUPINFOW
            {
                cb = Marshal.SizeOf<NativeMethods.STARTUPINFOW>(),
                dwFlags = startInfo.RedirectOutput || startInfo.ProvideStdin ? (int)StartfUseStdHandles : 0,
                hStdInput = stdinRead,
                hStdOutput = stdoutWrite,
                hStdError = stderrWrite,
            };

            var commandLine = $"\"{startInfo.FileName}\" {startInfo.Arguments}";
            var flags = CreateSuspended | CreateNoWindow;

            NativeMethods.PROCESS_INFORMATION pi;
            bool usedRestrictedToken;
            if (startInfo.Token is { } token)
            {
                if (NativeMethods.CreateProcessAsUserW(token.Handle, null, commandLine, IntPtr.Zero, IntPtr.Zero,
                        inherit, flags, IntPtr.Zero, startInfo.WorkingDirectory, ref si, out pi))
                {
                    usedRestrictedToken = true;
                }
                else
                {
                    var error = Marshal.GetLastWin32Error();
                    if (error != NativeMethods.ErrorPrivilegeNotHeld)
                    {
                        throw new Win32Exception(error);
                    }

                    // 降级路径：非特权宿主对 CreateRestrictedToken 派生令牌调用
                    // CreateProcessAsUser 一律 1314（无 SeAssignPrimaryTokenPrivilege）——
                    // 以调用方令牌挂起启动，再降子进程完整性为 Low（特权/组削减仅生产路径具备）
                    if (!NativeMethods.CreateProcessW(null, commandLine, IntPtr.Zero, IntPtr.Zero,
                            inherit, flags, IntPtr.Zero, startInfo.WorkingDirectory, ref si, out pi))
                    {
                        throw new Win32Exception();
                    }

                    RestrictedTokenSource.LowerProcessTokenIntegrity(pi.hProcess);
                    usedRestrictedToken = false;
                }
            }
            else
            {
                if (!NativeMethods.CreateProcessW(null, commandLine, IntPtr.Zero, IntPtr.Zero,
                        inherit, flags, IntPtr.Zero, startInfo.WorkingDirectory, ref si, out pi))
                {
                    throw new Win32Exception();
                }

                usedRestrictedToken = false;
            }

            // 子进程已拿到写端/读端副本，父进程侧的副本即可关闭
            if (stdoutWrite != IntPtr.Zero)
            {
                NativeMethods.CloseHandle(stdoutWrite);
            }

            if (stderrWrite != IntPtr.Zero)
            {
                NativeMethods.CloseHandle(stderrWrite);
            }

            if (stdinRead != IntPtr.Zero)
            {
                NativeMethods.CloseHandle(stdinRead);
            }

            return new SandboxedProcess(pi.hProcess, pi.hThread, pi.dwProcessId,
                stdoutRead, stderrRead, stdinWrite, usedRestrictedToken);
        }
        catch
        {
            CloseIfValid(stdoutRead);
            CloseIfValid(stdoutWrite);
            CloseIfValid(stderrRead);
            CloseIfValid(stderrWrite);
            CloseIfValid(stdinRead);
            CloseIfValid(stdinWrite);
            throw;
        }
    }

    /// <summary>恢复主线程（Assign 到 Job 之后调用）。</summary>
    public void Resume()
    {
        if (_thread != IntPtr.Zero && !_resumed)
        {
            NativeMethods.ResumeThread(_thread);
            _resumed = true;
        }
    }

    /// <summary>
    /// 终止进程（挂起态与运行态均有效）。
    /// 用于 Assign 失败（超限进程不受 Job 管控，不杀即泄漏）或墙钟超时的强制清理。
    /// </summary>
    public void Kill()
    {
        if (_process != IntPtr.Zero)
        {
            NativeMethods.TerminateProcess(_process, unchecked((uint)-1));
        }
    }

    /// <summary>等待进程退出。</summary>
    /// <param name="milliseconds">超时毫秒数（-1 无限）。</param>
    /// <returns>是否已退出。</returns>
    public bool WaitForExit(int milliseconds)
    {
        if (_process == IntPtr.Zero)
        {
            return true;
        }

        // WAIT_OBJECT_0 = 0（bool 编组会把非零超时码当 true，必须按 uint 比较）
        const uint waitObject0 = 0;
        var result = NativeMethods.WaitForSingleObject(_process, unchecked((uint)milliseconds));
        return result == waitObject0;
    }

    /// <summary>进程退出码（须在退出后访问）。</summary>
    public int ExitCode
    {
        get
        {
            if (!_exitCodeRead)
            {
                if (_process != IntPtr.Zero)
                {
                    NativeMethods.GetExitCodeProcess(_process, out _exitCode);
                }

                _exitCodeRead = true;
            }

            return unchecked((int)_exitCode);
        }
    }

    /// <summary>写入 stdin 数据并关闭写端（一次性输入）。</summary>
    /// <param name="data">UTF-8 字节。</param>
    public void WriteStdinAndClose(byte[] data)
    {
        if (_stdinWrite == IntPtr.Zero)
        {
            throw new InvalidOperationException("stdin pipe was not requested.");
        }

        try
        {
            var offset = 0;
            while (offset < data.Length)
            {
                var chunk = Math.Min(64 * 1024, data.Length - offset);
                if (!NativeMethods.WriteFile(_stdinWrite, data, (uint)chunk, out var written, IntPtr.Zero))
                {
                    break; // 子进程已关闭 stdin 或已退出
                }

                offset += (int)written;
            }
        }
        finally
        {
            NativeMethods.CloseHandle(_stdinWrite);
            _stdinWrite = IntPtr.Zero;
        }
    }

    /// <summary>
    /// 读取 stdout 累积数据（阻塞至写端关闭 EOF 或读满上限）。
    /// </summary>
    /// <param name="maxBytes">读取上限（读满即停，配合截断标记）。</param>
    /// <returns>读到的字节。</returns>
    public byte[] ReadStdout(int maxBytes) => ReadPipe(_stdoutRead, maxBytes);

    /// <summary>
    /// 读取 stderr 累积数据（阻塞至写端关闭 EOF 或读满上限）。
    /// </summary>
    /// <param name="maxBytes">读取上限（读满即停，配合截断标记）。</param>
    /// <returns>读到的字节。</returns>
    public byte[] ReadStderr(int maxBytes) => ReadPipe(_stderrRead, maxBytes);

    /// <summary>释放进程/线程/管道句柄。</summary>
    public void Dispose()
    {
        CloseIfValid(_process);
        CloseIfValid(_thread);
        CloseIfValid(_stdoutRead);
        CloseIfValid(_stderrRead);
        CloseIfValid(_stdinWrite);
        _process = IntPtr.Zero;
        _thread = IntPtr.Zero;
        _stdoutRead = IntPtr.Zero;
        _stderrRead = IntPtr.Zero;
        _stdinWrite = IntPtr.Zero;
    }

    private static (IntPtr Read, IntPtr Write) CreatePipe(bool inheritableWrite)
    {
        var sa = new NativeMethods.SECURITY_ATTRIBUTES
        {
            nLength = Marshal.SizeOf<NativeMethods.SECURITY_ATTRIBUTES>(),
            bInheritHandle = true,
        };
        if (!NativeMethods.CreatePipe(out var read, out var write, ref sa, 0))
        {
            throw new Win32Exception();
        }

        // 读端不继承（留在父进程），写端继承给子进程
        NativeMethods.SetHandleInformation(read, 0x0000_0001, 0);
        if (!inheritableWrite)
        {
            NativeMethods.SetHandleInformation(write, 0x0000_0001, 0);
        }

        return (read, write);
    }

    private byte[] ReadPipe(IntPtr pipe, int maxBytes)
    {
        if (pipe == IntPtr.Zero)
        {
            return Array.Empty<byte>();
        }

        // ReadFile 阻塞语义：有数据即读（EOF 前缓冲数据不丢），写端全关返回
        // FALSE(ERROR_BROKEN_PIPE) 即 EOF。不得用 PeekNamedPipe 轮询——写端关闭后
        // Peek 直接失败，缓冲区残留数据会被整段丢弃（快退出程序的输出竞态）。
        using var buffer = new MemoryStream();
        var chunk = new byte[64 * 1024];
        while (buffer.Length < maxBytes)
        {
            var want = (uint)Math.Min(chunk.Length, maxBytes - (int)buffer.Length);
            if (!NativeMethods.ReadFile(pipe, chunk, want, out var read, IntPtr.Zero))
            {
                break;
            }

            if (read == 0)
            {
                break;
            }

            buffer.Write(chunk, 0, (int)read);
        }

        return buffer.ToArray();
    }

    private static void CloseIfValid(IntPtr handle)
    {
        if (handle != IntPtr.Zero)
        {
            NativeMethods.CloseHandle(handle);
        }
    }
}
