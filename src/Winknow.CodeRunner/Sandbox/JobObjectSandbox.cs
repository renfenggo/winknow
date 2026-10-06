using System.ComponentModel;

namespace Winknow.CodeRunner.Sandbox;

/// <summary>
/// Windows Job Object 沙箱（ADR-003 隔离机制核心）：
/// 进程数/内存/CPU 时间限额 + JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE 进程树清理，
/// 提供峰值内存与累计写入字节记账查询。墙钟超时由调用方触发 <see cref="Terminate"/>。
/// </summary>
public sealed class JobObjectSandbox : IDisposable
{
    private const int JobObjectExtendedLimitInformation = 9;
    private const int JobObjectBasicAndIoAccountingInformation = 8;

    private const uint JobObjectLimitProcessTime = 0x0000_0002;
    private const uint JobObjectLimitActiveProcess = 0x0000_0008;
    private const uint JobObjectLimitProcessMemory = 0x0000_0100;
    private const uint JobObjectLimitKillOnJobClose = 0x0000_2000;
    private const uint JobObjectLimitDieOnUnhandledException = 0x0000_0400;

    private IntPtr _job;
    private bool _terminated;

    /// <summary>创建 Job Object 并按参数设置限额（KILL_ON_JOB_CLOSE 恒开）。</summary>
    /// <param name="activeProcessLimit">并发进程数上限（含子进程；null 不限制）。</param>
    /// <param name="processMemoryLimitBytes">单进程提交内存上限（字节；null 不限制）。</param>
    /// <param name="perProcessCpuTime">单进程 CPU 时间上限（超限进程被终止；null 不限制）。</param>
    public JobObjectSandbox(int? activeProcessLimit = null, long? processMemoryLimitBytes = null, TimeSpan? perProcessCpuTime = null)
    {
        _job = NativeMethods.CreateJobObjectW(IntPtr.Zero, null);
        if (_job == IntPtr.Zero)
        {
            throw new Win32Exception();
        }

        var info = new NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            BasicLimitInformation = new NativeMethods.JOBOBJECT_BASIC_LIMIT_INFORMATION(),
        };
        var flags = JobObjectLimitKillOnJobClose | JobObjectLimitDieOnUnhandledException;

        if (activeProcessLimit is > 0)
        {
            info.BasicLimitInformation.ActiveProcessLimit = (uint)activeProcessLimit.Value;
            flags |= JobObjectLimitActiveProcess;
        }

        if (processMemoryLimitBytes is > 0)
        {
            info.ProcessMemoryLimit = (UIntPtr)(ulong)processMemoryLimitBytes.Value;
            flags |= JobObjectLimitProcessMemory;
        }

        if (perProcessCpuTime is { } cpu)
        {
            // CPU 时间限额以 100ns 计
            info.BasicLimitInformation.PerProcessUserTimeLimit = (long)(cpu.TotalMilliseconds * 10_000);
            flags |= JobObjectLimitProcessTime;
        }

        info.BasicLimitInformation.LimitFlags = flags;
        if (!NativeMethods.SetInformationJobObject(_job, JobObjectExtendedLimitInformation, ref info,
                System.Runtime.InteropServices.Marshal.SizeOf<NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()))
        {
            var error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
            Dispose();
            throw new Win32Exception(error);
        }
    }

    /// <summary>把已启动（挂起态）的进程加入本 Job（必须在恢复线程前完成）。</summary>
    /// <param name="process">沙箱进程启动器返回的进程。</param>
    /// <returns>是否成功。</returns>
    public bool Assign(SandboxedProcess process)
    {
        ObjectDisposedException.ThrowIf(_job == IntPtr.Zero, this);
        ArgumentNullException.ThrowIfNull(process);
        return NativeMethods.AssignProcessToJobObject(_job, process.ProcessHandle);
    }

    /// <summary>终止 Job 内全部进程（进程树清理）。</summary>
    /// <param name="exitCode">统一退出码。</param>
    public void Terminate(int exitCode = -1)
    {
        if (_job == IntPtr.Zero || _terminated)
        {
            return;
        }

        _terminated = true;
        NativeMethods.TerminateJobObject(_job, unchecked((uint)exitCode));
    }

    /// <summary>查询 Job 内单进程峰值内存（字节，Job 记账）。</summary>
    /// <returns>峰值字节数；查询失败返回 0。</returns>
    public long QueryPeakProcessMemoryBytes()
    {
        if (_job == IntPtr.Zero)
        {
            return 0;
        }

        var info = new NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        return NativeMethods.QueryInformationJobObject(_job, JobObjectExtendedLimitInformation, ref info,
            System.Runtime.InteropServices.Marshal.SizeOf<NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION>(), out _)
            ? (long)info.PeakProcessMemoryUsed
            : 0;
    }

    /// <summary>查询 Job 累计写入字节（文件写入总量，作为 file_bytes 限额的记账口径）。</summary>
    /// <returns>累计写入字节数；查询失败返回 0。</returns>
    public ulong QueryWriteTransferBytes()
    {
        if (_job == IntPtr.Zero)
        {
            return 0;
        }

        var info = new NativeMethods.JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION();
        return NativeMethods.QueryInformationJobObject(_job, JobObjectBasicAndIoAccountingInformation, ref info,
            System.Runtime.InteropServices.Marshal.SizeOf<NativeMethods.JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION>(), out _)
            ? info.IoInfo.WriteTransferCount
            : 0;
    }

    /// <summary>查询 Job 当前活跃进程数。</summary>
    /// <returns>活跃进程数；查询失败返回 0。</returns>
    public int QueryActiveProcessCount()
    {
        if (_job == IntPtr.Zero)
        {
            return 0;
        }

        var info = new NativeMethods.JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION();
        return NativeMethods.QueryInformationJobObject(_job, JobObjectBasicAndIoAccountingInformation, ref info,
            System.Runtime.InteropServices.Marshal.SizeOf<NativeMethods.JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION>(), out _)
            ? (int)info.BasicAccounting.ActiveProcesses
            : 0;
    }

    /// <summary>关闭 Job 句柄（KILL_ON_JOB_CLOSE：关闭即终止全部残余进程）。</summary>
    public void Dispose()
    {
        if (_job != IntPtr.Zero)
        {
            NativeMethods.CloseHandle(_job);
            _job = IntPtr.Zero;
        }
    }
}
