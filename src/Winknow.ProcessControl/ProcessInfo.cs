namespace Winknow.ProcessControl;

/// <summary>
/// 进程信息快照（综合判断所需字段）。
/// </summary>
public sealed class ProcessInfo
{
    /// <summary>进程 ID。</summary>
    public int ProcessId { get; init; }

    /// <summary>父进程 ID。</summary>
    public int ParentProcessId { get; init; }

    /// <summary>进程名称（不含路径，仅用于日志，不作为唯一放行依据）。</summary>
    public string ProcessName { get; init; } = string.Empty;

    /// <summary>可执行文件完整路径。</summary>
    public string FilePath { get; init; } = string.Empty;

    /// <summary>命令行参数。</summary>
    public string CommandLine { get; init; } = string.Empty;

    /// <summary>运行用户 SID。</summary>
    public string UserSid { get; init; } = string.Empty;

    /// <summary>运行用户名。</summary>
    public string UserName { get; init; } = string.Empty;

    /// <summary>文件 SHA-256 哈希（16 进制）。</summary>
    public string FileHash { get; init; } = string.Empty;

    /// <summary>数字签名主体（空表示未签名）。</summary>
    public string SignatureSubject { get; init; } = string.Empty;

    /// <summary>是否已签名。</summary>
    public bool IsSigned => !string.IsNullOrEmpty(SignatureSubject);

    /// <summary>启动时间。</summary>
    public DateTime StartTime { get; init; }
}
