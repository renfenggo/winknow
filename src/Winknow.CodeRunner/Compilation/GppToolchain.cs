using System.Diagnostics;

namespace Winknow.CodeRunner.Compilation;

/// <summary>
/// g++ 编译链探测与参数构造（指导书 05：V1 仅 C++14/C++17）。
/// 探测顺序：环境变量 <see cref="CompilerPathEnvironmentVariable"/> → 官方指定 Dev-Cpp
/// 安装目录（教学环境标配）→ PATH → WinGet 用户级 WinLibs；
/// 探测后以 <c>g++ --version</c> 可执行为准。
/// </summary>
public sealed class GppToolchain
{
    /// <summary>显式指定 g++.exe 完整路径的环境变量（部署覆盖用）。</summary>
    public const string CompilerPathEnvironmentVariable = "WINKNOW_GPP_PATH";

    /// <summary>官方指定的 Dev-Cpp（TDM-GCC）默认安装路径下的 g++。</summary>
    public const string DevCppCompilerPath = @"C:\Program Files (x86)\Dev-Cpp\MinGW64\bin\g++.exe";

    /// <summary>编译器完整路径。</summary>
    public string CompilerPath { get; }

    /// <summary>编译器版本描述（--version 首行）。</summary>
    public string Version { get; }

    /// <summary>主版本号（--version 解析；解析失败按 0 处理）。</summary>
    public int MajorVersion { get; }

    private GppToolchain(string compilerPath, string version, int majorVersion)
    {
        CompilerPath = compilerPath;
        Version = version;
        MajorVersion = majorVersion;
    }

    /// <summary>语言 → -std= 开关。</summary>
    /// <param name="language">源语言。</param>
    /// <returns>如 -std=c++14。</returns>
    public static string StandardFlag(RunnerLanguage language) => language switch
    {
        RunnerLanguage.Cpp14 => "-std=c++14",
        RunnerLanguage.Cpp17 => "-std=c++17",
        _ => throw new ArgumentOutOfRangeException(nameof(language), language, null),
    };

    /// <summary>
    /// 工具链是否支持指定语言（-std= 开关能力：-std=c++17 需 GCC ≥ 5）。
    /// </summary>
    /// <param name="language">源语言。</param>
    /// <returns>支持返回 true；如官方 Dev-Cpp 4.9.2 不支持 C++17。</returns>
    public bool Supports(RunnerLanguage language) => language switch
    {
        RunnerLanguage.Cpp14 => MajorVersion >= 4,
        RunnerLanguage.Cpp17 => MajorVersion >= 5,
        _ => false,
    };

    /// <summary>
    /// 构造编译参数：-pipe（管道代替临时文件，避免写 TEMP）+ 标准 + -O1（教学诊断友好）。
    /// </summary>
    /// <param name="language">源语言（调用前须以 <see cref="Supports"/> 预检）。</param>
    /// <param name="sourcePath">源文件绝对路径。</param>
    /// <param name="outputPath">产物 exe 绝对路径。</param>
    /// <returns>g++ 参数串（不含程序名）。</returns>
    public string BuildArguments(RunnerLanguage language, string sourcePath, string outputPath) =>
        $"-pipe {StandardFlag(language)} -O1 -o \"{outputPath}\" \"{sourcePath}\"";

    /// <summary>
    /// 探测 g++ 并验证可用（--version 成功执行才返回实例）。
    /// </summary>
    /// <returns>可用编译链；未安装返回 null（调用方按环境缺失处理，不抛异常）。</returns>
    public static GppToolchain? Discover()
    {
        foreach (var candidate in CandidatePaths())
        {
            if (!File.Exists(candidate))
            {
                continue;
            }

            var version = TryQueryVersion(candidate);
            if (version is not null)
            {
                return new GppToolchain(candidate, version, ParseMajorVersion(version));
            }
        }

        return null;
    }

    private static IEnumerable<string> CandidatePaths()
    {
        var explicitPath = Environment.GetEnvironmentVariable(CompilerPathEnvironmentVariable);
        if (!string.IsNullOrWhiteSpace(explicitPath))
        {
            yield return explicitPath;
        }

        // 官方指定的 Dev-Cpp（TDM-GCC）安装路径（教学环境标配）
        yield return DevCppCompilerPath;

        foreach (var directory in (Environment.GetEnvironmentVariable("PATH") ?? string.Empty)
                     .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            yield return Path.Combine(directory, "g++.exe");
        }

        // WinGet 用户级 WinLibs（备选；注意 Smart App Control 开启时新构建的
        // cc1/cc1plus 后端会被静默拦截，仅作为 PATH 之外的兜底探测位）
        var packageRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Microsoft", "WinGet", "Packages");
        if (Directory.Exists(packageRoot))
        {
            foreach (var package in Directory.EnumerateDirectories(packageRoot, "*WinLibs*"))
            {
                yield return Path.Combine(package, "mingw64", "bin", "g++.exe");
            }
        }
    }

    private static int ParseMajorVersion(string versionLine)
    {
        // 形如 "g++.exe (tdm64-1) 4.9.2"：取最后一个 数字.数字 段的主版本
        var tail = versionLine.AsSpan();
        var lastSpace = tail.LastIndexOf(' ');
        if (lastSpace >= 0)
        {
            tail = tail[(lastSpace + 1)..];
        }

        var dot = tail.IndexOf('.');
        var majorSpan = dot < 0 ? tail : tail[..dot];
        return int.TryParse(majorSpan, out var major) ? major : 0;
    }

    private static string? TryQueryVersion(string compilerPath)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = compilerPath,
                Arguments = "--version",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true,
            });
            if (process is null)
            {
                return null;
            }

            var firstLine = process.StandardOutput.ReadLine();
            process.WaitForExit(5_000);
            return string.IsNullOrWhiteSpace(firstLine) ? null : firstLine.Trim();
        }
        catch (Exception)
        {
            return null;
        }
    }
}
