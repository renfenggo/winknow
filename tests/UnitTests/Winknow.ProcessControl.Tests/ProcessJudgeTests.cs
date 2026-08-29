using Winknow.Core.Results;
using Winknow.Policy;
using Winknow.ProcessControl;

namespace Winknow.ProcessControl.Tests;

/// <summary>
/// 综合判断引擎测试（白名单从策略文件加载，验证统一源）。
/// </summary>
public class ProcessJudgeTests
{
    private readonly ProcessJudge _judge;

    public ProcessJudgeTests()
    {
        var policy = CreateTestPolicy();
        _judge = new ProcessJudge(
            WhitelistRuleSet.FromPolicy(policy),
            highRiskInterpreters: policy.SoftwareControl.HighRiskInterpreters.Blocked);
    }

    [Fact(DisplayName = "系统关键进程直接放行")]
    public void Judge_SystemCritical_Allowed()
    {
        var info = new ProcessInfo
        {
            ProcessId = 4,
            ProcessName = "System",
            FilePath = string.Empty
        };

        var result = _judge.Judge(info);
        Assert.True(result.IsSuccess);
    }

    [Fact(DisplayName = "svchost 放行")]
    public void Judge_Svchost_Allowed()
    {
        var info = new ProcessInfo
        {
            ProcessId = 1000,
            ProcessName = "svchost",
            FilePath = @"C:\Windows\System32\svchost.exe"
        };

        var result = _judge.Judge(info);
        Assert.True(result.IsSuccess);
    }

    [Fact(DisplayName = "白名单路径放行")]
    public void Judge_WhitelistPath_Allowed()
    {
        var info = new ProcessInfo
        {
            ProcessId = 2000,
            ProcessName = "notepad",
            FilePath = @"C:\Windows\System32\notepad.exe"
        };

        var result = _judge.Judge(info);
        Assert.True(result.IsSuccess);
    }

    [Fact(DisplayName = "非白名单路径阻止")]
    public void Judge_UnknownPath_Blocked()
    {
        var info = new ProcessInfo
        {
            ProcessId = 3000,
            ProcessName = "game",
            FilePath = @"D:\Games\game.exe"
        };

        var result = _judge.Judge(info);
        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.ProcessBlocked, result.ErrorCode);
    }

    [Fact(DisplayName = "下载目录程序阻止")]
    public void Judge_DownloadsPath_Blocked()
    {
        var info = new ProcessInfo
        {
            ProcessId = 4000,
            ProcessName = "crack",
            FilePath = @"C:\Users\student\Downloads\crack.exe"
        };

        var result = _judge.Judge(info);
        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.ProcessBlocked, result.ErrorCode);
    }

    [Fact(DisplayName = "高风险解释器阻止（含危险命令行）")]
    public void Judge_DangerousCommandLine_Blocked()
    {
        var info = new ProcessInfo
        {
            ProcessId = 5000,
            ProcessName = "powershell.exe",
            FilePath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            CommandLine = "powershell -EncodedCommand SGVsbG8="
        };

        var result = _judge.Judge(info);
        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.ProcessBlocked, result.ErrorCode);
    }

    [Fact(DisplayName = "Winknow 自身组件放行")]
    public void Judge_WinknowComponent_Allowed()
    {
        var info = new ProcessInfo
        {
            ProcessId = 6000,
            ProcessName = "Winknow.ControlService",
            FilePath = @"C:\Program Files\Winknow\Winknow.ControlService.exe"
        };

        var result = _judge.Judge(info);
        Assert.True(result.IsSuccess);
    }

    [Fact(DisplayName = "学生编译产物放行（从策略 StudentOutput 加载）")]
    public void Judge_StudentBuild_Allowed()
    {
        var info = new ProcessInfo
        {
            ProcessId = 7000,
            ProcessName = "MyApp",
            FilePath = @"C:\Users\student\source\repos\MyApp\bin\Debug\MyApp.exe"
        };

        var result = _judge.Judge(info);
        Assert.True(result.IsSuccess);
    }

    [Fact(DisplayName = "Hash 不匹配阻止")]
    public void Judge_HashMismatch_Blocked()
    {
        var whitelist = new WhitelistRuleSet
        {
            PathRules = new List<WhitelistRule>
            {
                new()
                {
                    PathPattern = @"C:\Tools\*.exe",
                    ExpectedHash = "aaaabbbbcccc"
                }
            }
        };
        var judge = new ProcessJudge(whitelist);

        var info = new ProcessInfo
        {
            ProcessId = 8000,
            ProcessName = "tool",
            FilePath = @"C:\Tools\tool.exe",
            FileHash = "dddd0000"
        };

        var result = judge.Judge(info);
        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.ProcessBlocked, result.ErrorCode);
    }

    [Fact(DisplayName = "签名不匹配阻止")]
    public void Judge_SignatureMismatch_Blocked()
    {
        var whitelist = new WhitelistRuleSet
        {
            PathRules = new List<WhitelistRule>
            {
                new()
                {
                    PathPattern = @"C:\Apps\*.exe",
                    RequiredSigner = "Microsoft"
                }
            }
        };
        var judge = new ProcessJudge(whitelist);

        var info = new ProcessInfo
        {
            ProcessId = 9000,
            ProcessName = "app",
            FilePath = @"C:\Apps\app.exe",
            SignatureSubject = "Unknown Publisher"
        };

        var result = judge.Judge(info);
        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.ProcessBlocked, result.ErrorCode);
    }

    /// <summary>构造测试用策略文件（内存，含课堂软件与高风险黑名单）。</summary>
    private static PolicyFile CreateTestPolicy()
    {
        return new PolicyFile
        {
            Version = "7.0.0",
            PolicyId = "test-judge",
            SoftwareControl = new SoftwareControlSection
            {
                Whitelist = new SoftwareWhitelist
                {
                    ByPath = new List<PathRule>
                    {
                        new() { Path = @"C:\Users\*\AppData\Local\Programs\Microsoft VS Code\*", Description = "VS Code" },
                        new() { Path = @"C:\Program Files\Dev-Cpp\*", Description = "Dev-C++" }
                    }
                },
                StudentOutput = new StudentOutputSection
                {
                    AllowedDirectories = new List<string> { @"C:\Users\*\source\repos\**" }
                },
                HighRiskInterpreters = new HighRiskInterpretersSection
                {
                    Blocked = new List<string>
                    {
                        "powershell.exe", "wscript.exe", "cscript.exe",
                        "mshta.exe", "regedit.exe", "mmc.exe"
                    }
                }
            }
        };
    }
}
