using Winknow.Core.Results;
using Winknow.ProcessControl;

namespace Winknow.ProcessControl.Tests;

/// <summary>
/// 综合判断引擎测试。
/// </summary>
public class ProcessJudgeTests
{
    private readonly ProcessJudge _judge = new(WhitelistRuleSet.CreateDefault());

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

    [Fact(DisplayName = "危险命令行阻止")]
    public void Judge_DangerousCommandLine_Blocked()
    {
        var info = new ProcessInfo
        {
            ProcessId = 5000,
            ProcessName = "powershell",
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

    [Fact(DisplayName = "学生编译产物放行")]
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
}
