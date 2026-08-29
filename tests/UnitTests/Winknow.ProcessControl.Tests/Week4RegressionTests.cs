using Winknow.Core.Results;
using Winknow.ProcessControl;

namespace Winknow.ProcessControl.Tests;

/// <summary>
/// 第 4 周回归测试：白名单兼容性、子进程重检、高风险解释器、规则回滚。
/// 对应《基础版开发计划书》第 4 周验收项。
/// </summary>
public class Week4RegressionTests
{
    private readonly ProcessJudge _judge = new(WhitelistRuleSet.CreateDefault());

    // === 验收项1：Dev-C++ 完整编译调试流程正常 ===

    [Theory(DisplayName = "Dev-C++ 编译链进程放行")]
    [InlineData("devcpp.exe", @"C:\Program Files\Dev-Cpp\devcpp.exe")]
    [InlineData("gcc.exe", @"C:\Program Files\Dev-Cpp\MinGW64\bin\gcc.exe")]
    [InlineData("g++.exe", @"C:\Program Files\Dev-Cpp\MinGW64\bin\g++.exe")]
    [InlineData("gdb.exe", @"C:\Program Files\Dev-Cpp\MinGW64\bin\gdb.exe")]
    [InlineData("make.exe", @"C:\Program Files\Dev-Cpp\MinGW64\bin\make.exe")]
    public void DevCpp_Toolchain_Allowed(string name, string path)
    {
        var info = new ProcessInfo { ProcessId = 100, ProcessName = name, FilePath = path };
        var result = _judge.Judge(info);
        Assert.True(result.IsSuccess);
    }

    // === 验收项2：VS Code 常用 C++/Python 流程正常 ===

    [Theory(DisplayName = "VS Code 主程序及子组件放行")]
    [InlineData("Code.exe", @"C:\Users\student\AppData\Local\Programs\Microsoft VS Code\Code.exe")]
    [InlineData("Code.exe", @"C:\Users\student\AppData\Local\Programs\Microsoft VS Code\resources\app\extensions\cpptools\bin\cpptools.exe")]
    public void VsCode_ProcessChain_Allowed(string name, string path)
    {
        var info = new ProcessInfo { ProcessId = 200, ProcessName = name, FilePath = path };
        var result = _judge.Judge(info);
        Assert.True(result.IsSuccess);
    }

    // === 验收项3：学生生成程序只能在受控目录运行 ===

    [Fact(DisplayName = "学生编译产物在受控目录放行")]
    public void StudentBuild_InAllowedDir_Allowed()
    {
        var info = new ProcessInfo
        {
            ProcessId = 300,
            ProcessName = "MyApp",
            FilePath = @"C:\Users\student\source\repos\MyApp\bin\Debug\MyApp.exe"
        };
        var result = _judge.Judge(info);
        Assert.True(result.IsSuccess);
    }

    [Theory(DisplayName = "学生程序在非受控目录阻止")]
    [InlineData(@"C:\Users\student\Downloads\MyApp.exe")]
    [InlineData(@"C:\Users\student\Desktop\MyApp.exe")]
    [InlineData(@"D:\Games\MyApp.exe")]
    public void StudentProgram_OutsideAllowedDir_Blocked(string path)
    {
        var info = new ProcessInfo { ProcessId = 310, ProcessName = "MyApp", FilePath = path };
        var result = _judge.Judge(info);
        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.ProcessBlocked, result.ErrorCode);
    }

    // === 验收项4：Code.exe 启动未授权子进程时仍会重新检查 ===

    [Fact(DisplayName = "子进程不继承父进程白名单状态（每次独立判断）")]
    public void ChildProcess_Restricted_EvenIfParentWhitelisted()
    {
        // 父进程 Code.exe 在白名单
        var parent = new ProcessInfo
        {
            ProcessId = 4000,
            ProcessName = "Code.exe",
            FilePath = @"C:\Users\student\AppData\Local\Programs\Microsoft VS Code\Code.exe"
        };
        var parentResult = _judge.Judge(parent);
        Assert.True(parentResult.IsSuccess);

        // 子进程未授权，即使父进程在白名单也阻止（不继承允许状态）
        var child = new ProcessInfo
        {
            ProcessId = 4001,
            ParentProcessId = 4000,
            ProcessName = "malware.exe",
            FilePath = @"C:\Users\student\Downloads\malware.exe"
        };
        var childResult = _judge.Judge(child);
        Assert.False(childResult.IsSuccess);
        Assert.Equal(ErrorCode.ProcessBlocked, childResult.ErrorCode);
    }

    // === 验收项5：高风险解释器默认受限，不影响必要编译流程 ===

    [Theory(DisplayName = "高风险解释器默认阻止（即使路径在白名单）")]
    [InlineData("powershell.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")]
    [InlineData("wscript.exe", @"C:\Windows\System32\wscript.exe")]
    [InlineData("cscript.exe", @"C:\Windows\System32\cscript.exe")]
    [InlineData("mshta.exe", @"C:\Windows\System32\mshta.exe")]
    [InlineData("regedit.exe", @"C:\Windows\regedit.exe")]
    [InlineData("mmc.exe", @"C:\Windows\System32\mmc.exe")]
    public void HighRiskInterpreter_Blocked_EvenInWhitelistPath(string name, string path)
    {
        var info = new ProcessInfo
        {
            ProcessId = 5000,
            ProcessName = name,
            FilePath = path,
            CommandLine = string.Empty  // 无危险命令行，仅凭解释器身份阻止
        };
        var result = _judge.Judge(info);
        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.ProcessBlocked, result.ErrorCode);
    }

    [Fact(DisplayName = "高风险解释器策略不影响编译器")]
    public void HighRiskPolicy_DoesNotAffectCompilers()
    {
        var info = new ProcessInfo
        {
            ProcessId = 5100,
            ProcessName = "gcc.exe",
            FilePath = @"C:\Program Files\Dev-Cpp\MinGW64\bin\gcc.exe"
        };
        var result = _judge.Judge(info);
        Assert.True(result.IsSuccess);
    }

    // === 验收项6：错误白名单可以回滚 ===

    [Fact(DisplayName = "替换白名单规则集后新规则生效（回滚基础）")]
    public void WhitelistReplacement_NewRulesTakeEffect()
    {
        // 初始规则集：仅允许 C:\Allowed\*
        var initial = new WhitelistRuleSet
        {
            PathRules = new List<WhitelistRule>
            {
                new() { PathPattern = @"C:\Allowed\*", Description = "初始白名单" }
            }
        };
        var judgeInitial = new ProcessJudge(initial);

        // 回滚后规则集：仅允许 C:\Rollback\*
        var rolledBack = new WhitelistRuleSet
        {
            PathRules = new List<WhitelistRule>
            {
                new() { PathPattern = @"C:\Rollback\*", Description = "回滚后白名单" }
            }
        };
        var judgeRolled = new ProcessJudge(rolledBack);

        var target = @"C:\Rollback\app.exe";

        // 初始规则下：app.exe 被阻止（不在 C:\Allowed\*）
        var beforeInfo = new ProcessInfo { ProcessId = 6000, ProcessName = "app", FilePath = target };
        Assert.False(judgeInitial.Judge(beforeInfo).IsSuccess);

        // 回滚后规则下：同一 app.exe 放行（在 C:\Rollback\*）
        var afterInfo = new ProcessInfo { ProcessId = 6001, ProcessName = "app", FilePath = target };
        Assert.True(judgeRolled.Judge(afterInfo).IsSuccess);
    }

    [Fact(DisplayName = "自定义高风险解释器黑名单生效")]
    public void CustomHighRiskBlacklist_TakesEffect()
    {
        // 自定义黑名单：阻止 notepad.exe（仅作测试验证可配置性）
        var custom = new WhitelistRuleSet
        {
            PathRules = new List<WhitelistRule>
            {
                new() { PathPattern = @"C:\Windows\System32\*", Description = "System32" }
            }
        };
        var judge = new ProcessJudge(custom, highRiskInterpreters: new[] { "notepad.exe" });

        var info = new ProcessInfo
        {
            ProcessId = 7000,
            ProcessName = "notepad.exe",
            FilePath = @"C:\Windows\System32\notepad.exe"
        };
        var result = judge.Judge(info);
        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.ProcessBlocked, result.ErrorCode);
    }
}
