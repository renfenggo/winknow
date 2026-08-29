using Winknow.Security;

namespace Winknow.RecoveryTool;

/// <summary>
/// RecoveryTool 恢复工具入口。
/// 运行身份：管理员（或在 PE 环境下运行）。
///
/// 核心职责（见《V7.0 组件架构设计》第 3.6 节）：
/// 1. 离线授权（维护模式密码 + TOTP 二次验证）
/// 2. 维护模式（临时停止服务 + 倒计时 + 自动恢复）
/// 3. 紧急恢复（策略损坏恢复 + 服务配置重置 + 日志 Hash Chain 恢复）
///
/// 第 5 周骨架：仅实现服务保护与 SafeBoot 注册的命令行入口，
/// 为安装期/恢复期提供可调用的硬化工具。维护模式与紧急恢复在第 6/10 周补全。
///
/// 禁止：
/// - 不能在学生用户下运行
/// - 不持有管理员密码明文
/// </summary>
internal static class Program
{
    // 服务名常量：与 ControlService/GuardService 注册到 SCM 的 ServiceName 保持一致
    private const string ControlServiceName = "Winknow Control Service";
    private const string GuardServiceName = "Winknow Guard Service";

    private static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            PrintHelp();
            return 0;
        }

        try
        {
            return args[0].ToLowerInvariant() switch
            {
                "protect" => RunProtect(args),
                "unprotect" => RunUnprotect(args),
                "status" => RunStatus(args),
                "help" or "-h" or "--help" => PrintHelp(),
                _ => UnknownCommand(args[0])
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[FATAL] {ex.Message}");
            return 99;
        }
    }

    /// <summary>
    /// protect [service]：对核心服务应用 DACL + 失败恢复 + SafeBoot 注册。
    /// 不传 service 则对 Control 和 Guard 两个核心服务全部硬化。
    /// </summary>
    private static int RunProtect(string[] args)
    {
        if (!ServiceSecurity.IsRunningAsAdministrator())
        {
            Console.Error.WriteLine("[ERROR] 需要管理员权限运行。请以管理员身份启动 RecoveryTool。");
            return 1;
        }

        var targets = ResolveTargets(args);
        var failed = 0;

        foreach (var name in targets)
        {
            Console.WriteLine($"==> 硬化服务: {name}");

            var dacl = ServiceSecurity.ApplyServiceProtection(name);
            Console.WriteLine($"  服务 DACL        : {(dacl.IsSuccess ? "OK" : "FAIL " + dacl.ErrorMessage)}");
            if (!dacl.IsSuccess) { failed++; continue; }

            var recovery = ServiceRecovery.ApplyServiceRecovery(name);
            Console.WriteLine($"  SCM 失败恢复     : {(recovery.IsSuccess ? "OK" : "FAIL " + recovery.ErrorMessage)}");
            if (!recovery.IsSuccess) { failed++; continue; }

            var safeBoot = SafeBootRegistrar.Register(name, "Winknow 核心管控服务", null);
            Console.WriteLine($"  SafeBoot 注册    : {(safeBoot.IsSuccess ? "OK" : "FAIL " + safeBoot.ErrorMessage)}");
            if (!safeBoot.IsSuccess) { failed++; }
        }

        Console.WriteLine(failed == 0 ? "全部硬化完成。" : $"完成，但有 {failed} 项失败，请检查日志。");
        return failed == 0 ? 0 : 2;
    }

    /// <summary>
    /// unprotect [service]：移除 SafeBoot 注册（卸载/维护前调用）。
    /// </summary>
    private static int RunUnprotect(string[] args)
    {
        if (!ServiceSecurity.IsRunningAsAdministrator())
        {
            Console.Error.WriteLine("[ERROR] 需要管理员权限运行。");
            return 1;
        }

        var targets = ResolveTargets(args);
        var failed = 0;
        foreach (var name in targets)
        {
            var ret = SafeBootRegistrar.Unregister(name);
            Console.WriteLine($"移除 SafeBoot 注册 {name}: {(ret.IsSuccess ? "OK" : "FAIL " + ret.ErrorMessage)}");
            if (!ret.IsSuccess) { failed++; }
        }
        return failed == 0 ? 0 : 2;
    }

    /// <summary>
    /// status [service]：检查 SafeBoot 注册状态。
    /// </summary>
    private static int RunStatus(string[] args)
    {
        var targets = ResolveTargets(args);
        foreach (var name in targets)
        {
            var registered = SafeBootRegistrar.IsRegistered(name);
            Console.WriteLine($"{name,-32} SafeBoot: {(registered ? "已注册 (Minimal+Network)" : "未注册")}");
        }
        return 0;
    }

    private static List<string> ResolveTargets(string[] args)
    {
        // 跳过子命令名，其余非选项参数视为显式服务名
        var explicitNames = args.Skip(1).Where(a => !a.StartsWith("-")).ToList();
        return explicitNames.Count > 0 ? explicitNames : new List<string> { ControlServiceName, GuardServiceName };
    }

    private static int PrintHelp()
    {
        Console.WriteLine("Winknow RecoveryTool V7.0 (基础版骨架)");
        Console.WriteLine("用途：安装/恢复阶段对核心服务应用保护并注册安全模式。");
        Console.WriteLine();
        Console.WriteLine("用法:");
        Console.WriteLine("  RecoveryTool protect [service ...]   应用 DACL + 失败恢复 + SafeBoot 注册");
        Console.WriteLine("  RecoveryTool unprotect [service ...] 移除 SafeBoot 注册");
        Console.WriteLine("  RecoveryTool status [service ...]    查看 SafeBoot 注册状态");
        Console.WriteLine("  RecoveryTool help                     显示本帮助");
        Console.WriteLine();
        Console.WriteLine("不带 service 名时，默认对以下核心服务操作：");
        Console.WriteLine($"  - {ControlServiceName}");
        Console.WriteLine($"  - {GuardServiceName}");
        Console.WriteLine();
        Console.WriteLine("未实现（后续周次）：");
        Console.WriteLine("  TODO 第 6 周：maintain  维护模式密码 + TOTP 验证 + 倒计时");
        Console.WriteLine("  TODO 第 10 周：recover   策略/服务/日志紧急恢复");
        return 0;
    }

    private static int UnknownCommand(string cmd)
    {
        Console.Error.WriteLine($"[ERROR] 未知命令: {cmd}");
        Console.Error.WriteLine("运行 'RecoveryTool help' 查看可用命令。");
        return 1;
    }
}
