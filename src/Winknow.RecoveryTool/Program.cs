using System.Diagnostics;
using System.ServiceProcess;
using System.Text.Json;
using Winknow.Core;
using Winknow.Logging;
using Winknow.Security;

namespace Winknow.RecoveryTool;

/// <summary>
/// RecoveryTool 恢复工具入口。
/// 运行身份：管理员（或在 PE 环境下运行）。
///
/// 核心职责（见《V7.0 组件架构设计》第 3.6 节）：
/// 1. 维护模式：临时停止服务 + 倒计时 + 自动恢复（maintain 命令）
/// 2. 离线授权：维护密码 + TOTP + 一次性恢复码
/// 3. 授权卸载：清理服务、策略、文件和日志（uninstall 命令）
/// 4. 紧急恢复：策略/服务/日志恢复（第 10 周实现）
///
/// 禁止：
/// - 不能在学生用户下运行
/// - 不持有管理员密码明文（仅存 Argon2id 哈希）
/// </summary>
internal static class Program
{
    private static readonly string ConfigDir = ProductPaths.MaintainDir;
    private static readonly string ConfigPath = Path.Combine(ConfigDir, "maintain.json");
    private static readonly string RecoveryPath = Path.Combine(ConfigDir, "recovery-codes.json");
    private static readonly string AuditDbPath = Path.Combine(ConfigDir, "audit.db");

    private static readonly string[] ManagedServices = ServiceNames.Managed;

    private static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            return PrintHelp();
        }

        try
        {
            return args[0].ToLowerInvariant() switch
            {
                "maintain" => RunMaintain(args[1..]),
                "uninstall" => RunUninstall(args[1..]),
                "status" => RunMaintainStatus(),
                "help" or "--help" or "-h" => PrintHelp(),
                _ => UnknownCommand(args[0])
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ERROR] {ex.Message}");
            return 99;
        }
    }

    private static int RunMaintain(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("用法: maintain <init|enter|status> [选项]");
            return 1;
        }

        return args[0].ToLowerInvariant() switch
        {
            "init" => RunMaintainInit(),
            "enter" => RunMaintainEnter(args[1..]),
            "status" => RunMaintainStatus(),
            _ => UnknownCommand($"maintain {args[0]}")
        };
    }

    /// <summary>
    /// 首次初始化：设置维护密码 + 生成 TOTP 密钥 + 生成恢复码。
    /// </summary>
    private static int RunMaintainInit()
    {
        Directory.CreateDirectory(ConfigDir);

        Console.Write("请输入维护密码: ");
        var password = ReadPassword();
        Console.Write("请再次输入维护密码: ");
        var password2 = ReadPassword();
        if (password != password2)
        {
            Console.Error.WriteLine("[ERROR] 两次输入不一致");
            return 1;
        }
        if (string.IsNullOrWhiteSpace(password) || password.Length < 8)
        {
            Console.Error.WriteLine("[ERROR] 维护密码至少 8 位");
            return 1;
        }

        var passwordHash = MaintenancePassword.Hash(password);
        var totpSecret = SecurityUtils.GenerateRandomBytes(20);
        var totpBase32 = Base32Encode(totpSecret);

        var config = new MaintainConfig
        {
            PasswordHash = passwordHash,
            TotpSecretBase32 = totpBase32
        };
        SaveConfig(config);

        var recoveryStore = new RecoveryCodeStore(RecoveryPath);
        var codes = recoveryStore.GenerateCodes(10);

        Console.WriteLine();
        Console.WriteLine("=== 初始化完成（请妥善保存以下信息，仅显示一次）===");
        Console.WriteLine($"TOTP 密钥（录入 Authenticator）: {totpBase32}");
        Console.WriteLine("otpauth://totp/Winknow:maintain?secret=" + totpBase32 + "&issuer=Winknow");
        Console.WriteLine();
        Console.WriteLine("一次性恢复码（每个仅可用一次）:");
        foreach (var c in codes)
        {
            Console.WriteLine($"  {c}");
        }
        Console.WriteLine();
        Console.WriteLine($"配置已保存: {ConfigPath}");
        Console.WriteLine($"审计数据库: {AuditDbPath}");
        return 0;
    }

    /// <summary>
    /// 进入维护模式：密码+TOTP 或恢复码验证，启动倒计时。
    /// </summary>
    private static int RunMaintainEnter(string[] args)
    {
        var config = LoadConfig();
        if (config is null)
        {
            Console.Error.WriteLine($"[ERROR] 未初始化维护配置，请先运行: maintain init");
            return 1;
        }

        var password = GetOption(args, "--password");
        var totp = GetOption(args, "--totp");
        var recoveryCode = GetOption(args, "--recovery-code");
        var reason = GetOption(args, "--reason") ?? "manual";
        var timeoutStr = GetOption(args, "--timeout");
        var timeoutMinutes = int.TryParse(timeoutStr, out var t) && t > 0 ? t : 15;

        var totpSecret = TotpGenerator.Base32Decode(config.TotpSecretBase32);
        var audit = new MaintenanceAuditLog(AuditDbPath);
        var recoveryStore = new RecoveryCodeStore(RecoveryPath);

        using var session = new MaintenanceSession(new MaintenanceSessionOptions
        {
            PasswordHash = config.PasswordHash,
            TotpSecret = totpSecret,
            RecoveryCodes = recoveryStore,
            DefaultTimeoutMinutes = timeoutMinutes,
            OnEnter = StopManagedServices,
            OnExit = _ => StartManagedServices(),
            OnAudit = (actor, op, rsn, detail) => audit.RecordEntry(actor, op, rsn, detail)
        });

        var result = recoveryCode is not null
            ? session.EnterWithRecoveryCode(recoveryCode, Environment.UserName, reason)
            : session.Enter(password ?? string.Empty, totp ?? string.Empty, Environment.UserName, reason);

        if (!result.IsSuccess)
        {
            Console.Error.WriteLine($"[ERROR] {result.ErrorMessage}");
            return (int)result.ErrorCode / 1000;
        }

        Console.WriteLine($"已进入维护模式，超时 {timeoutMinutes} 分钟后自动恢复");
        Console.WriteLine("输入 exit 退出维护模式");

        // 后台线程读 exit
        var inputThread = new Thread(() =>
        {
            while (session.IsActive)
            {
                var line = Console.ReadLine();
                if (line is null) break;
                if (line.Trim().Equals("exit", StringComparison.OrdinalIgnoreCase))
                {
                    session.Exit(Environment.UserName, "user-exit");
                    break;
                }
            }
        })
        { IsBackground = true };
        inputThread.Start();

        // 主线程显示倒计时，直到会话结束（超时或 exit）
        while (session.IsActive)
        {
            var remaining = session.ExpiresAt - DateTimeOffset.UtcNow;
            if (remaining < TimeSpan.Zero) remaining = TimeSpan.Zero;
            Console.Write($"\r剩余维护时间: {remaining:hh\\:mm\\:ss}  ");
            Thread.Sleep(1000);
        }
        Console.WriteLine("\n维护模式已结束，服务保护已恢复");

        return 0;
    }

    private static int RunMaintainStatus()
    {
        if (!File.Exists(AuditDbPath))
        {
            Console.WriteLine("无维护审计记录");
            return 0;
        }

        var audit = new MaintenanceAuditLog(AuditDbPath);
        var entries = audit.QueryRecent(20);
        if (entries.Count == 0)
        {
            Console.WriteLine("无维护审计记录");
            return 0;
        }

        Console.WriteLine($"最近 {entries.Count} 条维护审计:");
        Console.WriteLine(new string('-', 80));
        foreach (var e in entries)
        {
            Console.WriteLine($"#{e.Id} [{e.Timestamp}] {e.Actor} {e.Operation}" +
                (e.Reason is null ? "" : $" reason={e.Reason}") +
                (e.Detail is null ? "" : $" detail={e.Detail}"));
        }
        return 0;
    }

    /// <summary>
    /// 授权卸载：停止并删除服务、策略、文件和日志。
    /// </summary>
    private static int RunUninstall(string[] args)
    {
        var autoYes = args.Any(a => a is "--yes" or "-y");
        if (!autoYes)
        {
            Console.Write("将停止并删除 Winknow 服务、策略、配置与日志，不可逆。确认？(yes/no): ");
            var confirm = Console.ReadLine();
            if (confirm?.Trim() != "yes")
            {
                Console.WriteLine("已取消");
                return 1;
            }
        }

        var audit = new MaintenanceAuditLog(AuditDbPath);
        var actor = Environment.UserName;

        // 1. 停止并删除服务
        foreach (var svc in ManagedServices)
        {
            try
            {
                using var sc = new ServiceController(svc);
                Console.Write($"停止服务 {svc}...");
                if (sc.Status == ServiceControllerStatus.Running)
                {
                    sc.Stop();
                    sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                }
                Console.WriteLine("已停止");
            }
            catch (InvalidOperationException)
            {
                Console.WriteLine($"服务 {svc} 不存在，跳过");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"停止服务 {svc} 失败: {ex.Message}");
            }

            // 删除服务（ServiceController 无 Delete，用 sc.exe）
            try
            {
                var psi = new ProcessStartInfo("sc.exe", $"delete \"{svc}\"")
                {
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    UseShellExecute = false
                };
                var p = Process.Start(psi);
                if (p is not null)
                {
                    p.WaitForExit(15000);
                    Console.WriteLine($"已删除服务: {svc}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"删除服务 {svc} 失败: {ex.Message}");
            }
        }

        // 2. 删除配置与日志目录
        try
        {
            if (Directory.Exists(ConfigDir))
            {
                Directory.Delete(ConfigDir, true);
                Console.WriteLine($"已删除配置/日志: {ConfigDir}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"删除配置目录失败: {ex.Message}");
        }

        // 3. 删除策略目录（如存在，ADR-001/TD-02 生效策略位置）
        var policyDir = ProductPaths.PoliciesDir;
        try
        {
            if (Directory.Exists(policyDir))
            {
                Directory.Delete(policyDir, true);
                Console.WriteLine($"已删除策略: {policyDir}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"删除策略目录失败: {ex.Message}");
        }

        audit.RecordEntry(actor, "uninstall", "authorized", "completed");
        Console.WriteLine("授权卸载完成");
        return 0;
    }

    private static void StopManagedServices()
    {
        foreach (var svc in ManagedServices)
        {
            try
            {
                using var sc = new ServiceController(svc);
                if (sc.Status == ServiceControllerStatus.Running)
                {
                    sc.Stop();
                    sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                    Console.WriteLine($"[维护] 已停止 {svc}");
                }
            }
            catch (InvalidOperationException)
            {
                // 服务未安装，忽略
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[维护] 停止 {svc} 失败: {ex.Message}");
            }
        }
    }

    private static void StartManagedServices()
    {
        foreach (var svc in ManagedServices)
        {
            try
            {
                using var sc = new ServiceController(svc);
                if (sc.Status == ServiceControllerStatus.Stopped)
                {
                    sc.Start();
                    Console.WriteLine($"[恢复] 已启动 {svc}");
                }
            }
            catch (InvalidOperationException)
            {
                // 服务未安装，忽略
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[恢复] 启动 {svc} 失败: {ex.Message}");
            }
        }
    }

    private static MaintainConfig? LoadConfig()
    {
        if (!File.Exists(ConfigPath)) return null;
        var json = File.ReadAllText(ConfigPath);
        return JsonSerializer.Deserialize<MaintainConfig>(json);
    }

    private static void SaveConfig(MaintainConfig config)
    {
        Directory.CreateDirectory(ConfigDir);
        var json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(ConfigPath, json);
    }

    private static string? GetOption(string[] args, string name)
    {
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (args[i].Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return args[i + 1];
            }
        }
        return null;
    }

    private static string ReadPassword()
    {
        var sb = new System.Text.StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter) break;
            if (key.Key == ConsoleKey.Backspace)
            {
                if (sb.Length > 0) sb.Remove(sb.Length - 1, 1);
                continue;
            }
            sb.Append(key.KeyChar);
            Console.Write('*');
        }
        Console.WriteLine();
        return sb.ToString();
    }

    private static string Base32Encode(byte[] data)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var sb = new System.Text.StringBuilder((data.Length * 8 + 4) / 5);
        var buffer = 0;
        var bitsLeft = 0;
        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bitsLeft += 8;
            while (bitsLeft >= 5)
            {
                bitsLeft -= 5;
                sb.Append(alphabet[(buffer >> bitsLeft) & 0x1f]);
            }
        }
        if (bitsLeft > 0)
        {
            sb.Append(alphabet[(buffer << (5 - bitsLeft)) & 0x1f]);
        }
        return sb.ToString();
    }

    private static int PrintHelp()
    {
        Console.WriteLine("""
            Winknow RecoveryTool V7.0
            用法: RecoveryTool <command> [options]

            命令:
              maintain init                 首次初始化维护密码 + TOTP + 恢复码
              maintain enter [options]      进入维护模式
                --password <pwd>            维护密码
                --totp <code>               6 位 TOTP
                --recovery-code <code>      恢复码（紧急通道，二选一）
                --reason <text>             维护原因
                --timeout <minutes>         超时分钟（默认 15）
              status                        查看维护状态与审计记录
              uninstall [--yes]             授权卸载（停删服务+策略+日志）
              help                          显示本帮助

            运行身份：管理员
            """);
        return 0;
    }

    private static int UnknownCommand(string cmd)
    {
        Console.Error.WriteLine($"[ERROR] 未知命令: {cmd}");
        Console.Error.WriteLine("运行 'RecoveryTool help' 查看用法");
        return 1;
    }
}

internal sealed class MaintainConfig
{
    public string PasswordHash { get; set; } = string.Empty;
    public string TotpSecretBase32 { get; set; } = string.Empty;
}
