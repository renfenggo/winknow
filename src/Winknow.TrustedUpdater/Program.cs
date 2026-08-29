using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;
using Winknow.Core.Results;

namespace Winknow.TrustedUpdater;

/// <summary>
/// TrustedUpdater 入口。
/// 运行身份：管理员（生产签名私钥在 HSM/Token，本工具仅持公钥验签）。
///
/// 核心职责（V7.0 第 7 周）：
/// 1. apply：验证签名+产品+Hash → 版本守卫 → 数据库迁移 → A/B 切换 → 健康检查 → 自动回滚
/// 2. rollback：手动回滚到 Previous
/// 3. status：当前版本 + 可回滚状态
/// 4. sign：开发辅助，用私钥对 manifest 签名（生产应在受控构建环境/HSM 完成）
/// </summary>
internal static class Program
{
    private static readonly string DeployRoot = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Winknow", "deploy");

    private static readonly string DataDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Winknow");
    private const string ProductId = "Winknow.V7";

    private static readonly string[] ManagedServices = ["Winknow Control Service", "Winknow Guard Service"];

    private static int Main(string[] args)
    {
        if (args.Length == 0) return PrintHelp();

        try
        {
            return args[0].ToLowerInvariant() switch
            {
                "apply" => RunApply(args[1..]),
                "rollback" => RunRollback(),
                "status" => RunStatus(),
                "sign" => RunSign(args[1..]),
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

    private static int RunApply(string[] args)
    {
        if (args.Length == 0 || args[0].StartsWith('-'))
        {
            Console.Error.WriteLine("用法: apply <package.wku> [--publickey <path>]");
            return 1;
        }

        var packagePath = args[0];
        var publicKeyPath = GetOption(args, "--publickey")
            ?? Path.Combine(DeployRoot, "publickey.pem");

        if (!File.Exists(publicKeyPath))
        {
            Console.Error.WriteLine($"[ERROR] 公钥不存在: {publicKeyPath}（用 --publickey 指定）");
            return 1;
        }

        var orchestrator = new UpdateOrchestrator(new UpdateOptions
        {
            DeployRoot = DeployRoot,
            ExpectedProductId = ProductId,
            PublicKey = LoadPublicKey(publicKeyPath),
            AuditDbPath = null,   // 第 9 周接入日志迁移
            SnapshotDir = null,
            StopServices = StopManagedServices,
            StartServices = StartManagedServices,
            MigrateDatabase = null,
            CheckServiceHealth = CheckServiceHealth,
            CheckAgentHealth = () => Result.Success(),   // 第 2 周接入
            CheckPolicyHealth = () => Result.Success()   // 第 4 周接入
        });

        Console.WriteLine($"应用更新包: {packagePath}");

        // 更新模式标志：阻止 GuardService 在 Stop→切换→Start 窗口内拉起服务（防交叉拉起）
        if (!UpdateModeFlag.TryEnter(DataDir))
        {
            Console.Error.WriteLine("[ERROR] 已有更新正在进行，拒绝并发更新");
            return 1;
        }
        try
        {
            var r = orchestrator.Apply(packagePath);
            if (r.IsSuccess)
            {
                Console.WriteLine("更新成功");
                return 0;
            }
            Console.Error.WriteLine($"[ERROR] {r.ErrorMessage}");
            return 1;
        }
        finally
        {
            UpdateModeFlag.Exit(DataDir);
        }
    }

    private static int RunRollback()
    {
        var orchestrator = new UpdateOrchestrator(new UpdateOptions
        {
            DeployRoot = DeployRoot,
            ExpectedProductId = ProductId,
            PublicKey = RSA.Create(), // 回滚不需验签，占位
            StopServices = StopManagedServices,
            StartServices = StartManagedServices
        });

        if (!UpdateModeFlag.TryEnter(DataDir))
        {
            Console.Error.WriteLine("[ERROR] 已有更新正在进行，拒绝并发回滚");
            return 1;
        }
        try
        {
            var r = orchestrator.Rollback();
            if (r.IsSuccess)
            {
                Console.WriteLine("回滚完成");
                return 0;
            }
            Console.Error.WriteLine($"[ERROR] {r.ErrorMessage}");
            return 1;
        }
        finally
        {
            UpdateModeFlag.Exit(DataDir);
        }
    }

    private static int RunStatus()
    {
        var orchestrator = new UpdateOrchestrator(new UpdateOptions
        {
            DeployRoot = DeployRoot,
            ExpectedProductId = ProductId,
            PublicKey = RSA.Create()
        });
        var status = orchestrator.GetStatus();
        Console.WriteLine($"当前版本: {status.CurrentVersion ?? "（未安装）"}");
        Console.WriteLine($"可回滚: {(status.CanRollback ? "是" : "否")}");
        return 0;
    }

    /// <summary>
    /// 开发辅助：用私钥对 manifest.json 签名（生产应在受控构建/HSM 完成）。
    /// </summary>
    private static int RunSign(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("用法: sign <manifestDir> <privateKey.pem>");
            return 1;
        }

        var manifestDir = args[0];
        var privateKeyPath = args[1];
        var manifestPath = Path.Combine(manifestDir, "manifest.json");

        if (!File.Exists(manifestPath)) { Console.Error.WriteLine($"[ERROR] {manifestPath} 不存在"); return 1; }
        if (!File.Exists(privateKeyPath)) { Console.Error.WriteLine($"[ERROR] {privateKeyPath} 不存在"); return 1; }

        var manifest = UpdateManifest.Parse(File.ReadAllText(manifestPath));
        var rsa = RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(privateKeyPath));

        var data = Encoding.UTF8.GetBytes(manifest.ToSignableJson());
        var signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        manifest.Signature = Convert.ToBase64String(signature);

        File.WriteAllText(manifestPath, JsonSerializer.Serialize(manifest,
            new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"已签名: {manifestPath}");
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
                    Console.WriteLine($"[更新] 已停止 {svc}");
                }
            }
            catch (InvalidOperationException) { /* 服务未安装 */ }
            catch (Exception ex) { Console.WriteLine($"[更新] 停止 {svc} 失败: {ex.Message}"); }
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
                    Console.WriteLine($"[更新] 已启动 {svc}");
                }
            }
            catch (InvalidOperationException) { /* 服务未安装 */ }
            catch (Exception ex) { Console.WriteLine($"[更新] 启动 {svc} 失败: {ex.Message}"); }
        }
    }

    private static Result CheckServiceHealth()
    {
        foreach (var svc in ManagedServices)
        {
            try
            {
                using var sc = new ServiceController(svc);
                if (sc.Status != ServiceControllerStatus.Running)
                {
                    return Result.Failure(ErrorCode.ExternalError, $"{svc} 未运行（{sc.Status}）");
                }
            }
            catch (InvalidOperationException)
            {
                return Result.Failure(ErrorCode.PathNotFound, $"{svc} 未安装");
            }
        }
        return Result.Success();
    }

    private static RSA LoadPublicKey(string path)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(path));
        return rsa;
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

    private static int PrintHelp()
    {
        Console.WriteLine("""
            Winknow TrustedUpdater V7.0
            用法: TrustedUpdater <command> [options]

            命令:
              apply <package.wku> [--publickey <path>]   应用更新（验签+切换+健康检查+自动回滚）
              rollback                                   手动回滚到 Previous
              status                                     当前版本与可回滚状态
              sign <manifestDir> <privateKey.pem>        开发辅助：签名 manifest（生产在 HSM）
              help                                       显示本帮助

            运行身份：管理员
            生产签名私钥必须在 HSM/Token，本工具仅持公钥验签
            """);
        return 0;
    }

    private static int UnknownCommand(string cmd)
    {
        Console.Error.WriteLine($"[ERROR] 未知命令: {cmd}");
        Console.Error.WriteLine("运行 'TrustedUpdater help' 查看用法");
        return 1;
    }
}
