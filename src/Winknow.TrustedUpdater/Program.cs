namespace Winknow.TrustedUpdater;

/// <summary>
/// TrustedUpdater 可信更新器入口。
/// 运行身份：LocalSystem（由 ControlService 或计划任务拉起）。
///
/// 核心职责（见《V7.0 组件架构设计》第 3.5 节）：
/// 1. 签名验证（验证更新包签名，公钥验证，私钥不在此处）
/// 2. A/B 部署（双分区切换 + 旧版本保留）
/// 3. 自动回滚（更新后健康检查失败 → 回退）
/// 4. 策略签名（Policy Signature 验证）
///
/// 禁止：
/// - 不持有正式签名私钥
/// - 不自动联网下载（由管理员手动提供更新包）
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        // TODO 第7周：实现更新包签名验证
        // TODO 第7周：实现 A/B 部署逻辑
        // TODO 第7周：实现健康检查和自动回滚

        return 0;
    }
}
