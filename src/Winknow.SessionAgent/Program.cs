namespace Winknow.SessionAgent;

/// <summary>
/// SessionAgent 会话代理入口。
/// 运行身份：学生用户（当前登录的标准用户）。
/// 输出类型：WinExe（无控制台窗口）。
///
/// 核心职责（见《V7.0 组件架构设计》第 3.3 节）：
/// 1. 会话内交互（键盘钩子 WH_KEYBOARD_LL + 屏幕控制）
/// 2. IPC 客户端（连接 ControlService Named Pipe）
/// 3. 自清理（用户注销时退出）
///
/// 启动方式：由 ControlService 在用户登录时通过 CreateProcessAsUser 拉起。
/// 实例数：每个活动用户会话 1 个（通过互斥锁保证）。
///
/// 禁止：
/// - 不执行软件终止决策（决策权在 ControlService）
/// - 不持有管理员权限
/// - 不直接修改注册表或文件 ACL
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        // TODO 第2周：创建互斥锁（防止多实例）+ 会话枚举
        // TODO 第2周：设置键盘钩子（SetWindowsHookEx + WH_KEYBOARD_LL）
        // TODO 第2周：连接 ControlService Named Pipe
        // TODO 第2周：进入消息循环（GetMessage）

        return 0;
    }
}
