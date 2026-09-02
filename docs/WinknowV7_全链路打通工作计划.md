# Winknow V7.0 全链路打通工作计划

> 依据：`docs/WinknowV7_项目说明书_AI分析版.md`（事实基线 commit `8ab40ac`）及三项代码专项调查（服务命名 / IPC-Agent 链路 / 构建-安装-更新链）。
>
> 目标链路：**安装 → 双服务启动 → 策略加载 → 进程管控 → 学生登录 Agent 拉起 → 锁屏/解锁 → 维护进入/退出 → 更新/回滚 → 授权卸载**
>
> 原则：每阶段一个 commit + 全量测试绿；在干净 Win10/11 VM 快照上验收；**不新增功能，只接通闭环**。

## 阶段 0：基线与测试环境

- [ ] 记录当前 commit 基线，跑全量 `dotnet test`（确认 422 项基线）
- [ ] 准备隔离 VM：Win11 x64 快照 + .NET 8 Desktop Runtime + Inno Setup 6（ISCC）
- [ ] 修复已知"假绿"：CI 增加门禁——每个测试 DLL 必须执行 ≥1 项（当前 `Winknow.Network.Tests` 零执行但整体返回 0）

## 阶段 1：服务名统一（一切的地基）

**现状**：SCM 内部名 `WinknowControl/WinknowGuard`（安装器）vs 代码全用显示名 `Winknow Control Service` → `OpenService/sc sdset/ServiceController/SafeBoot` 全部静默失败，守护拉起、更新停启、维护停服务、卸载全瘫。

| 改动 | 位置 |
|---|---|
| 新增单一可信源常量 `Constants.Services` | `src/Winknow.Core/Constants.cs`（当前无任何服务名常量） |
| 替换硬编码（10 处） | ControlService `Program.cs:6`、`Worker.cs:22,102-104`；GuardService `Program.cs:6`、`Worker.cs:27`；AdminUI `MainWindow.xaml.cs:27`；TrustedUpdater `Program.cs:30`；RecoveryTool `Program.cs:33`；Security `RegistryAclProtector.cs:93,96` |
| 测试同步 | `ArchitectureTests.cs:82-83`、`HeartbeatAndInstanceTests.cs:32` |

统一方案：以安装器内部名 `WinknowControl`/`WinknowGuard` 为准（canary 脚本已按此名核验），显示名仅保留在安装器 `[Services]` 的 `DisplayName`。

**验收**：VM 上 kill ControlService → GuardService 秒级拉起成功；`sc sdset`/SafeBoot 注册不再报 1060。

## 阶段 2：构建与安装链修复

**现状**：发布产物缺 SessionAgent/RecoveryTool；策略路径三方分裂（装到 `policy.json`，服务读 `deploy\Current\policies\`，永远走默认策略）；安装器调用不存在的 `snapshot` 命令；`publickey.pem` 从未部署 → apply 开箱必败。

1. `Build-Release.ps1` 增发 `Winknow.SessionAgent`（→ payload\agent）、`Winknow.RecoveryTool`（→ payload\tools）；同步混淆 DLL 清单
2. 策略统一安装到 `{commonappdata}\Winknow\deploy\Current\policies\default_policy_v7.0.json`（随 A/B 槽切换，语义自洽）；删 `WinknowSetup.iss:58` 的改名落盘；修 RecoveryTool 卸载清理路径
3. TrustedUpdater 新增 `snapshot` 命令（复用现成 `RecoveryVault.SnapshotFrom`，注意 iss:82 传的是 deploy 根而非 Current）
4. 签名阶段导出 `publickey.pem` 进 payload，iss 落位 deploy 根（apply 默认读取处）
5. 修 `WinknowSetup.iss:123` dotnet 检测路径 `{commoncf}` → `{autopf}`

**验收**：ISCC 真实编译通过；VM 全新安装 → 双服务 Running → 服务日志证明加载了真实策略文件（非内置默认）→ Recovery manifest 生成。

## 阶段 3：IPC 真实身份与消息处理

**现状**：管道 Everyone 可写且信任消息自报 SID（可伪造）；白名单只有 SYSTEM/管理员，学生心跳必被拒；服务端收到消息只打 Debug 日志不回包。

1. `IpcServer`：用 `GetNamedPipeClientProcessId` + Impersonation 取真实客户端 SID，与消息 `SenderSid` 比对；`ValidateMessage` 补传 `actualDeviceId` 启用设备绑定校验（当前 `IpcServer.cs:144` 未传）
2. 认证模型：服务从连接层取真实 SID 做准入（替代自报），登录事件动态 `AllowSid`、注销 `RevokeSid`
3. 重写 `Worker.cs OnMessageReceived`（当前 409-414 仅日志）：心跳→登记会话在线表；按类型分发；回 ACK
4. `IpcConstants` 补 `MessageTypeLockOverlay = 0x03E9`（消灭 SessionAgent 里的魔法数 1001）
5. IpcServer 增加服务端主动推送能力（sessionId→连接映射）

**验收**：伪造 `SenderSid=S-1-5-18` 的学生消息被拒；真实学生 SID 心跳被登记。

## 阶段 4：SessionAgent 拉起与锁屏闭环

**现状**：无 WTS 监听、无 `CreateProcessAsUser`，Agent 无人启动；会话 ID 错取 PID（`Program.cs:113`）；无消息循环导致遮罩即使 SHOW 也不渲染；连不上即退出无重试。

1. 新增 `SessionAgentLauncher`（独立类，绕开 ArchitectureTests 对 Worker.cs 的字符串约束，同时更新该测试约束）：WTS 登录事件 → `WTSQueryUserToken` → `CreateProcessAsUser` 拉起 Agent；注销时终止并 `RevokeSid`
2. SessionAgent：`GetCurrentSessionId` 改 `Process.GetCurrentProcess().SessionId`；连接失败指数退避重连；断连自杀让服务重拉
3. LockOverlay：引入 Win32 消息循环（GetMessage/DispatchMessage），`Show/Hide` marshal 到窗口线程
4. 订阅改命名方法（修复 `-=` 退订无效缺陷）
5. AdminUI `ClassroomPage.xaml.cs:190` 锁定按钮 → IPC 命令 → ControlService 推送 → 目标 Agent 显示遮罩（替掉 TODO）

**验收**：学生登录 → Agent 自动拉起 → 心跳在线 → AdminUI 点锁定 → 3 秒内全屏置顶遮罩 → 解锁消失。Ctrl+Alt+Del 逃生路径记录为已知边界。

## 阶段 5：维护与卸载鉴权闭环（可与阶段 4 并行）

1. AdminUI `OnMaintenanceExited`（`MainWindow.xaml.cs:109-117`）增加 `StartManagedServices`（对称于停止逻辑）；停/启失败弹窗反馈，不再吞异常
2. RecoveryTool `uninstall` 前置 `MaintenanceSession` 鉴权（密码+TOTP 或恢复码）；`--yes` 只跳过交互确认，不得跳过鉴权
3. iss `InitializeUninstall` 调用 RecoveryTool 校验命令，或卸载入口统一收敛到 RecoveryTool

**验收**：AdminUI 退出维护后两服务自动恢复 Running；无凭据 uninstall 被拒；鉴权卸载后服务/目录/SafeBoot 键/注册表干净。

## 阶段 6：更新闭环与授权收尾

1. `CheckAgentHealth/CheckPolicyHealth`（`TrustedUpdater/Program.cs:84-85` 硬编码成功）接真实探针：Agent IPC ping、策略文件可解析
2. Licensing 去模拟化（最小改）：令牌签名复用阶段 2 的 RSA 体系（TeacherLicenseServer 私钥签 / 客户端公钥验），废除"签名非空即通过"（`LicenseToken.VerifySignature`）和公开 DeviceId 派生密钥
3. 更新包解压前后加路径穿越/总大小/文件数限制

**验收**：VM 上构造 7.0.1 签名包 → apply → 槽切换 → 健康检查通过；注入坏包 → 自动回滚 Previous。

## 阶段 7：端到端全链路验收（交付）

干净 VM 按剧本走完整链：安装 → 服务 → 策略 → 学生登录 Agent → 违规进程 2 秒内被杀 → 锁屏/解锁 → 维护进入/退出 → 更新+回滚 → 授权卸载。输出验收报告，同步更新 `WinknowV7_项目说明书_AI分析版.md` 的 A/B/C/D 状态标记。

## 依赖与顺序

```
阶段0 → 阶段1 → 阶段2 → 阶段3 → 阶段4 → 阶段7
                          ↘ 阶段5（可与4并行）→ 阶段6 ↗
```

## 明确不做（本计划范围外）

- 真实网站流量阻断（需 WFP/驱动，属产品能力扩展，说明书已建议降级产品承诺）
- 云端后台/集中多机管理（Licensing 仅做单机签名加固）
- 键盘钩子级防绕过（记录为已知边界）
