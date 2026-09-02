# ADR-001：服务标识与产品路径统一

| 项 | 内容 |
|---|---|
| 状态 | 已批准（Accepted）——产品负责人于 2026-09-02 批准 |
| 日期 | 2026-09-02 |
| 覆盖决策 | TD-01 服务标识、TD-02 程序/策略/数据路径 |
| 关联任务 | PR-01（ServiceNames + ProductPaths）、PR-02（发布 payload + 安装器） |
| 关联问题 | B-01（服务名不一致）、B-03（策略路径分裂） |

## 背景

安装器以内部服务名 `WinknowControl`/`WinknowGuard` 注册服务（`sc.exe create`），而全部 C# 代码使用显示名 `Winknow Control Service`/`Winknow Guard Service` 调用 `OpenService`/`ServiceController`/`sc sdset`/SafeBoot 注册表路径。SCM 系列 API 只认内部名，导致服务自保护、守护拉起、维护停启、更新与卸载全部静默失败（说明书 B-01）。

策略文件存在三方分裂：构建产出 `payload\policy\`、安装落地 `%ProgramData%\Winknow\policy.json`、服务读取 `deploy\Current\policies\default_policy_v7.0.json`，服务实际永远退回内置默认策略（B-03）。

## 决策

### TD-01 服务标识

- 内部服务名固定为 `WinknowControl`、`WinknowGuard`。
- 显示名固定为 `Winknow Control Service`、`Winknow Guard Service`。
- 所有 `ServiceController`、`OpenService`、`sc.exe`、服务注册表路径（含 `HKLM\SYSTEM\CurrentControlSet\Services\<name>` 与 SafeBoot 键）一律使用内部名。
- UI 展示与日志文本可使用显示名。
- 在 `Winknow.Core` 建立唯一常量源 `ServiceNames`（随 PR-01 落地），生产项目禁止再出现服务名字符串字面量（以架构测试强制）。

### TD-02 程序、策略与数据路径

| 内容 | 路径 |
|---|---|
| 服务程序（A/B 槽位） | `%ProgramData%\Winknow\deploy\{Current,Previous,Staging,Recovery}` |
| 生效策略 | `%ProgramData%\Winknow\policies\active_policy.json`（签名 `active_policy.sig` 或含签名字段的封装格式） |
| 维护配置 | `%ProgramData%\Winknow\maintain` |
| 日志与密钥 | `%ProgramData%\Winknow\logs`、`%ProgramData%\Winknow\keys` |
| AdminUI / 常驻 Updater | `%ProgramFiles%\Winknow` |

- 所有路径集中到 `Winknow.Core.ProductPaths`，支持测试注入临时根目录。
- **策略与二进制版本必须在更新事务中保持一致**：`active_policy.json` 的激活版本由更新编排管理，apply/rollback 随事务一并切换（v8 计划 P6-03 第 8 条），防止回滚后新策略与旧服务不兼容。
- 敏感目录（策略、密钥、恢复库、维护配置、服务文件）ACL：SYSTEM/Administrators 可写，标准用户只读或无权访问。

## 理由

- 内部名不带空格，利于 `sc.exe`/PowerShell/注册表操作；canary 脚本已按内部名核验。
- 策略独立于 deploy 槽位（而非放入 `Current\policies\`）允许策略热更新不换二进制；版本一致性由更新事务保证。
- 单一常量源消除 10 处硬编码漂移（调查确认 ControlService/GuardService/AdminUI/TrustedUpdater/RecoveryTool/RegistryAclProtector 均受影响）。

## 后果

- 需同步修改 2 个测试文件（ArchitectureTests、HeartbeatAndInstanceTests），否则 CI 锁死旧名。
- RecoveryTool 卸载清理路径、安装器 [Files]/[Run] 段随 PR-02 一并统一。

## 被否决的替代方案

- 改安装器使用显示名作内部名：显示名含空格，`sc.exe`/注册表路径易错，且 canary 脚本已按内部名工作，改动面更大。
- 策略放入 `deploy\Current\policies\`：策略更新必须走整包更新，无法独立修复策略缺陷。
