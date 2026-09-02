# Winknow V7.0 任务追踪表

> 依据：《WinknowV7_修改实施计划书_AI执行版_v8.md》
> 用法：每个任务一行，状态流转 `待办 → 进行中 → 待验收 → 完成/已取消`；证据列填 PR/提交/报告链接。
> 负责人约定：AI=AI 开发执行（Trae）；PO=产品负责人（验收与决策）。
> 本表为 P0-03 交付物（gh CLI 未安装，暂以仓库内追踪表替代 GitHub Issues；安装后可迁移）。

## 阶段 0：基线冻结与架构决策

| 任务 ID | 内容 | 负责人 | 状态 | 验收人 | 证据 |
|---|---|---|---|---|---|
| P0-01 | 固定分支/提交/SDK/包锁定策略，产出基线记录 | AI | 完成 | PO | docs/baseline/阶段0_基线验证报告.md |
| P0-02 | TD-01~TD-08 形成 ADR 并获 PO 批准 | AI 起草 / PO 批准 | 完成 | PO | docs/adr/ADR-001/002/003（2026-09-02 全部批准） |
| P0-03 | 建立任务追踪表 | AI | 完成 | PO | 本文件 |
| P0-04 | Verify-Baseline.ps1 一键基线验证脚本 | AI | 完成 | PO | tools/Verify-Baseline.ps1（基线：构建 0w/0e，486/486 测试通过，10/10 程序集执行） |

## 阶段 1：构建、发布、安装与服务统一

| 任务 ID | 内容 | 负责人 | 状态 | 验收人 | 证据 |
|---|---|---|---|---|---|
| PR-01 | ServiceNames + ProductPaths 常量统一 | AI | 待验收 | PO | src/Winknow.Core/ServiceNames.cs + ProductPaths.cs；13 个文件改用常量；架构测试新增字面量禁令（486→487 测试全过） |
| PR-02 | 发布 payload 补全 + 安装器修复（snapshot/策略路径/公钥） | AI | 待验收 | PO | Build-Release 补发 SessionAgent/RecoveryTool + 混淆绝对路径配置修复 + keygen/公钥步骤；iss 落位 active_policy.json/{app}\Tools/publickey.pem/snapshot 无参/{autopf}；发布管线端到端 exit 0（payload 278 文件哈希全对）。注：ISCC 本机未装，安装包编译待具备 Inno Setup 6 的环境复验 |

## 阶段 2：IPC 与 SessionAgent 闭环

| 任务 ID | 内容 | 负责人 | 状态 | 验收人 | 证据 |
|---|---|---|---|---|---|
| PR-03 | IPC 真实 SID（Impersonation）+ 握手协议 | AI | 待办 | PO | |
| PR-04 | SessionManager/WtsSessionMonitor/SessionAgentLauncher + Agent 消息泵 | AI | 待办 | PO | |
| P2-05 | 键盘钩子（`KeyboardPolicyEnabled` 独立开关，默认关） | AI | 待办 | PO | |

## 阶段 3：维护、卸载与授权安全

| 任务 ID | 内容 | 负责人 | 状态 | 验收人 | 证据 |
|---|---|---|---|---|---|
| PR-05 | 维护配置保护（DPAPI/TOTP）+ MaintenanceCoordinator | AI | 待办 | PO | |
| PR-06 | 卸载一次性票据鉴权 | AI | 待办 | PO | |
| PR-07 | 授权 Token 签名 + LAN Provider 真实化 | AI | 待办 | PO | |

## 阶段 4：进程管控可信化

| 任务 ID | 内容 | 负责人 | 状态 | 验收人 | 证据 |
|---|---|---|---|---|---|
| PR-08 | WinVerifyTrust + 进程规则（ByHash/路径字段/优先级） | AI | 待办 | PO | |

## 阶段 5：网络管控可交付化

| 任务 ID | 内容 | 负责人 | 状态 | 验收人 | 证据 |
|---|---|---|---|---|---|
| PR-09 | 受管浏览器 URL 策略 + 按用户 Hive 应用网络策略 | AI | 待办 | PO | |

## 阶段 6：日志、守护、更新与恢复加固

| 任务 ID | 内容 | 负责人 | 状态 | 验收人 | 证据 |
|---|---|---|---|---|---|
| PR-10 | 统一 AuditWriter 审计管道 | AI | 待办 | PO | |
| PR-11 | 更新包加固 + Recovery Vault 信任源 | AI | 待办 | PO | |

## 阶段 7：自动化、兼容性与安全验证

| 任务 ID | 内容 | 负责人 | 状态 | 验收人 | 证据 |
|---|---|---|---|---|---|
| PR-12 | CI 门禁（0-test 拒绝/覆盖率棘轮/漏洞=0/ISCC 编译/payload 校验） | AI | 待办 | PO | |
| P7-验证 | Windows 兼容矩阵 + 攻击用例 + 7 天稳定性 | AI + PO | 待办 | PO | |

## 阶段 8：灰度与正式发布

| 任务 ID | 内容 | 负责人 | 状态 | 验收人 | 证据 |
|---|---|---|---|---|---|
| S0~S3 | 灰度四阶段（2 台→10 台→1 课堂→25% 批次） | PO 主导 | 待办 | PO | |

## 里程碑

| 里程碑 | 定义 | 状态 |
|---|---|---|
| M1 可安装基线 | 安装包完整、服务/路径统一、策略加载、重启在线 | 未达 |
| M2 会话闭环 | Agent 可信启动、IPC 真实身份、锁屏命令闭环 | 未达 |
| M3 可信管理 | 维护/卸载/授权全部有身份、审计与重放防护 | 未达 |
| M4 管控闭环 | 进程可信判断 + 受管浏览器策略通过绕过测试 | 未达 |
| M5 可恢复发布 | 审计完整性/Guard/A-B 更新/故障注入/回滚通过 | 未达 |
| M6 正式候选版 | CI 门禁/兼容矩阵/真实课堂灰度/正式签名完成 | 未达 |
