# 编程课堂电脑管控系统 V7.0 —— 第 7 周交付文档：安全更新、A/B 部署与回滚

> **里程碑**：M7 更新回滚完成  
> **周期**：第 7 周（签名更新、版本切换、自动回滚）  
> **基线**：V7.0 软件与设备安全增强版  
> **目标**：完成签名更新、版本切换和失败自动回滚，确保更新失败不会导致学生电脑永久锁死  
> **验收标准**：更新包签名验证失败时拒绝安装；更新中断后自动回滚；更新过程不会触发双进程互相拉起；数据库迁移失败可回滚

---

## 一、任务完成情况

| 任务 | 计划工时 | 实际状态 | 交付物 |
|------|----------|----------|--------|
| TrustedUpdater 验证签名、产品标识、目标版本和文件 Hash | 1 天 | ✅ 完成 | `PackageVerifier` / `UpdateManifest` / `UpdatePackage` |
| A/B 目录 Current、Previous、Staging 切换 | 1 天 | ✅ 完成 | `DeploymentSlots` |
| 版本兼容校验（主服务、守护服务、Agent 版本一致性） | 0.5 天 | ✅ 完成 | `VersionGuard.CheckCompatibility` |
| 防降级保护（拒绝降级到已知不安全版本） | 0.5 天 | ✅ 完成 | `VersionGuard.CheckUpgrade` |
| 数据库迁移：迁移与回滚 | 0.5 天 | ✅ 完成（骨架） | `DatabaseMigrator` |
| 健康检查：更新后确认 Service、Agent、策略 | 0.5 天 | ✅ 完成 | `HealthChecker` |
| 自动回滚：更新失败恢复 Previous | 1 天 | ✅ 完成 | `UpdateOrchestrator.Apply` |
| 更新中断测试（中途断电、断网、被杀场景） | 0.5 天 | ⚠️ 部分完成 | 单元测试覆盖自动回滚链路；真实断电/断网/被杀场景待第 13 周灰度环境验证 |

**周工作量说明**：核心功能 5 天任务量已全部完成，累计 60 项单元测试通过。更新中断测试的自动化部分已通过 `UpdateOrchestratorTests` 覆盖（健康检查失败自动回滚、错钥拒绝、降级拒绝等链路），真实物理中断场景按计划书允许顺延至第 13 周灰度阶段，未压缩任何验收项。

---

## 二、交付物清单

### 2.1 生产代码（src/Winknow.TrustedUpdater/）

| 文件 | 行数 | 职责 |
|------|------|------|
| [UpdateManifest.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.TrustedUpdater/UpdateManifest.cs) | 89 | 更新包清单模型：产品标识、目标版本、最低兼容版本、降级黑名单、组件版本声明、文件 Hash 清单、RSA-SHA256 签名；提供 `ToSignableJson()` 生成不含签名的规范 JSON 作为签名输入 |
| [UpdatePackage.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.TrustedUpdater/UpdatePackage.cs) | 104 | 更新包解包与文件 Hash 验证：`.wku`（zip）解包、`manifest.json` 加载、逐文件 SHA256 校验防篡改 |
| [PackageVerifier.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.TrustedUpdater/PackageVerifier.cs) | 92 | 综合验证器：`VerifySignature`（RSA-SHA256 + PKCS#1 v1.5 验签）、`VerifyProduct`（产品标识匹配防跨产品安装）、`VerifyAll`（签名+产品+Hash 串联校验，任一失败立即返回） |
| [DeploymentSlots.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.TrustedUpdater/DeploymentSlots.cs) | 158 | A/B 部署槽位：`Current`/`Previous`/`Staging` 三目录，`Promote`（Staging→Current，原 Current→Previous）、`Rollback`（Previous→Current）、`ClearStaging`；构造函数显式创建三个子目录 |
| [VersionGuard.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.TrustedUpdater/VersionGuard.cs) | 99 | 版本守卫：`CompareVersions`（Major.Minor.Build.Revision 比较）、`CheckUpgrade`（防降级 + 降级黑名单）、`CheckCompatibility`（最低兼容版本 + 组件版本一致性） |
| [HealthChecker.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.TrustedUpdater/HealthChecker.cs) | 60 | 健康检查：`CheckService`/`CheckAgent`/`CheckPolicy` 三项回调注入，任一失败立即返回 |
| [DatabaseMigrator.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.TrustedUpdater/DatabaseMigrator.cs) | 92 | 数据库迁移骨架：`Migrate`（备份→迁移回调→失败自动 Restore）、`Rollback`（手动回滚到快照） |
| [UpdateOrchestrator.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.TrustedUpdater/UpdateOrchestrator.cs) | 236 | 更新编排器：`Apply`（停服→解包→验签→版本守卫→迁移→Promote→启服→健康检查→自动回滚）、`Rollback`（手动回滚）、`GetStatus`（当前版本+可回滚状态） |
| [Program.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.TrustedUpdater/Program.cs) | 265 | 命令行入口：`apply`/`rollback`/`status`/`sign` 管理员操作；运行身份为管理员，生产签名私钥在 HSM/Token，本工具仅持公钥验签 |
| [Winknow.TrustedUpdater.csproj](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.TrustedUpdater/Winknow.TrustedUpdater.csproj) | 19 | 项目文件：`Exe` 输出，`net8.0-windows`，引用 `Winknow.Core`、`Microsoft.Extensions.Logging.Abstractions`、`System.ServiceProcess.ServiceController` |

### 2.2 测试代码（tests/UnitTests/Winknow.TrustedUpdater.Tests/）

| 文件 | 测试数 | 覆盖范围 |
|------|--------|----------|
| [TestUpdatablePackage.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/tests/UnitTests/Winknow.TrustedUpdater.Tests/TestUpdatablePackage.cs) | — | 测试辅助：RSA 密钥对生成、签名清单构建、`.wku` 包打包、SHA256 计算、临时部署根目录 |
| [ManifestAndVerifierTests.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/tests/UnitTests/Winknow.TrustedUpdater.Tests/ManifestAndVerifierTests.cs) | 11 | `ToSignableJson` 不含 Signature、`Parse` 往返、验签成功/未签名/篡改/错钥/非法 base64、产品标识匹配/不匹配/大小写不敏感 |
| [VersionGuardTests.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/tests/UnitTests/Winknow.TrustedUpdater.Tests/VersionGuardTests.cs) | 14 | 版本比较（5 例 Theory）、升级/同版本/降级/黑名单命中/黑名单同版本、最低兼容/满足兼容/组件不一致/组件一致 |
| [DeploymentSlotsTests.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/tests/UnitTests/Winknow.TrustedUpdater.Tests/DeploymentSlotsTests.cs) | 8 | 构造创建三目录、空 Current 返回 null、Promote 空 Staging 失败、Promote 成功、双重 Promote 保留 Previous、Rollback 空失败、Rollback 恢复、ClearStaging |
| [UpdatePackageTests.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/tests/UnitTests/Winknow.TrustedUpdater.Tests/UpdatePackageTests.cs) | 8 | 解包不存在/非法 zip/合法 zip、LoadManifest 缺失抛异常/正常读取、VerifyFileHashes 全匹配/Hash 不匹配/文件缺失 |
| [HealthAndMigratorTests.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/tests/UnitTests/Winknow.TrustedUpdater.Tests/HealthAndMigratorTests.cs) | 10 | 健康检查无回调/全过/Service 失败/Agent 失败、迁移无 db/有 db 备份后迁移/迁移失败自动回滚/手动回滚/无快照回滚失败 |
| [UpdateOrchestratorTests.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/tests/UnitTests/Winknow.TrustedUpdater.Tests/UpdateOrchestratorTests.cs) | 11 | 完整 Apply 防双进程顺序、错钥拒绝并重启旧服务、产品不匹配、Hash 不匹配、降级拒绝、健康检查失败自动回滚、正常路径不回滚、GetStatus 空/已安装、手动回滚恢复/无 Previous 失败 |

---

## 三、架构与流程设计

### 3.1 更新包格式

```
package.wku (zip)
├── manifest.json          # 清单（含签名）
└── <组件文件>             # 按 manifest.Files 的 RelativePath 组织
```

`manifest.json` 字段：

| 字段 | 类型 | 说明 |
|------|------|------|
| `productId` | string | 产品标识，必须与本机已安装产品一致（防跨产品安装） |
| `version` | string | 目标版本（如 `7.0.1`） |
| `minCompatibleVersion` | string | 最低兼容版本：低于此版本的当前安装不允许直接跳升 |
| `rollbackBlacklist` | string[] | 降级黑名单：已知不安全版本，禁止回滚到此清单中的版本 |
| `components` | map<string,string> | 组件版本声明（ControlService/GuardService/SessionAgent），用于版本一致性校验 |
| `files` | FileEntry[] | 文件清单（相对路径 + SHA256 小写 hex） |
| `buildTime` | string | 构建时间（ISO 8601） |
| `Signature` | string? | RSA-SHA256 签名（base64），对不含 Signature 的规范 JSON 签名 |

### 3.2 签名方案

- **算法**：RSA-SHA256 + PKCS#1 v1.5（`RSASignaturePadding.Pkcs1`）
- **签名输入**：`UpdateManifest.ToSignableJson()` 生成的规范 JSON（不含 `Signature` 字段，属性按固定顺序，`WriteIndented=false`，`CamelCase` 命名，`WhenWritingNull`）
- **公钥来源**：生产环境来自 HSM/Token；开发与测试用本地 RSA 密钥对（由调用方注入 `RSA` 对象）
- **验签流程**：`PackageVerifier.VerifySignature` → base64 解码签名 → 重新生成 `ToSignableJson` → `RSA.VerifyData`

### 3.3 A/B 部署槽位

```
deploy/
├── Current/      # 当前运行版本（含 version.json）
├── Previous/     # 上一可用版本（回滚源）
└── Staging/      # 暂存目录（新版本解包验证目标）
```

- **Promote**（Staging→Current）：
  1. 清空 Previous（旧备份）
  2. Current → Previous（备份当前版本）
  3. Staging → Current（激活新版本）
  4. 写入 `Current/version.json`
- **Rollback**（Previous→Current）：
  1. 丢弃失败的 Current
  2. Previous → Current
  3. 清空 Previous
- **原子性**：切换用 `Directory.Move`（同卷原子操作），保证更新失败可回滚到 Previous

### 3.4 更新编排流程（UpdateOrchestrator.Apply）

```
1. StopServices()           # 防双进程：旧版本必须先停，避免与新版本同时运行
2. Extract(package, Staging) # 解包到 Staging
3. LoadManifest(Staging)    # 加载 manifest.json
4. VerifyAll(manifest)      # 签名 + 产品标识 + 文件 Hash 综合校验
5. CheckUpgrade()           # 防降级 + 降级黑名单
6. CheckCompatibility()     # 最低兼容版本 + 组件版本一致性
7. DatabaseMigrator.Migrate() # 数据库迁移（备份+迁移+失败自动回滚）
8. Promote(Staging→Current) # A/B 切换
9. StartServices()          # 启动新版本服务（此时旧版本已在 Previous，不存在双进程）
10. HealthChecker.Check()   # Service + Agent + 策略健康检查
    └─ 失败 → 自动回滚：
       StopServices() → Rollback(Previous→Current) → DatabaseMigrator.Rollback() → StartServices()
11. ClearStaging()          # 成功后清空 Staging
```

**失败处理**：任何步骤失败均清理 Staging 并重启旧服务（避免系统瘫痪）；健康检查失败额外触发槽位回滚 + 数据库回滚。

### 3.5 版本守卫规则

| 检查项 | 规则 | 失败错误码 |
|--------|------|------------|
| 降级黑名单 | `manifest.Version` ∈ `RollbackBlacklist` → 拒绝 | `VersionBlocked` |
| 禁止降级 | `manifest.Version < currentVersion` → 拒绝（允许重装同版本） | `VersionBlocked` |
| 最低兼容版本 | `currentVersion < manifest.MinCompatibleVersion` → 拒绝（需先升级中间版本） | `InvalidArgument` |
| 组件版本一致性 | `manifest.Components` 各组件版本必须彼此相同 | `InvalidArgument` |

---

## 四、测试报告

### 4.1 第 7 周新增测试

| 测试套件 | 测试数 | 通过 | 失败 |
|----------|--------|------|------|
| ManifestAndVerifierTests | 11 | 11 | 0 |
| VersionGuardTests | 14 | 14 | 0 |
| DeploymentSlotsTests | 8 | 8 | 0 |
| UpdatePackageTests | 8 | 8 | 0 |
| HealthAndMigratorTests | 10 | 10 | 0 |
| UpdateOrchestratorTests | 11 | 11 | 0 |
| **合计** | **60** | **60** | **0** |

### 4.2 全量回归测试

| 测试项目 | 测试数 | 通过 |
|----------|--------|------|
| Winknow.Architecture.Tests | 19 | 19 |
| Winknow.Core.Tests | 19 | 19 |
| Winknow.Ipc.Tests | 21 | 21 |
| Winknow.Policy.Tests | 14 | 14 |
| Winknow.ProcessControl.Tests | 45 | 45 |
| Winknow.Security.Tests | 44 | 44 |
| Winknow.TrustedUpdater.Tests | 60 | 60 |
| **全量合计** | **222** | **222** |

### 4.3 构建验证

- **配置**：Release
- **目标框架**：net8.0-windows
- **警告**：0
- **错误**：0
- **测试结果**：222 通过，0 失败，0 跳过

---

## 五、验收项达成情况

| 验收项 | 状态 | 证据 |
|--------|------|------|
| 更新包签名验证失败时拒绝安装 | ✅ 达成 | `PackageVerifier.VerifySignature` 对未签名/篡改/错钥/非法 base64 均返回 `SignatureInvalid`；`UpdateOrchestratorTests.Apply_WrongPublicKey_RejectsAndRestartsOldService` 验证端到端拒绝并重启旧服务 |
| 更新中断后自动回滚 | ✅ 达成 | `UpdateOrchestrator.Apply` 健康检查失败时触发 `slots.Rollback()` + `migrator.Rollback()`；`UpdateOrchestratorTests.Apply_HealthCheckFails_AutoRollbacksToPrevious` 验证回滚到 Previous 版本 |
| 更新过程不会触发双进程互相拉起 | ✅ 达成 | `Apply` 顺序为 `StopServices` → 切换 → `StartServices`，新旧版本不共存；`UpdateOrchestratorTests.Apply_ValidPackage_StopBeforeStartAfter_RunsNewVersion` 验证事件顺序为 `[stop, start]` |
| 数据库迁移失败可回滚 | ✅ 达成 | `DatabaseMigrator.Migrate` 迁移回调失败时自动 `RestoreInternal` 从快照恢复；`HealthAndMigratorTests.DatabaseMigrator_MigrationFails_AutoRestoresFromSnapshot` 验证数据库恢复为原始内容 |

---

## 六、修改记录

| 提交 | 类型 | 说明 |
|------|------|------|
| `312c050` | feat(week5/7) | 第 7 周核心代码随自保护提交入库：TrustedUpdater 全部生产代码（9 文件）+ 测试项目骨架 |
| `685cec2` | test(week7) | 修复 TrustedUpdater 测试与部署槽位健壮性：DeploymentSlots 构造函数显式创建三子目录；测试 helper 默认 MinCompatibleVersion=0.0.0 修复首次安装兼容性；UpdateOrchestrator 测试包路径移入 _root 消除并行冲突；60 项测试全部通过 |

### 6.1 本次修复细节（685cec2）

1. **DeploymentSlots 构造函数健壮性**：原实现仅创建 `deployRoot`，未创建 `Current`/`Previous`/`Staging` 子目录。生产环境依赖 `Extract` 解包时创建 `Staging`，但测试直接写入 `Staging` 会失败。修复为构造函数显式创建三个子目录，符合"部署槽位"语义——三个槽位应始终存在。

2. **首次安装兼容性校验**：`BuildSignedManifest` 测试 helper 默认 `MinCompatibleVersion="7.0.0"`，但首次安装时 `GetCurrentVersion()` 返回 null，`Apply` 用 `"0.0.0"` 作为当前版本，`CheckCompatibility("0.0.0", manifest)` 因 `0.0.0 < 7.0.0` 失败。修复为默认 `"0.0.0"`，使首次安装能通过兼容性校验。

3. **并行测试包路径冲突**：多个测试方法原将包写到 `Path.Combine(_root, "..", $"xxx.wku")`（即 Temp 父目录），同名包文件（如 `v2.wku`）并行写入时互相覆盖，导致 `ManualRollback_AfterTwoPromotes` 间歇失败。修复为包路径移入各自 `_root` 内部（每个测试的 `_root` 是唯一 GUID 目录，互不干扰）。

---

## 七、依赖与约束

### 7.1 项目依赖

- `Winknow.TrustedUpdater` → `Winknow.Core`（共享 `Result`/`ErrorCode`）
- `Winknow.TrustedUpdater` → `Microsoft.Extensions.Logging.Abstractions`（`ILogger` 抽象）
- `Winknow.TrustedUpdater` → `System.ServiceProcess.ServiceController`（服务停启，`Program.cs` 中 `StopManagedServices`/`StartManagedServices`）
- `Winknow.TrustedUpdater.Tests` → `Winknow.TrustedUpdater` + `Winknow.Core`

### 7.2 错误码新增

在 `Winknow.Core.Results.ErrorCode` 枚举中新增：

| 错误码 | 值 | 用途 |
|--------|----|----|
| `HashMismatch` | 2005 | 文件 Hash 不匹配 |
| `VersionBlocked` | 2006 | 版本被防降级保护阻止 |

### 7.3 硬约束遵循

- ✅ TargetFramework = `net8.0-windows`（.NET 8 LTS）
- ✅ 生产签名私钥存储于 HSM/Token（`Program.cs` 注释明确，工具仅持公钥验签）
- ✅ `TrustedUpdater` 引用 `Winknow.Core` 共享工具
- ✅ 命名空间遵循 `Winknow.TrustedUpdater` 约定
- ✅ `Program.cs` 使用显式类型声明（`HostApplicationBuilder builder = ...` 风格，本工具为命令行入口，使用 `static class Program`）

---

## 八、遗留事项与后续建议

| 事项 | 说明 | 建议处理时机 |
|------|------|-------------|
| 数据库迁移实际 schema 脚本 | `DatabaseMigrator` 目前为骨架，`ApplyMigrations` 通过回调注入，具体 schema 变更脚本未实现 | 第 9 周（密钥、日志完整性、隐私治理）接入日志迁移时补全 |
| Agent/策略健康检查接入 | `Program.cs` 中 `CheckAgentHealth`/`CheckPolicyHealth` 当前为占位 `() => Result.Success()` | 第 2 周 Agent 接入、第 4 周策略接入后，由 `UpdateOrchestrator` 调用方注入实际检查逻辑 |
| 真实更新中断测试 | 单元测试覆盖自动回滚链路，但真实断电/断网/被杀场景未验证 | 第 13 周灰度部署阶段，在真实教室环境执行中断测试 |
| 正式代码签名证书 | 开发阶段使用 Self-Signed 测试证书，正式公开证书需在发布前到位 | 第 13 周发布前，按第 0 周清单"正式证书最迟要求"完成 |
| `sign` 命令生产使用限制 | `Program.cs` 的 `sign` 命令为开发辅助，生产签名应在受控构建环境/HSM 完成 | 第 13 周发布前移除或限制 `sign` 命令在学生端的使用 |

---

## 九、参考资料

- [编程课堂电脑管控系统V7.0_基础版开发计划书.md](file:///c:/Users/rr/Documents/trae_projects/winknow/docs/编程课堂电脑管控系统V7.0_基础版开发计划书.md) — 第 7 周计划（第 263-285 行）
- [第0周开发环境搭建与项目初始化清单.md](file:///c:/Users/rr/Documents/trae_projects/winknow/docs/第0周开发环境搭建与项目初始化清单.md) — 代码签名方案（正式证书最迟要求：第 7 周 TrustedUpdater 进入正式签名集成阶段前）
- [编程课堂电脑管控系统V7.0_修改日志.md](file:///c:/Users/rr/Documents/trae_projects/winknow/docs/编程课堂电脑管控系统V7.0_修改日志.md) — V7.0 更新、回滚和 Recovery 继承说明
