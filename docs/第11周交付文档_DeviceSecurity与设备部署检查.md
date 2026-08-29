# 编程课堂电脑管控系统 V7.0 —— 第 11 周交付文档：DeviceSecurity 与设备部署检查

> **里程碑**：M11 设备模块完成
> **周期**：第 11 周（固件信息采集、Secure Boot 检测、启动配置采集、人工核验表、设备评分、核验记录、变化失效机制、AdminUI 页面、报告导出）
> **基线**：V7.0 守护与恢复版（第 10 周交付，提交 `ec797d6`）
> **目标**：新增设备启动安全模块，形成"自动检测 + 人工核验"结合的部署流程——自动项可采尽采，固件项如实标注"需人工核验"，评分逐项可追溯，BIOS 变化自动作废旧核验
> **验收标准**：Secure Boot 状态读取正确；无法自动检测的项目显示"需人工核验"，不显示为通过；设备评分可追溯到原始检查项；BIOS 更新后旧核验记录自动失效；文档明确 V7.0 不使用 BitLocker 的边界

---

## 一、任务完成情况

| 任务 | 计划工时 | 实际状态 | 交付物 |
|------|----------|----------|--------|
| 固件信息采集（厂商、型号、版本、UEFI/Legacy） | 0.5 天 | ✅ 完成 | `FirmwareInfoCollector`（WMI 三表 + GetFirmwareType P/Invoke） |
| Secure Boot 检测（状态读取和风险提示） | 0.5 天 | ✅ 完成 | `SecureBootDetector`（注册表 State + 风险映射） |
| 启动配置采集（启动项和系统盘状态） | 1 天 | ✅ 完成 | `BootConfigCollector`（系统盘/GPT-MBR/BCD 可读性） |
| 人工核验表（BIOS 密码、USB Boot、PXE、Boot Order、Boot Menu） | 1 天 | ✅ 完成 | `ManualChecklist`（五项定义 + JSON 持久化） |
| 设备评分（权重、等级、整改建议） | 0.5 天 | ✅ 完成 | `DeviceSecurityScorer`（100 分权重模型 + 硬规则） |
| 核验记录（管理员、时间、设备、固件版本和备注） | 0.5 天 | ✅ 完成 | `VerificationStore`（verification.json） |
| 变化失效机制（BIOS 更新/主板变化后重新核验） | 0.5 天 | ✅ 完成 | 固件指纹比对 + 记录删除 + 核验表重置 |
| AdminUI 页面（状态、评分、报告和风险项） | 1.5 天 | ✅ 完成 | `DeviceSecurityPage`（Tab 页 + 人工核验操作 + 导出） |
| 导出报告（Markdown/CSV） | 0.5 天 | ✅ 完成 | `ReportExporter`（MD 五节报告 + CSV UTF-8 BOM） |

**周工作量说明**：计划 9 项任务全部完成；新增 33 项单元测试（新测试项目 `Winknow.DeviceSecurity.Tests`），全量 456 项测试通过；生产项目保持 14 个（新组件全部归入 Winknow.DeviceSecurity 既有项目），AdminUI 引用 DeviceSecurity 完成页面集成。

---

## 二、交付物清单

### 2.1 Winknow.DeviceSecurity（8 个新文件）

| 文件 | 职责 |
|------|------|
| [Models.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.DeviceSecurity/Models.cs) | 领域模型：CheckStatus（Pass/Fail/**Pending**/NotApplicable）、SecurityGrade、CheckItem、FirmwareInfo、BootConfigInfo、ManualCheckResult、VerificationRecord、DeviceSecurityReport；**模块注释即 BitLocker 边界声明** |
| [FirmwareInfoCollector.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.DeviceSecurity/FirmwareInfoCollector.cs) | Win32_BIOS（厂商/版本/发布日期）+ Win32_BaseBoard（主板/序列号）+ Win32_ComputerSystem（整机）+ kernel32 `GetFirmwareType`（UEFI/Legacy）；`ComputeFingerprint`：SHA256(版本\|日期\|序列号) 前 16 字节；单项 WMI 失败容错为 "Unknown"，采集器永不抛异常 |
| [SecureBootDetector.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.DeviceSecurity/SecureBootDetector.cs) | HKLM\...\SecureBoot\State：1→Enabled / 0→Disabled / 不可读→**Unknown**；`Evaluate` 映射：Disabled→Fail+整改建议，Unknown→**Pending（需人工核验，绝不显示为通过）** |
| [BootConfigCollector.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.DeviceSecurity/BootConfigCollector.cs) | Win32_BootPartition→系统盘；分区表判定规则独立方法 `DeterminePartitionStyle`（"GPT:" 前缀→GPT，非空无前缀→MBR，空→Unknown）便于测试；bcdedit 探测 BCD 可读性（不可读不算错误） |
| [ManualChecklist.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.DeviceSecurity/ManualChecklist.cs) | 五项固件检查定义（bios-password 15 / usb-boot 15 / pxe-boot 10 / boot-order 5 / boot-menu 5）；默认全 Pending；SetResult 拒绝 Pending 与未知 Id、管理员必填；checklist.json 持久化，损坏按全 Pending 处理 |
| [DeviceSecurityScorer.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.DeviceSecurity/DeviceSecurityScorer.cs) | 权重模型：自动 50（secure-boot 30 + uefi-mode 20）+ 人工 50；**Score = Σ(Pass 权重)**；存在 Pending → 等级恒为 NeedsManualReview；无 Pending 按 ≥85 Secure / ≥70 Attention / <70 HighRisk；**硬规则**：secure-boot 或 usb-boot Fail → 至少 HighRisk（外部启动主通道不容折扣）；整改建议按权重降序 |
| [VerificationStore.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.DeviceSecurity/VerificationStore.cs) | 核验记录 Save/Load/IsCurrent；**ValidateAndExpire**：指纹不一致 → 删除记录 + 重置人工核验表（强制重新核验），返回处置描述供 UI/报告展示 |
| [ReportExporter.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.DeviceSecurity/ReportExporter.cs) | Markdown 五节报告（固件/Secure Boot 与启动配置/检查项明细表/评分与整改/核验记录状态）+ **BitLocker 边界固定页脚**；CSV（表头+明细、逗号引号转义、UTF-8 BOM）；`WriteFiles` 双格式落盘 |
| [DeviceSecurityAssessor.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.DeviceSecurity/DeviceSecurityAssessor.cs) | 评估门面：采集→指纹→失效判定→七项检查组装→评分→报告；`SaveVerification`（逐项或批量保存人工结论，写核验记录） |

### 2.2 AdminUI（页面 1.5 天任务）

| 文件 | 改动 |
|------|------|
| [MainWindow.xaml](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.AdminUI/MainWindow.xaml) | 重构为 TabControl：Tab1 维护模式（原功能不变）+ Tab2 设备安全 |
| [DeviceSecurityPage.xaml](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.AdminUI/DeviceSecurityPage.xaml) | 评分大字（等级配色 绿/橙/红）、Secure Boot 与核验记录状态、固件信息条、检查项 DataGrid（标题/类别/权重/状态/详情）、人工核验操作区（管理员/备注 + 记为通过/未通过）、整改建议列表、导出按钮 |
| [DeviceSecurityPage.xaml.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.AdminUI/DeviceSecurityPage.xaml.cs) | 检测→渲染→核验→重评闭环：自动项拦截提示（无需人工核验）、核验后自动 Assess 刷新评分与核验状态；SaveFileDialog 选导出位置 |
| Winknow.AdminUI.csproj | 新增 DeviceSecurity 项目引用 |

### 2.3 配置与测试

| 文件 | 改动 |
|------|------|
| [Constants.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.Core/Constants.cs) | 新增 `Constants.DeviceSecurity` 节（数据目录名/核验记录文件名/清单文件名） |
| Winknow.DeviceSecurity.csproj | 新增 System.Management 包（WMI） |
| [Winknow.DeviceSecurity.Tests](file:///c:/Users/rr/Documents/trae_projects/winknow/tests/UnitTests/Winknow.DeviceSecurity.Tests/Winknow.DeviceSecurity.Tests.csproj)（新项目，3 个测试文件） | ScorerTests 8 + ChecklistAndVerificationTests 13 + ReportAndAssessorTests 12 = 33 项 |

---

## 三、架构与流程设计

### 3.1 评估流水线（DeviceSecurityAssessor.Assess）

```
┌────────────────────────────────────────────────────────┐
│ ① 固件采集（WMI×3 + GetFirmwareType）                    │
│    └→ 当前固件指纹 = SHA256(BIOS版本|发布日期|主板序列号)  │
├────────────────────────────────────────────────────────┤
│ ② 变化失效判定（ValidateAndExpire）                      │
│    指纹一致 → 核验有效（人工项沿用已核验结论）             │
│    指纹不一致 → 删核验记录 + 人工项全部回退 Pending        │
│    无记录 → "从未核验"                                   │
├────────────────────────────────────────────────────────┤
│ ③ 自动项检测                                             │
│    secure-boot（30）：注册表 State → Pass/Fail/Pending    │
│    uefi-mode（20）：GetFirmwareType → Pass/Fail/Pending  │
├────────────────────────────────────────────────────────┤
│ ④ 人工项组装（ManualChecklist 五项，50 分）               │
│    已核验 → Pass/Fail；未核验 → Pending（含失效原因提示） │
├────────────────────────────────────────────────────────┤
│ ⑤ 评分（Score=ΣPass 权重）+ 等级（含 Pending/硬规则）     │
└────────────────────────────────────────────────────────┘
          ↓
 DeviceSecurityReport ──→ AdminUI 渲染 / MD+CSV 导出
```

### 3.2 权重模型（100 分 = 自动 50 + 人工 50）

| # | 检查项 | Id | 类别 | 权重 | 判定方式 |
|---|--------|----|------|------|----------|
| 1 | Secure Boot 已启用 | secure-boot | 自动 | 30 | 注册表 State |
| 2 | UEFI 固件模式 | uefi-mode | 自动 | 20 | GetFirmwareType API |
| 3 | BIOS 管理员密码 | bios-password | 人工 | 15 | 现场核验 |
| 4 | USB 外部启动禁用 | usb-boot | 人工 | 15 | 现场核验 |
| 5 | PXE 网络启动禁用 | pxe-boot | 人工 | 10 | 现场核验 |
| 6 | Boot Order 首位内置盘 | boot-order | 人工 | 5 | 现场核验 |
| 7 | Boot Menu 禁用 | boot-menu | 人工 | 5 | 现场核验 |

等级规则：任一 Pending → **需人工核验**（分数仅供参考不作为通过依据）；无 Pending：≥85 安全 / ≥70 需关注 / <70 高风险；**硬规则**：secure-boot 或 usb-boot Fail → 至少高风险。

### 3.3 变化失效机制（验收④）

```
核验时：记录指纹 = SHA256("1.2.3" | "20250101…" | "MB-001")
                     ↓ BIOS 升级 1.2.3 → 2.0（或主板更换）
评估时：当前指纹 = SHA256("2.0"   | "20250101…" | "MB-001") ≠ 记录指纹
                     ↓
     ① 删除 verification.json（旧记录作废）
     ② 人工核验表 Reset（五项回 Pending）
     ③ 报告/UI 明示"固件已变化，核验记录自动失效，需重新人工核验"
     ④ 等级回落"需人工核验"——直到管理员重新现场核验
```

### 3.4 自动/人工边界（威胁模型视角）

- **自动可判定**：Secure Boot（OS 可读注册表投影）、固件模式（API）——这两项失守意味着 A3 攻击者（USB/网络启动绕过）的门槛大幅降低，故占自动 50 分权重且设硬规则；
- **必须人工**：BIOS 密码、USB/PXE 启动开关、Boot Order、Boot Menu 属固件设置，OS 内无可靠读取通道——**宁标注"需人工核验"也不猜测**（对应验收②），与第 12 周多品牌 BIOS 兼容矩阵衔接；
- **BitLocker 边界**：V7.0 不使用、不检测、不依赖 BitLocker/TPM——启动安全防线是"Secure Boot + USB/PXE 禁用 + 进程管控"，全盘加密属学校镜像管理范畴；系统若启用 BitLocker 与本模块正交运行（模型注释 + 报告页脚 + 交付文档三处声明）。

---

## 四、测试报告

### 4.1 第 11 周新增测试（33 项，Winknow.DeviceSecurity.Tests）

| 分组 | 测试数 | 关键用例 |
|------|--------|----------|
| 评分器 | 8 | 全 Pass=100/Secure；**Score=ΣPass 权重逐项可追溯**；**90 分但含 Pending → 需人工核验**（不显示为通过）；SecureBoot Fail 70 分 → 高风险（硬规则压过阈值）；USB Boot Fail 85 分 → 高风险；85/84/70/69 阈值边界；整改建议按权重降序含待核验项；人工定义 5 项权重和 50 |
| 核验表与记录 | 13 | 默认全 Pending；SetResult 持久化跨实例；拒绝 Pending/未知 Id/空管理员；Reset 持久化复位；指纹相同信息稳定；**BIOS 升级/日期变化/主板更换三组 Theory 均改变指纹**；指纹格式 32hex；记录往返；无记录 IsCurrent=null；指纹匹配=true；**BIOS 更新 → 记录删除+核验表重置**；指纹匹配 → 核验表保留 |
| 报告与门面 | 12 | SecureBoot 三态映射（Unknown→Pending）；真实注册表烟测不抛异常；分区表 GPT/MBR/Unknown Theory；Markdown 含全部五节+**BitLocker 边界**+需人工核验文案+50/100 评分展示；CSV 表头+行数+逗号转义；WriteFiles 双文件+UTF-8 BOM 字节断言；**Assessor 真机全流程**（7 项权重和 100、未核验等级需人工核验、人工项 5 Pending）；核验后 Assess 显示 VerificationCurrent=true 且人工项全 Pass；SaveVerification 拒绝 Pending 结论 |

### 4.2 全量回归测试

| 测试项目 | 测试数 | 通过 |
|----------|--------|------|
| Winknow.Architecture.Tests | 19 | 19 |
| Winknow.Core.Tests | 19 | 19 |
| Winknow.Ipc.Tests | 21 | 21 |
| Winknow.Policy.Tests | 14 | 14 |
| Winknow.ProcessControl.Tests | 45 | 45 |
| Winknow.Security.Tests | 123 | 123 |
| Winknow.TrustedUpdater.Tests | 60 | 60 |
| Winknow.Network.Tests | 64 | 64 |
| Winknow.Guard.Tests | 58 | 58 |
| **Winknow.DeviceSecurity.Tests（本周新增）** | **33** | **33** |
| **全量合计** | **456** | **456** |

### 4.3 构建验证

- **配置**：Release | **目标框架**：net8.0-windows | **警告/错误**：0 / 0
- **架构约束**：`ProductionProjects_ShouldBeFourteen` 通过（14 生产项目不变）
- **真机集成**：Assessor 集成测试在开发机真实执行 WMI/注册表/GetFirmwareType 调用（非 mock），验证采集器容错语义

### 4.4 测试设计说明

- 评分/核验/失效为纯逻辑，直接构造模型断言；采集器走真实系统接口做烟测（断言"不抛异常+返回合法结构"，不绑定具体硬件值——测试机 BIOS 各异）；
- 变化失效用 Theory 覆盖指纹三要素的独立变化，等价模拟 BIOS 升级与主板更换两类事件；
- CSV BOM 用字节级断言（0xEF 0xBB 0xBF），杜绝 Excel 打开乱码回归；
- AdminUI 交互（WPF）不纳入单元测试，依赖代码审查与后续人工验收（遗留事项）。

---

## 五、验收项达成情况

| 验收项 | 状态 | 证据 |
|--------|------|------|
| Secure Boot 状态读取正确 | ✅ 达成 | `SecureBootDetector.Detect`（注册表 State）+ `SecureBoot_Evaluate_Mapping` 三态映射 + 真机烟测 `SecureBoot_Detect_NeverThrows`；Disabled 带整改建议 |
| 无法自动检测的项目显示"需人工核验"，不显示为通过 | ✅ 达成 | 五项固件项默认 `Pending`；`AnyPending_GradeIsNeedsManualReview_EvenWithHighScore`：90 分仍判"需人工核验"；Unknown 的 Secure Boot 同样映射 Pending 而非猜测；UI/DataGrid/MD/CSV 四处均显示"需人工核验"文案 |
| 设备评分可追溯到原始检查项 | ✅ 达成 | `Score = Σ(Pass 权重)`（`Score_EqualsSumOfPassedWeights_Traceable`）；MD 报告第三节逐项表格（# / 检查项 / 类别 / 权重 / 状态 / 详情）；UI DataGrid 同构展示 |
| BIOS 更新后旧核验记录自动失效 | ✅ 达成 | 固件指纹三要素任一变化即失效：`Verification_BiosUpdate_InvalidatesRecord_AndResetsChecklist` + 指纹 Theory 三组；失效动作=删记录+核验表重置+UI/报告明示原因 |
| 文档明确 V7.0 不使用 BitLocker 的边界 | ✅ 达成 | 三处声明：Models 模块注释（API 文档）、每份导出报告固定页脚 `BitLockerBoundaryNote`（有测试断言）、本交付文档 3.4 节 |

---

## 六、修改记录

| 提交 | 类型 | 说明 |
|------|------|------|
| `4ad788a` | feat(week11) | DeviceSecurity 与设备部署检查：8 组件 + AdminUI Tab 页 + 33 项测试；20 文件变更，2243 行新增，17 行删除 |

### 6.1 本次实现细节

1. **Pending 语义优先于分数**：等级计算在分数之前先判 Pending——评分是"已核验部分的得分"，等级是"能否信任的结论"，两者分离避免"高分假安全"；UI 上分数照常展示但等级与颜色明确标注不完整。
2. **硬规则压过阈值**：secure-boot/usb-boot 任一 Fail 直接至少高风险（威胁模型 A3 外部启动主通道），防止"低权重项失分但总分仍 85+"的误判——测试 `UsbBootFail_ForcesHighRisk` 固定该语义。
3. **指纹三要素**：BIOS 版本+发布日期+主板序列号——只看版本会漏掉"同版本降级刷写"，只看序列号会漏掉 BIOS 更新，三者任一变化均触发失效。
4. **逐项核验支持**：`SaveVerification` 接受部分结果（管理员可分多次核验），核验记录每次保存全量清单快照——最后完成的记录天然完整；拒绝 Pending 条目防止"未核验被当作已核验"写入。
5. **采集器永不抛异常**：课堂设备 WMI 实现质量参差（部分厂商 SMBIOS 不全），单项失败降级 "Unknown" 并在详情中如实展示，而非评估流程崩溃。
6. **分区表判定独立成纯函数**：`DeterminePartitionStyle` 与 WMI 解析分离，规则（"GPT:" 前缀）可 Theory 直测。
7. **AdminUI 核验闭环**：记录核验后立即重新 `Assess`（而非本地改状态）——评分/等级/核验状态全部走同一评估管线，UI 永远只是渲染层。

### 6.2 编译与测试修复记录

| 问题 | 修复 |
|------|------|
| Models.cs 双 namespace 声明（文件级 + 块级并存） | 删除块级声明及其闭合括号 |
| Assessor 缺 `using Winknow.Core.Results`（CS0103 ErrorCode） | 补 using |
| 评分器硬规则绕圈写法（`Definitions.First(...).Id` 取常量） | 提取 `CheckUsbBoot` 常量 + `is ... or` 模式匹配 |
| XAML 属性值内英文双引号（MC3000） | 改用『』中文括号表述 |
| WinForms FolderBrowserDialog 需额外引用 | 改用 WPF 原生 SaveFileDialog（导出目录取自所选文件路径） |
| AdminUI 强制 XML 文档注释，CheckRow 属性 8 处 CS1591 | 逐属性补注释 |
| 测试断言错误：未核验时人工 Pending 项应为 5 却写 2 | 修正为 5（与权重模型一致） |

---

## 七、依赖与约束

### 7.1 项目依赖（本周新增边）

- `Winknow.AdminUI` → `Winknow.DeviceSecurity`（页面集成；DeviceSecurity 仅依赖 Core，链条干净）
- `Winknow.DeviceSecurity` → 新增 NuGet `System.Management`（WMI，与 ControlService 的 WmiMonitor 同源依赖）
- `Winknow.DeviceSecurity.Tests` → Core + DeviceSecurity

### 7.2 硬约束遵循

- ✅ 生产项目数保持 14（新组件全部归入 Winknow.DeviceSecurity）
- ✅ TargetFramework = net8.0-windows（GetFirmwareType 自 Win8 起可用）
- ✅ 复用 `Result`/`ErrorCode`（ExternalError/InvalidParameter）与 `Constants` 收敛（新增 DeviceSecurity 节）
- ✅ AdminUI 页面按计划分散开发（第 11 周 1.5 天，无独立周占用）

---

## 八、遗留事项与后续建议

| 事项 | 说明 | 建议处理时机 |
|------|------|-------------|
| 多品牌 BIOS 兼容矩阵 | 五项人工核验项在不同品牌（联想/戴尔/惠普/华硕等）BIOS 中的路径差异与操作手册 | 第 12 周主任务（本模块的五项 Id 已为矩阵预留锚点） |
| AdminUI 人工验收 | WPF 页面交互（核验操作/导出/渲染）未纳入自动化测试 | 第 12/13 周部署测试时人工走查留档 |
| 评分上报/集中管理 | 当前报告仅本机导出；多机房集中查看需 ControlService/IPC 上报通道 | 基础版不做，V7.1 评估（计划书范围外） |
| 核验提醒联动 | 固件变化失效后仅 UI/报告提示；未联动 ControlService 告警事件 | 第 13 周综合测试时评估是否接入事件锚点 |
| 自动项扩充 | TPM 在位/安全模式启动项等更多自动检测 | 第 12 周随兼容矩阵评估，注意不越 BitLocker 边界 |

---

## 九、参考资料

- [编程课堂电脑管控系统V7.0_基础版开发计划书.md](file:///c:/Users/rr/Documents/trae_projects/winknow/docs/编程课堂电脑管控系统V7.0_基础版开发计划书.md) — 第 11 周计划（DeviceSecurity 与设备部署检查）+ AdminUI 开发分布表
- [第10周交付文档_守护增强重启限流与可信恢复.md](file:///c:/Users/rr/Documents/trae_projects/winknow/docs/第10周交付文档_守护增强重启限流与可信恢复.md) — 前周交付（守护/恢复，本周设备模块与其正交）
- Win32_BIOS / Win32_BaseBoard / Win32_BootPartition（WMI 文档）、GetFirmwareType（kernel32）、Secure Boot 注册表投影（HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State）— 实现依据
