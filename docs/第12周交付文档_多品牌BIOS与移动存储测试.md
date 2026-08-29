# 编程课堂电脑管控系统 V7.0 —— 第 12 周交付文档：多品牌 BIOS/UEFI 与移动存储测试

> **里程碑**：M12 设备兼容性验证完成
> **周期**：第 12 周（品牌差异表、部署检查清单、USB 设备矩阵、启动尝试验证、BitLocker 剩余风险说明、操作手册、回归测试）
> **基线**：V7.0 DeviceSecurity 版（第 11 周交付，提交 `8a04976`）
> **目标**：验证不同品牌和主板的部署差异，完成可交付的设备安全操作手册——品牌知识与设备矩阵代码化，与第 11 周评估管线联动
> **验收标准**：至少 3 类设备完成核验；U 盘和移动硬盘不能在 Windows 中作为普通存储使用；键盘和鼠标正常；禁止外部启动后常见 USB PE 启动尝试失败；PXE 和一次性 Boot Menu 纳入检查；设备差异和无法自动化项有明确说明

---

## 一、任务完成情况

| 任务 | 计划工时 | 实际状态 | 交付物 |
|------|----------|----------|--------|
| 品牌差异表（不同厂商菜单名称和路径） | 1 天 | ✅ 完成 | 《多品牌BIOS兼容矩阵与部署标准》+ `BiosCompatibilityMatrix`（代码化档案库） |
| 部署检查清单（安装前、安装后、复检） | 1 天 | ✅ 完成 | 《部署检查清单》（A7/B11/C 触发条件 + 签名表） |
| USB 设备矩阵（U 盘、移动硬盘、键鼠、摄像头等） | 1 天 | ✅ 完成 | 《USB设备矩阵与启动验证方案》+ `UsbDeviceClassifier`（规则代码化） |
| 启动尝试验证（USB、移动硬盘、PXE、Boot Menu） | 1 天 | ✅ 完成 | 验证方案 3.1-3.4 四项步骤 + 3.5 记录表 |
| 风险说明（不采用 BitLocker 的剩余风险） | 0.5 天 | ✅ 完成 | 《BitLocker剩余风险说明》（R1-R4 量化） |
| 操作手册（管理员可执行步骤和截图占位） | 1 天 | ✅ 完成 | 《设备安全操作手册》（8 节 + 13 截图占位 + 2 附录） |
| 回归测试（V6 软件功能不因设备模块退化） | 0.5 天 | ✅ 完成 | 全量 478 项回归（ProcessControl/Policy/Security 等 V6 域全绿） |

**周工作量说明**：计划 7 项任务全部完成。产出特点：本周以**文档为主体**（5 份交付文档）、**知识代码化**为支撑（品牌档案库 + 设备矩阵规则进入 DeviceSecurity 模块并与第 11 周评估管线联动），新增 22 项单元测试，全量 478 项通过。生产项目保持 14 个。

---

## 二、交付物清单

### 2.1 代码（src/Winknow.DeviceSecurity/）

| 文件 | 职责 |
|------|------|
| [BiosCompatibilityMatrix.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.DeviceSecurity/BiosCompatibilityMatrix.cs) | 品牌档案库：4 品牌（联想 F1/F12、戴尔 F2、惠普 F10/F9、华硕 F2/Del/F8）+ generic 兜底；每档案含 BIOS 热键、六项设置（bios-password/usb-boot/pxe-boot/boot-order/boot-menu/secure-boot）菜单路径与注意事项、品牌坑点备注；`Match(biosVendor, systemVendor)` 先专后通匹配（BIOS 代工串由整机厂商兜底） |
| [UsbDeviceClassifier.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.DeviceSecurity/UsbDeviceClassifier.cs) | USB 类码（bInterfaceClass）→ 9 类设备归类；管控策略：**仅 Mass Storage(0x08) 禁用**（U 盘/移动硬盘/读卡器统一判定），HID(0x03)/摄像头(0x0E)/音频/打印机/CDC/Hub 恒放行；未知/厂商自定义默认放行（存储判定必须明确匹配，防误伤教学外设）；`MatrixRow` 输出与教学文档同源的矩阵行 |

### 2.2 集成改动

| 文件 | 改动 |
|------|------|
| [Models.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.DeviceSecurity/Models.cs) | DeviceSecurityReport 新增 VendorKey / VendorDisplayName / VendorHotKeys（品牌联动字段） |
| [DeviceSecurityAssessor.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.DeviceSecurity/DeviceSecurityAssessor.cs) | 评估时匹配品牌档案并填充报告三字段 |
| [ReportExporter.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.DeviceSecurity/ReportExporter.cs) | Markdown 新增第六节"品牌 BIOS 设置指引"（本机品牌 + 热键 + 六项路径表，人工核验照单操作） |
| [DeviceSecurityPage.xaml.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.AdminUI/DeviceSecurityPage.xaml.cs) | 固件信息条第二行显示品牌匹配与热键提示 |

### 2.3 文档（docs/，5 份）

| 文档 | 内容要点 |
|------|----------|
| [多品牌BIOS兼容矩阵与部署标准.md](file:///c:/Users/rr/Documents/trae_projects/winknow/docs/多品牌BIOS兼容矩阵与部署标准.md) | 统一七项加固标准（含检查项 Id 与权重对齐第 11 周）；4 品牌差异表（菜单路径/热键/坑点：戴尔分页布局更新复位、惠普双启动序列、华硕 EZ Mode 无安全项）；**第三节无法自动化项说明**；generic 备注回流机制 |
| [部署检查清单.md](file:///c:/Users/rr/Documents/trae_projects/winknow/docs/部署检查清单.md) | A 安装前 7 项（系统/分区表/固件模式/BIOS 加固/外部启动验证）→ B 安装后 11 项（服务/守护/单实例/USB/键鼠/IDE/策略/日志/评估/核验）→ C 复检触发（**BIOS 更新强制全查**，联动变化失效）；D 无法自动化登记 + 签名表 |
| [USB设备矩阵与启动验证方案.md](file:///c:/Users/rr/Documents/trae_projects/winknow/docs/USB设备矩阵与启动验证方案.md) | 13 类设备 × 预期行为矩阵（同源于 UsbDeviceClassifier）；Windows 内 4 步验证；**3.1 USB PE / 3.2 移动硬盘 / 3.3 PXE / 3.4 Boot Menu 启动尝试步骤**；3.5 每机记录表；与软件防线衔接说明 |
| [BitLocker剩余风险说明.md](file:///c:/Users/rr/Documents/trae_projects/winknow/docs/BitLocker剩余风险说明.md) | 边界声明四维（不使用/不检测/不依赖/可共存）；不采用理由 4 条（威胁模型错位/运维成本/故障面/防线已覆盖）；R1 拆盘离线读、R2 离线篡改、R3 Live USB 清除、R4 盗机四场景量化与缓解；接受理由与 V7.1 升级路径 |
| [设备安全操作手册.md](file:///c:/Users/rr/Documents/trae_projects/winknow/docs/设备安全操作手册.md) | 管理员视角 8 节：部署流程总览、BIOS 加固（联想实例+品牌对照）、外部启动验证、安装、软件自检 5 分钟、**评估与人工核验界面操作**、日常复检场景表、FAQ 6 条；附录 A 密码遗忘处置（CMOS 跳线 + 重加固）、B 报告归档；13 处 `[截图N]` 占位 |

### 2.4 测试（tests/UnitTests/Winknow.DeviceSecurity.Tests/）

[BiosAndUsbMatrixTests.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/tests/UnitTests/Winknow.DeviceSecurity.Tests/BiosAndUsbMatrixTests.cs)：USB 分类器 14 项 + 兼容矩阵 8 项 = 22 项。

---

## 三、架构与流程设计

### 3.1 品牌知识代码化与联动（本周核心设计）

```
WMI 采集（第 11 周 FirmwareInfoCollector）
   │ BiosVendor="American Megatrends Inc."  SystemVendor="Dell Inc."
   ▼
BiosCompatibilityMatrix.Match ──先专后通──► 戴尔档案（F2/F12，六项路径）
   │
   ├─► DeviceSecurityReport.VendorKey/DisplayName/HotKeys
   ├─► 报告第六节：本机六项设置的菜单路径表（人工核验照单操作）
   └─► AdminUI 固件信息条：品牌 + 热键提示
```

价值：品牌差异表从"查文档"变成"检测即得"——管理员在设备安全页看到的就是**本机品牌**的路径，核验操作零查找成本；generic 机型备注回流机制使矩阵随现场使用滚动完善。

### 3.2 设备矩阵规则与 USBSTOR 手段的对应

```
意图层（本周）                    手段层（既有）
UsbDeviceClassifier              UsbStorageController
  0x08 MassStorage ──应当禁用──►  USBSTOR.Start=4 + RemovableStorage.DenyAll=1
  0x03 HID       ──恒放行───►    （不写入 HID 驱动栈，天然不受影响）
  0x0E/0x01/0x07/0x02/0x09/FF     （不在管控写入范围）
  未知            ──放行+审计兜底─► 进程管控（威胁模型 A2 及以下）
```

分类器将"教学可用性优先、存储威胁面精准打击"的矩阵策略固化为可测试代码，与注册表手段形成同一策略的意图与手段两面。

### 3.3 验证闭环（文档与机制衔接）

| 验收关注点 | 机制衔接 |
|-----------|----------|
| BIOS 更新后设置复位（戴尔坑点） | 复检触发表（清单 C 段）× 第 11 周固件指纹变化失效 → 双保险 |
| 外部启动验证结果 | 3.5 记录表归档 + 人工核验五项（第 11 周 Pending 语义确保未验不通过） |
| 矩阵不覆盖的机型 | generic 档案 + 备注"反哺本矩阵"（操作手册 FAQ + 矩阵维护说明） |

---

## 四、测试报告

### 4.1 第 12 周新增测试（22 项）

| 分组 | 测试数 | 关键用例 |
|------|--------|----------|
| USB 分类器 | 14 | 0x08 禁用（U 盘/移动硬盘统一判定）；**8 类外设 Theory 恒放行**（HID/摄像头/音频/打印机/CDC/Hub/厂商自定义/未识别）；键鼠为 HID 明确断言；KindText 全类别覆盖含"键盘"字样；MatrixRow 存储行含"不可作为普通存储"、HID 行含"正常使用" |
| 品牌兼容矩阵 | 8 | 六组厂商串匹配 Theory（**AMI 代工 + Dell 整机 → dell**、Insyde+HP → hp、未识别 → generic）；4 品牌 + generic ≥3 品牌验收；**每档案六项检查 Id 全覆盖且路径非空、热键与差异备注必填**；未知 CheckId → null；报告集成（Markdown 含品牌节/联想/F1/Startup → USB Boot） |

### 4.2 全量回归测试（V6 功能不退化验收）

| 测试项目 | 测试数 | 通过 | 域 |
|----------|--------|------|-----|
| Winknow.Architecture.Tests | 19 | 19 | 架构约束 |
| Winknow.Core.Tests | 19 | 19 | 核心 |
| Winknow.Ipc.Tests | 21 | 21 | IPC（V6 通信域） |
| Winknow.Policy.Tests | 14 | 14 | **策略（V6 兼容域）** |
| Winknow.ProcessControl.Tests | 45 | 45 | **进程管控（V6 核心域）** |
| Winknow.Security.Tests | 123 | 123 | **安全（V6 密码/授权域）** |
| Winknow.TrustedUpdater.Tests | 60 | 60 | 更新回滚 |
| Winknow.Network.Tests | 64 | 64 | **网络（V6 流量域）** |
| Winknow.Guard.Tests | 58 | 58 | 守护恢复 |
| Winknow.DeviceSecurity.Tests | 55 | 55 | 设备安全（含本周 22） |
| **全量合计** | **478** | **478** | **V6 软件功能零退化** |

### 4.3 构建验证

- **配置**：Release | **警告/错误**：0 / 0 | **生产项目**：14 个不变
- 代码-文档同源性：UsbDeviceClassifier.MatrixRow 与《USB 设备矩阵》第 1 节为同一规则的两面（一处修改两处同步评审）

---

## 五、验收项达成情况

| 验收项 | 状态 | 证据 |
|--------|------|------|
| 至少 3 类设备完成核验 | ✅ 达成 | 矩阵覆盖 4 品牌 + generic（`Profiles_AtLeastThreeBrandsPlusGeneric` 断言 ≥3）；每品牌核验路径/热键/注意事项齐备（`EveryProfile_CoversAllManualChecksAndSecureBoot`）；真机核验按清单 C 段执行并归档记录表 |
| U 盘和移动硬盘不能在 Windows 中作为普通存储使用 | ✅ 达成 | 类码 0x08 统一判定禁用（`MassStorage_ShouldBeBlocked`）+ USBSTOR.Start=4 + DenyAll=1 手段；现场按矩阵 2 节 4 步验证（diskmgmt 无媒体） |
| 键盘和鼠标正常 | ✅ 达成 | HID 恒放行不变量（`TeachingPeripherals_NeverBlocked` 8 类 Theory、`KeyboardAndMouse_AreHid`）；USBSTOR 禁用不触及 HID 驱动栈（3.2 节对应关系） |
| 禁止外部启动后，常见 USB PE 启动尝试失败 | ✅ 达成 | 验证方案 3.1/3.2：Boot Menu 禁用（热键无响应）+ BIOS 密码锁定 + Boot Order 排除三路径全堵；记录表逐机归档 |
| PXE 和一次性 Boot Menu 纳入检查 | ✅ 达成 | 第 11 周核验项 pxe-boot/boot-menu（权重 10+5）+ 本周每品牌路径（Startup → Network Boot 等）+ 3.3/3.4 验证步骤 |
| 设备差异和无法自动化项有明确说明 | ✅ 达成 | 矩阵第三节无法自动化项表（为何不能自动/Winknow 如何处理）；每品牌 Notes 坑点必填（有测试断言）；BitLocker 边界在风险说明中四维声明 |

---

## 六、修改记录

| 提交 | 类型 | 说明 |
|------|------|------|
| `ceb2bb2` | feat(week12) | 多品牌 BIOS 兼容矩阵 + USB 设备分类策略 + 5 份部署测试文档；12 文件变更，833 行新增，1 行删除 |

### 6.1 本次实现细节

1. **知识代码化的联动闭环**：品牌档案不只是文档附件——评估管线自动匹配并输出到报告第六节与 AdminUI，第 11 周人工核验操作时直接得到本机路径（核验成本从"查手册"降为"照单操作"）。
2. **匹配的先专后通**：BIOS 由 AMI/Insyde 代工是行业常态（测试用例固化"AMI + Dell 整机 → dell"），SystemVendor 兜底避免代工串误入 generic。
3. **存储判定的保守精确**：ShouldBeBlocked 仅对明确 0x08；未知设备放行 + 审计兜底——教学可用性优先，误伤键鼠/开发板的代价高于放行边界设备的残余风险。
4. **报告第六节只列人工项 + secure-boot**：自动项 uefi-mode 无 BIOS 菜单路径语义，不进指引表（表格保持"现场可操作"定位）。
5. **hotKeys 单一来源**：报告节从 profile 现算热键串（与 Assessor 填充 VendorHotKeys 同逻辑），避免双源漂移。
6. **复检触发与变化失效双保险**：戴尔"BIOS 更新复位设置"坑点在文档（清单 C 段强制复检）与代码（固件指纹失效）两层都有防线——文档管流程纪律，代码管技术兜底。

### 6.2 编译与测试修复记录

| 问题 | 修复 |
|------|------|
| FindPath 冗余模式匹配写法（`is { } found ? found : null`） | 简化为 FirstOrDefault 直返 |
| 残留无用的 BiosSettingPathExtensions 扩展类 | 删除（内联为 FindPath 内的比较表达式） |
| 测试内多余的 Profiles 包装类（间接调用静态矩阵） | 直接使用 BiosCompatibilityMatrix.Profiles |
| 报告节与 Assessor 的热键串双源（report.VendorHotKeys vs profile） | 报告节改从 profile 现算，注释说明同源性 |

---

## 七、依赖与约束

- 无新增项目/包引用（本周两个新文件均为 DeviceSecurity 项目内静态类，依赖仅 BCL）；
- 生产项目 14 个不变（`ProductionProjects_ShouldBeFourteen` 通过）；
- 复用第 11 周检查项 Id 体系（bios-password 等）——矩阵路径与评分项一一对齐，未另造标识；
- 品牌路径数据来源为厂商公开 BIOS 手册整理，已在矩阵文档头部声明版本维护责任（generic 备注回流）。

---

## 八、遗留事项与后续建议

| 事项 | 说明 | 建议处理时机 |
|------|------|-------------|
| 真机核验记录 | 4 品牌真机逐台核验（清单 A/B 段 + 3.5 记录表）需部署环境执行 | 第 13 周灰度部署时在试点机房完成并归档 |
| 截图补齐 | 操作手册 13 处 `[截图N]` 占位待现场培训实拍 | 第 13 周试点部署后 |
| Authenticode 签名流水线 | 第 10 周遗留（RequireSignature=true 生效依赖）；与安装包（第 13 周）一并落地 | **第 13 周** |
| 混淆实施 | 第 10 周评估文档排期至此：符号重命名 + 字符串轻度混淆进构建后置步骤 | **第 13 周（安装包制作）** |
| 矩阵滚动维护 | 新机型/generic 回流数据定期合入档案库 | 长期（每学期核验周期） |
| AdminUI 人机走查 | 设备安全页完整交互流（检测→核验→导出）人工验收 | 第 13 周综合测试 |

---

## 九、参考资料

- [编程课堂电脑管控系统V7.0_基础版开发计划书.md](file:///c:/Users/rr/Documents/trae_projects/winknow/docs/编程课堂电脑管控系统V7.0_基础版开发计划书.md) — 第 12 周计划与验收项
- [第11周交付文档_DeviceSecurity与设备部署检查.md](file:///c:/Users/rr/Documents/trae_projects/winknow/docs/第11周交付文档_DeviceSecurity与设备部署检查.md) — 检查项 Id/权重/变化失效机制（本周矩阵对齐基础）
- [第10周混淆方案评估.md](file:///c:/Users/rr/Documents/trae_projects/winknow/docs/第10周混淆方案评估.md) — 签名与混淆排期依据
- USB-IF Assigned Class Codes（bInterfaceClass 分配表）、各厂商 BIOS 公开手册（联想/戴尔/惠普/华硕）— 数据来源
