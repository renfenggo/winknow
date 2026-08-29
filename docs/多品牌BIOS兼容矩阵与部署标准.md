# 多品牌 BIOS/UEFI 兼容矩阵与部署标准

> V7.0 第 12 周交付 | 配套代码：[BiosCompatibilityMatrix.cs](file:///c:/Users/rr/Documents/trae_projects/winknow/src/Winknow.DeviceSecurity/BiosCompatibilityMatrix.cs)
> 适用：机房批量部署 Winknow 前的 BIOS/UEFI 加固标准
> 数据来源：各厂商公开 BIOS 手册（联想 ThinkCentre/启天、戴尔 OptiPlex、惠普 ProDesk/EliteDesk、华硕商用台式）路径整理；**具体机型以随机手册为准，发现差异请反哺本矩阵（generic 档案备注栏）**

---

## 一、统一部署标准（全品牌目标态）

无论品牌，部署完成后的 BIOS 必须满足：

| # | 设置项 | 目标态 | Winknow 检查项 Id | 权重 |
|---|--------|--------|-------------------|------|
| 1 | BIOS/UEFI 管理员密码 | 已设置 | bios-password | 15 |
| 2 | USB 存储启动 | 禁用 | usb-boot | 15 |
| 3 | PXE/网络启动 | 禁用 | pxe-boot | 10 |
| 4 | Boot Order 首位 | 内置系统盘 | boot-order | 5 |
| 5 | 一次性 Boot Menu | 禁用 | boot-menu | 5 |
| 6 | Secure Boot | 启用（UEFI 模式） | secure-boot（自动） | 30 |
| 7 | 固件启动模式 | UEFI（非 Legacy） | uefi-mode（自动） | 20 |

## 二、品牌差异表（菜单名称与路径）

### 2.1 联想（ThinkCentre / 启天 / 扬天）

| 项目 | 路径 |
|------|------|
| 进入 BIOS | 开机 **F1**（启动菜单 **F12**） |
| 管理员密码 | Security → Administrator Password |
| USB 启动 | Startup → **USB Boot → Disabled** |
| PXE | Startup → **Network Boot → Disabled** |
| Boot Order | Startup → Boot：内置 HDD/SSD 调首位（Excluded 列表移除外设） |
| Boot Menu | Startup → **Boot Menu → Disabled**（F12 菜单关闭） |
| Secure Boot | Security → Secure Boot → Enabled（需先切换 UEFI） |

**差异备注**：教学机型常见 F1/F12 组合；部分启天机型为精简 BIOS，路径以随机手册为准。

### 2.2 戴尔（OptiPlex 系列）

| 项目 | 路径 |
|------|------|
| 进入 BIOS | 开机 **F2**（一次性启动菜单 **F12**） |
| 管理员密码 | Security → **System Password 与 Setup Password 都设置**（Setup Password 才限制 BIOS 修改） |
| USB 启动 | Boot Configuration → Boot Sequence：取消 USB Storage Device |
| PXE | Boot Configuration → Boot Sequence：取消 Onboard NIC/PXE |
| Boot Order | Boot Configuration → Boot Sequence：仅勾选内部硬盘 |
| Boot Menu | Boot Sequence 项内控制（One Time Boot 由 F12 触发，可在 BIOS 关闭） |
| Secure Boot | Secure Boot → Secure Boot Enable → Enabled |

**差异备注**：新版 OptiPlex BIOS 为**分页布局**（旧版树形）；**BIOS 更新后个别设置项会复位，更新后必须复检**（对应第 11 周变化失效机制）。

### 2.3 惠普（ProDesk / EliteDesk 系列）

| 项目 | 路径 |
|------|------|
| 进入 BIOS | 开机 **F10**（一次性启动菜单 **F9**） |
| 管理员密码 | Security → Administrator Password（注意 Power-On Password 联动选项） |
| USB 启动 | Advanced → Boot Options → **取消 USB Storage Boot** |
| PXE | Advanced → Boot Options → **取消 Network (PXE) Boot** |
| Boot Order | Advanced → Boot Order（**Legacy 与 UEFI 两列独立维护，都要核验**） |
| Boot Menu | Advanced → Boot Options → **取消 One-Time Boot Menu**（F9） |
| Secure Boot | Advanced → Secure Boot Configuration → Secure Boot → Enable |

**差异备注**：双启动顺序独立维护是惠普最大坑点；BIOS 密码遗忘需主板跳线清除——机房保留处置流程（见操作手册附录）。

### 2.4 华硕（商用台式 / 零售主板）

| 项目 | 路径 |
|------|------|
| 进入 BIOS | 开机 **F2 或 Del**（启动菜单 **F8**） |
| 管理员密码 | Advanced Mode（**F7** 切换）→ Security → Administrator Password |
| USB 启动 | Advanced Mode → Boot → Boot Configuration → USB Boot 控制 |
| PXE | Advanced Mode → Boot → Network Stack Configuration → 关闭 Network Stack |
| Boot Order | Advanced Mode → Boot → Boot Option Priorities → Boot Option #1 为内置盘 |
| Boot Menu | Boot Configuration 中 Boot Menu（F8）按机型支持情况 |
| Secure Boot | Advanced Mode → Boot → Secure Boot → OS Type = Windows UEFI |

**差异备注**：EZ Mode 无安全设置项，**必须 F7 进 Advanced Mode**；零售主板无统一 Boot Menu 开关，靠 Boot Option Priorities 排除兜底。

### 2.5 未识别机型（generic 兜底档案）

BIOS 由 AMI/Insyde/Phoenix 代工的品牌机与组装机：按上表通用路径（Security/Boot 菜单）定位同名设置；核验完成后在 Winknow 备注中登记机型与实际路径，反哺矩阵。

## 三、无法自动化项说明（验收项）

| 项目 | 为什么不能自动 | Winknow 处理 |
|------|----------------|--------------|
| BIOS 密码 | 固件内状态 OS 不可读 | 人工核验（Pending，不显示为通过） |
| USB/PXE/Boot Order/Boot Menu | 固件设置 OS 不可读 | 人工核验（同上） |
| Secure Boot | 注册表可读投影 | 自动检测（State 值）；不可读时降级人工 |
| UEFI/Legacy | GetFirmwareType API | 自动检测 |
| USB PE 实际启动尝试 | 需物理插入介质重启 | 现场验证（见《USB设备矩阵与启动验证方案》） |

## 四、矩阵与软件联动

- `BiosCompatibilityMatrix.Match(biosVendor, systemVendor)`：按 WMI 厂商串匹配档案（BIOS 代工商串由整机厂商兜底）；
- 设备安全报告第六节"品牌 BIOS 设置指引"自动输出当前机型六项设置的路径与注意事项；
- AdminUI 设备安全页显示品牌匹配结果与热键，核验时照单操作。

版本维护：本表随真机核验记录滚动更新（generic 备注回流）；BIOS 大版本更新（如戴尔分页布局切换）需整表复核。
