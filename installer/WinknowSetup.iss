; =====================================================================
; Winknow V7.0 安装脚本（Inno Setup 6.x）
; V7.0 第 13 周：服务安装、权限配置、策略部署、.NET 8 运行时检测
;
; 目录布局（与 DeploymentSlots/PeerVerifier/HeartbeatLease 约定一致）：
;   {autopf}\Winknow            —— AdminUI、TrustedUpdater（更新器常驻副本）
;   {commonappdata}\Winknow     —— 策略、审计库、设备安全数据、心跳
;     └─ deploy\Current         —— 服务运行位置（更新时 TrustedUpdater 切槽）
;     └─ deploy\Previous|Staging
;     └─ device_security\
;
; 使用：先用 Build-Release.ps1 生成 installer\payload，再 ISCC 编译本脚本
; =====================================================================

#define MyAppName "Winknow"
#define MyAppVersion "7.0.0"
#define MyAppPublisher "Winknow Project"
#define MyAppExeName "Winknow.AdminUI.exe"

[Setup]
AppId={{9C1F6B2A-4E3D-4F8A-9B7C-WINKNOWV700}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
PrivilegesRequired=admin
OutputDir=dist
OutputBaseFilename=WinknowSetup-{#MyAppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=no
; 卸载由维护模式授权保护（第 6 周）——脚本层仅提示，授权校验在程序内
Uninstallable=yes

[Languages]
Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"

[Types]
Name: "full"; Description: "完整安装（服务 + 管理控制台 + 更新器）"
Name: "custom"; Description: "自定义"; Flags: iscustom

[Components]
Name: "services"; Description: "管控服务（WinknowControl + WinknowGuard）"; Types: full custom; Flags: fixed
Name: "admin"; Description: "管理控制台（AdminUI）"; Types: full
Name: "updater"; Description: "可信更新器（TrustedUpdater）"; Types: full custom; Flags: fixed

[Files]
; 服务二进制 → deploy\Current（服务从此运行；更新走槽切换）
Source: "payload\services\*"; DestDir: "{commonappdata}\Winknow\deploy\Current"; Components: services; Flags: ignoreversion recursesubdirs
; 更新器 → 安装目录（常驻，不受槽切换影响）
Source: "payload\updater\*"; DestDir: "{app}\Updater"; Components: updater; Flags: ignoreversion recursesubdirs
; 管理控制台
Source: "payload\admin\*"; DestDir: "{app}\AdminUI"; Components: admin; Flags: ignoreversion recursesubdirs
; 默认策略（仅首次安装部署；升级不覆盖机房定制策略）
Source: "payload\policy\default_policy_v7.0.json"; DestDir: "{commonappdata}\Winknow"; DestName: "policy.json"; Flags: onlyifdoesntexist

[Dirs]
; ProgramData 数据目录：BUILTIN\Users 只读（学生不可改策略/审计）
Name: "{commonappdata}\Winknow"; Permissions: users-readexec
Name: "{commonappdata}\Winknow\deploy"; Permissions: users-readexec
Name: "{commonappdata}\Winknow\device_security"; Permissions: users-readexec

[Services]
; ControlService：LocalSystem、开机自启、崩溃自动重启（SCM 第一层）
Name: "WinknowControl"; DisplayName: "Winknow Control Service"; Description: "Winknow V7.0 管控服务（进程/网络/策略）"; \
  Check: InstallServices; Flags: demand start; \
  ; 用 [Run] 段 sc create 精确控制（见下），此处仅声明性占位

[Run]
; 服务安装（LocalSystem + auto + 失败恢复策略——第 6 周 ServiceRecovery 语义）
Filename: "{sys}\sc.exe"; Parameters: "create WinknowControl binPath= ""{commonappdata}\Winknow\deploy\Current\Winknow.ControlService.exe"" start= auto obj= LocalSystem"; Flags: runhidden; StatusMsg: "安装 WinknowControl 服务"
Filename: "{sys}\sc.exe"; Parameters: "failure WinknowControl reset= 86400 actions= restart/5000/restart/10000/restart/30000"; Flags: runhidden; StatusMsg: "配置 WinknowControl 恢复策略"
Filename: "{sys}\sc.exe"; Parameters: "create WinknowGuard binPath= ""{commonappdata}\Winknow\deploy\Current\Winknow.GuardService.exe"" start= auto obj= LocalSystem"; Flags: runhidden; StatusMsg: "安装 WinknowGuard 服务"
Filename: "{sys}\sc.exe"; Parameters: "failure WinknowGuard reset= 86400 actions= restart/5000/restart/10000/restart/30000"; Flags: runhidden; StatusMsg: "配置 WinknowGuard 恢复策略"
; 先起 Guard 后起 Control（Guard 立即进入守护位，Control 起来后租约生效）
Filename: "{sys}\sc.exe"; Parameters: "start WinknowGuard"; Flags: runhidden; StatusMsg: "启动 WinknowGuard"; Check: StartServicesNow
Filename: "{sys}\sc.exe"; Parameters: "start WinknowControl"; Flags: runhidden; StatusMsg: "启动 WinknowControl"; Check: StartServicesNow
; 可信恢复快照（首次安装建立 Vault，供第 10 周自动修复使用）
Filename: "{app}\Updater\Winknow.TrustedUpdater.exe"; Parameters: "snapshot ""{commonappdata}\Winknow\deploy"""; Flags: runhidden; StatusMsg: "建立可信恢复快照"

[UninstallRun]
; 停止并删除服务（到达此处前必须已通过维护模式授权——见 [Code] 提示）
Filename: "{sys}\sc.exe"; Parameters: "stop WinknowGuard"; Flags: runhidden; RunOnceId: "StopGuard"
Filename: "{sys}\sc.exe"; Parameters: "stop WinknowControl"; Flags: runhidden; RunOnceId: "StopControl"
Filename: "{sys}\sc.exe"; Parameters: "delete WinknowGuard"; Flags: runhidden; RunOnceId: "DelGuard"
Filename: "{sys}\sc.exe"; Parameters: "delete WinknowControl"; Flags: runhidden; RunOnceId: "DelControl"

[UninstallDelete]
; 审计数据按保留策略由程序清理；安装器仅移除程序文件
Type: filesandordirs; Name: "{commonappdata}\Winknow\deploy"

[Icons]
Name: "{group}\Winknow 管理控制台"; Filename: "{app}\AdminUI\{#MyAppExeName}"; Components: admin
Name: "{commondesktop}\Winknow 管理控制台"; Filename: "{app}\AdminUI\{#MyAppExeName}"; Components: admin; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加任务："
Name: "startservices"; Description: "安装完成后立即启动服务"; GroupDescription: "附加任务："; Flags: checkedonce

[Code]
const
  // .NET 8 Desktop Runtime：注册表安装标记（x64）
  Net8RegKey = 'SOFTWARE\dotnet\Setup\InstalledVersions\x64\sharedfx\Microsoft.WindowsDesktop.App';
  Net8DownloadUrl = 'https://dotnet.microsoft.com/download/dotnet/8.0';

// .NET 8 运行时检测（注册表 + 文件系统双保险）
function IsNet8DesktopRuntimeInstalled(): Boolean;
var
  version: string;
  runtimeDir: string;
begin
  Result := False;
  // ① 注册表：InstalledVersions 的 sharedfx 版本值 ≥ 8
  if RegQueryStringValue(HKEY_LOCAL_MACHINE, Net8RegKey, 'Version', version) then
    if Pos('8.', version) = 1 then
      Result := True;
  // ② 文件系统：Program Files\dotnet\shared\Microsoft.WindowsDesktop.App 下存在 8.x 目录
  if not Result then
  begin
    runtimeDir := ExpandConstant('{commoncf}\dotnet\shared\Microsoft.WindowsDesktop.App');
    if DirExists(runtimeDir + '\8.0') then
      Result := True;
  end;
end;

function InitializeSetup(): Boolean;
var
  errorCode: Integer;
begin
  Result := True;
  if not IsNet8DesktopRuntimeInstalled() then
  begin
    if MsgBox(
      '未检测到 .NET 8 Desktop Runtime（x64）。' + #13#10 +
      'Winknow 服务与管理控制台依赖该运行时。' + #13#10 + #13#10 +
      '选择「是」打开官方下载页（安装运行时后重新运行本安装包），' + #13#10 +
      '选择「否」继续安装（服务将无法启动）。',
      mbConfirmation, MB_YESNO) = IDYES then
    begin
      ShellExec('open', Net8DownloadUrl, '', '', SW_SHOWNORMAL, ewNoWait, errorCode);
      Result := False; // 引导先装运行时
    end;
  end;
end;

function InstallServices(): Boolean;
begin
  Result := UsingServices; // 声明性占位（实际创建在 [Run] sc.exe）
end;

function StartServicesNow(): Boolean;
begin
  Result := IsTaskSelected('startservices');
end;

// 卸载前置提示：维护模式授权（第 6 周机制在程序内校验；脚本层拦一道）
function InitializeUninstall(): Boolean;
begin
  Result := MsgBox(
    '即将卸载 Winknow V7.0。' + #13#10 + #13#10 +
    '安全要求：请确认已在「Winknow 管理控制台 → 维护模式」完成授权' + #13#10 +
    '（维护密码 + TOTP 双因素），否则管控策略将随卸载解除。' + #13#10 + #13#10 +
    '继续卸载？',
    mbConfirmation, MB_YESNO) = IDYES;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    MsgBox(
      '卸载完成。' + #13#10 + #13#10 +
      '注意：审计数据（{commonappdata}\Winknow\audit.db）与核验记录' + #13#10 +
      '按数据保留策略保留 30 天，需要立即销毁请手动删除该目录。',
      mbInformation, MB_OK);
end;
