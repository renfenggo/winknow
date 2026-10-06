using System.Security.Principal;
using Winknow.Core;
using Winknow.DesktopBridge;
using Winknow.Ipc;
using Winknow.Ipc.Protocol;
using Winknow.Ipc.Session;

// DesktopBridge：Flutter 与 ControlService 之间的唯一通道（ADR-002）。
// 协议：stdin 每行一个请求 JSON，stdout 每行一个响应 JSON；日志只写 stderr。
var pipeName = IpcConstants.ControlPipeName;
var deviceId = DeviceId.Generate();
var capabilities = new[] { "status.read", "device.read", "runner.read", "runner.execute" };
var sessionId = Guid.NewGuid().ToString("N");
var componentVersion = "0.1.0";

for (var i = 0; i < args.Length - 1; i++)
{
    switch (args[i])
    {
        case "--pipe":
            pipeName = args[i + 1];
            break;
        case "--device":
            deviceId = args[i + 1];
            break;
        case "--capabilities":
            capabilities = args[i + 1].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            break;
        case "--session":
            sessionId = args[i + 1];
            break;
        case "--version":
            componentVersion = args[i + 1];
            break;
        default:
            continue;
    }
}

var callerSid = WindowsIdentity.GetCurrent().User?.Value ?? string.Empty;

var handshake = new HandshakeParams
{
    ProtocolVersion = ProtocolVersion.Current.ToString(),
    Component = "bridge",
    ComponentVersion = componentVersion,
    Capabilities = capabilities,
    DeviceId = deviceId,
    CallerSid = callerSid,
    SessionId = sessionId,
};

await using var connection = new BridgeConnection(pipeName, handshake);
Console.Error.WriteLine(
    "bridge ready: pipe={0} device={1} sid={2} session={3}",
    pipeName, deviceId, callerSid, sessionId);

await BridgeLineProtocol.RunAsync(Console.In, Console.Out, connection.InvokeAsync, CancellationToken.None);
Console.Error.WriteLine("bridge stdin closed, exiting.");
return 0;
