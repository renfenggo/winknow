using System.Text;
using System.Text.Json;
using Winknow.Ipc.Protocol;
using Winknow.Ipc.Session;

namespace Winknow.Ipc.Tests;

/// <summary>
/// M2-2 连接期握手校验器测试（ADR-001：首帧必须是 handshake；不兼容显式拒绝断连）。
/// </summary>
public sealed class IpcHandshakeValidatorTests
{
    private const string Sid = "S-1-5-21-3623811015-3361044348-30300820-1013";
    private const string DeviceId = "0123456789abcdef0123456789abcdef";

    private static IpcHandshakeValidator CreateValidator(
        ProtocolVersion? protocol = null,
        string? deviceId = null,
        string[]? capabilities = null)
    {
        var descriptor = new IpcServerDescriptor
        {
            Protocol = protocol ?? new ProtocolVersion(1, 0),
            ComponentVersion = "7.0.0",
            SupportedCapabilities = new HashSet<string>(
                capabilities ?? new[] { "status.read", "device.read", "classroom.control", "policy.control", "runner.read" },
                StringComparer.Ordinal),
            DeviceId = deviceId ?? DeviceId,
            SessionTtlSeconds = 28800,
        };
        return new IpcHandshakeValidator(descriptor);
    }

    private static byte[] Payload(string json) => Encoding.UTF8.GetBytes(json);

    private static string HandshakeJson(
        string protocolVersion = "1.0",
        string component = "bridge",
        string deviceId = DeviceId,
        string callerSid = Sid,
        string sessionId = "c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f",
        string capabilities = "[\"status.read\", \"device.read\"]") =>
        string.Create(
            System.Globalization.CultureInfo.InvariantCulture,
            $"{{\"v\":1,\"method\":\"ipc.handshake\",\"trace_id\":\"t1\",\"params\":{{" +
            $"\"protocol_version\":\"{protocolVersion}\"," +
            $"\"component\":\"{component}\"," +
            $"\"component_version\":\"0.1.0\"," +
            $"\"capabilities\":{capabilities}," +
            $"\"device_id\":\"{deviceId}\"," +
            $"\"caller_sid\":\"{callerSid}\"," +
            $"\"session_id\":\"{sessionId}\"}}}}");

    [Fact]
    public void Handle_ValidHandshake_AcceptsAndGrantsIntersection()
    {
        var outcome = CreateValidator().Handle(Payload(HandshakeJson()), Sid);

        Assert.True(outcome.Accepted);
        Assert.False(outcome.CloseConnection);
        Assert.Equal("c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f", outcome.SessionId);
        Assert.Contains("status.read", outcome.GrantedCapabilities);
        Assert.Contains("device.read", outcome.GrantedCapabilities);
        Assert.Equal(2, outcome.GrantedCapabilities.Count);

        Assert.True(outcome.Response.Ok);
        Assert.NotNull(outcome.Response.Result);
        var result = outcome.Response.Result!.Value.Deserialize<HandshakeResult>(Protocol.Json.Options);

        Assert.NotNull(result);
        Assert.Equal("1.0", result.ProtocolVersion);
        Assert.Equal("7.0.0", result.ComponentVersion);
        Assert.Equal(28800, result.SessionTtlSeconds);
        Assert.True(result.ServerTimeUnix > 0);
        Assert.Equal(outcome.GrantedCapabilities.OrderBy(c => c), result.Capabilities.OrderBy(c => c));
    }

    [Fact]
    public void Handle_CapabilityNotSupported_GrantsOnlyIntersection()
    {
        var json = HandshakeJson(capabilities: "[\"status.read\", \"runner.execute\", \"no_such.read\"]");

        var outcome = CreateValidator().Handle(Payload(json), Sid);

        // runner.execute 未在服务端开放（M3），no_such.read 不存在 → 仅授予 status.read
        Assert.True(outcome.Accepted);
        Assert.Single(outcome.GrantedCapabilities);
        Assert.Contains("status.read", outcome.GrantedCapabilities);
    }

    [Theory]
    [InlineData("2.0")]  // 主版本不一致
    [InlineData("1.1")]  // 客户端次版本高于服务端
    public void Handle_VersionIncompatible_RejectsAndCloses(string clientVersion)
    {
        var outcome = CreateValidator().Handle(Payload(HandshakeJson(protocolVersion: clientVersion)), Sid);

        Assert.False(outcome.Accepted);
        Assert.True(outcome.CloseConnection, "版本不兼容必须断连，不得静默运行");
        Assert.False(outcome.Response.Ok);
        Assert.Equal(IpcErrorCodes.IpcVersionMismatch, outcome.Response.Error!.Code);
        Assert.False(outcome.Response.Error.Retryable);
        Assert.NotNull(outcome.Response.Error.Details);
        Assert.Equal("1.0", outcome.Response.Error.Details!["expected"]);
        Assert.Equal(clientVersion, outcome.Response.Error.Details!["actual"]);
    }

    [Fact]
    public void Handle_DeviceMismatch_RejectsAndCloses()
    {
        var json = HandshakeJson(deviceId: "ffffffffffffffffffffffffffffffff");

        var outcome = CreateValidator().Handle(Payload(json), Sid);

        Assert.False(outcome.Accepted);
        Assert.True(outcome.CloseConnection, "设备绑定失败必须断连");
        Assert.Equal(IpcErrorCodes.PermissionDenied, outcome.Response.Error!.Code);
    }

    [Fact]
    public void Handle_CallerSidMismatchWithFrame_RejectsAndCloses()
    {
        var frameSid = "S-1-5-21-1111111111-2222222222-3333333333-9999";

        var outcome = CreateValidator().Handle(Payload(HandshakeJson()), frameSid);

        Assert.False(outcome.Accepted);
        Assert.True(outcome.CloseConnection, "payload 自报 SID 与管道身份不一致必须断连");
        Assert.Equal(IpcErrorCodes.PermissionDenied, outcome.Response.Error!.Code);
    }

    [Fact]
    public void Handle_MalformedPayload_RejectsAsInvalidArgument()
    {
        var validator = CreateValidator();

        var notJson = validator.Handle(Encoding.UTF8.GetBytes("not-json{{"), Sid);
        Assert.False(notJson.Accepted);
        Assert.True(notJson.CloseConnection);
        Assert.Equal(IpcErrorCodes.InvalidArgument, notJson.Response.Error!.Code);

        var empty = validator.Handle(Array.Empty<byte>(), Sid);
        Assert.False(empty.Accepted);
        Assert.Equal(IpcErrorCodes.InvalidArgument, empty.Response.Error!.Code);
    }

    [Fact]
    public void Handle_WrongFirstMethod_RejectsAsInvalidArgument()
    {
        var json = """{"v":1,"method":"system.get_status","params":{}}""";

        var outcome = CreateValidator().Handle(Payload(json), Sid);

        Assert.False(outcome.Accepted);
        Assert.True(outcome.CloseConnection, "首帧方法不是 handshake 必须拒绝");
        Assert.Equal(IpcErrorCodes.InvalidArgument, outcome.Response.Error!.Code);
    }

    [Fact]
    public void Handle_ParamsSchemaViolation_RejectsAsInvalidArgument()
    {
        // device_id 过短（schema minLength 8）
        var json = HandshakeJson(deviceId: "short");
        var outcome = CreateValidator().Handle(Payload(json), Sid);

        Assert.False(outcome.Accepted);
        Assert.Equal(IpcErrorCodes.InvalidArgument, outcome.Response.Error!.Code);
        Assert.Contains("device_id", outcome.Response.Error.Message);
    }

    [Fact]
    public void Handle_NewerServer_AcceptsOlderClient()
    {
        // 服务端升级到 1.2 后仍接受 1.0 客户端（向后兼容）
        var outcome = CreateValidator(protocol: new ProtocolVersion(1, 2))
            .Handle(Payload(HandshakeJson(protocolVersion: "1.0")), Sid);

        Assert.True(outcome.Accepted);
        Assert.Equal("1.2", outcome.Response.Result!.Value
            .Deserialize<HandshakeResult>(Protocol.Json.Options)!.ProtocolVersion);
    }
}
