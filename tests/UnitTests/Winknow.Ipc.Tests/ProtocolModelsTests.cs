using System.Text.Json;
using Winknow.Ipc.Protocol;

namespace Winknow.Ipc.Tests;

/// <summary>
/// M2-1 契约协议层测试：Envelope/Handshake/错误码/ProtocolVersion
/// （对齐 contracts/ipc 与 contracts/errors 示例）。
/// </summary>
public sealed class ProtocolModelsTests
{
    // ---- ProtocolVersion ----

    [Theory]
    [InlineData("1.0", 1, 0)]
    [InlineData("2.13", 2, 13)]
    public void ProtocolVersion_Parse_Valid(string text, int major, int minor)
    {
        Assert.True(ProtocolVersion.TryParse(text, out var v));
        Assert.Equal(new ProtocolVersion(major, minor), v);
        Assert.Equal(text, v.ToString());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("1")]
    [InlineData("1.0.0")]
    [InlineData("a.b")]
    [InlineData("1.x")]
    [InlineData("-1.0")]
    public void ProtocolVersion_Parse_Invalid(string? text)
    {
        Assert.False(ProtocolVersion.TryParse(text, out _));
    }

    [Fact]
    public void ProtocolVersion_Accepts_ServerRules()
    {
        var server = new ProtocolVersion(1, 0);
        Assert.True(server.Accepts(new ProtocolVersion(1, 0)), "同版本必须兼容");
        Assert.False(server.Accepts(new ProtocolVersion(2, 0)), "主版本不一致必须拒绝");
        Assert.False(server.Accepts(new ProtocolVersion(1, 1)), "客户端次版本更高必须拒绝（服务端不支持该次版本）");

        var richer = new ProtocolVersion(1, 2);
        Assert.True(richer.Accepts(new ProtocolVersion(1, 0)), "服务端高次版本应接受低次版本客户端");
    }

    // ---- ErrorEnvelope ----

    [Fact]
    public void ErrorEnvelope_Serialize_MatchesContractFields()
    {
        var error = ErrorEnvelope.Create(
            IpcErrorCodes.IpcSidExpired, "会话授权已过期，请重新登录",
            traceId: "3f9d2c1a8b4e4f219c0d5a6b7e8f9012");

        var json = error.Serialize();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("1.0", root.GetProperty("schema_version").GetString());
        Assert.Equal("IPC_SID_EXPIRED", root.GetProperty("code").GetString());
        Assert.Equal("会话授权已过期，请重新登录", root.GetProperty("message").GetString());
        Assert.False(root.GetProperty("retryable").GetBoolean());
        Assert.Equal("3f9d2c1a8b4e4f219c0d5a6b7e8f9012", root.GetProperty("trace_id").GetString());
    }

    [Fact]
    public void ErrorEnvelope_Retryable_DerivedFromRegistry()
    {
        Assert.True(ErrorEnvelope.Create(IpcErrorCodes.Timeout, "t").Retryable);
        Assert.True(ErrorEnvelope.Create(IpcErrorCodes.InternalError, "t").Retryable);
        Assert.False(ErrorEnvelope.Create(IpcErrorCodes.IpcVersionMismatch, "t").Retryable);
        Assert.False(ErrorEnvelope.Create(IpcErrorCodes.PermissionDenied, "t").Retryable);
    }

    [Fact]
    public void ErrorEnvelope_Deserialize_ContractExample()
    {
        // contracts/ipc/examples/error_response_sid_expired.json 的 error 对象
        const string json = """
            {"schema_version":"1.0","code":"IPC_SID_EXPIRED","message":"会话授权已过期，请重新登录","retryable":false,"trace_id":"abc"}
            """;
        var error = ErrorEnvelope.Deserialize(json);

        Assert.NotNull(error);
        Assert.Equal("IPC_SID_EXPIRED", error.Code);
        Assert.False(error.Retryable);
        Assert.Equal("abc", error.TraceId);
    }

    // ---- RequestEnvelope ----

    [Theory]
    [InlineData("system.get_status", true)]
    [InlineData("ipc.handshake", true)]
    [InlineData("runner.get_capabilities", true)]
    [InlineData("classroom.begin", true)]
    [InlineData("system_shutdown", false)]     // 缺少域.动词分层
    [InlineData("System.get_status", false)]   // 大写不允许
    [InlineData("1system.get", false)]         // 数字开头不允许
    [InlineData("system.get-status", false)]   // 连字符不允许
    [InlineData("", false)]
    [InlineData(null, false)]
    public void RequestEnvelope_MethodName_Validation(string? method, bool expected)
    {
        Assert.Equal(expected, RequestEnvelope.IsValidMethodName(method));
    }

    [Fact]
    public void RequestEnvelope_Serialize_CamelCaseFields()
    {
        var request = new RequestEnvelope
        {
            Method = "device.get_state",
            TraceId = "trace-1",
            Params = JsonSerializer.SerializeToElement(new { device_id = "abc12345" }),
        };

        var json = request.Serialize();
        using var doc = JsonDocument.Parse(json);

        Assert.Equal(1, doc.RootElement.GetProperty("v").GetInt32());
        Assert.Equal("device.get_state", doc.RootElement.GetProperty("method").GetString());
        Assert.Equal("trace-1", doc.RootElement.GetProperty("trace_id").GetString());
        Assert.Equal("abc12345", doc.RootElement.GetProperty("params").GetProperty("device_id").GetString());
    }

    // ---- ResponseEnvelope ----

    [Fact]
    public void ResponseEnvelope_FromResult_HasResultNoError()
    {
        var response = ResponseEnvelope.FromResult(new { status = "running" });

        Assert.True(response.Ok);
        Assert.NotNull(response.Result);
        Assert.Null(response.Error);

        var json = response.Serialize();
        using var doc = JsonDocument.Parse(json);
        Assert.True(doc.RootElement.TryGetProperty("result", out _));
        Assert.False(doc.RootElement.TryGetProperty("error", out _));
    }

    [Fact]
    public void ResponseEnvelope_FromError_HasErrorNoResult()
    {
        var response = ResponseEnvelope.FromError(
            ErrorEnvelope.Create(IpcErrorCodes.IpcUnknownMethod, "unknown"));

        Assert.False(response.Ok);
        Assert.Null(response.Result);
        Assert.NotNull(response.Error);

        var json = response.Serialize();
        using var doc = JsonDocument.Parse(json);
        Assert.True(doc.RootElement.TryGetProperty("error", out _));
        Assert.False(doc.RootElement.TryGetProperty("result", out _));
    }

    [Fact]
    public void ResponseEnvelope_RoundTrip()
    {
        var original = ResponseEnvelope.FromResult(new { capabilities = new[] { "status.read" } });
        var restored = ResponseEnvelope.Deserialize(original.Serialize());

        Assert.NotNull(restored);
        Assert.True(restored.Ok);
        Assert.Equal("status.read", restored.Result!.Value.GetProperty("capabilities")[0].GetString());
    }

    // ---- HandshakeParams ----

    private static HandshakeParams ValidParams() => new()
    {
        ProtocolVersion = "1.0",
        Component = "bridge",
        ComponentVersion = "0.1.0",
        Capabilities = new[] { "status.read", "device.read", "runner.read" },
        DeviceId = "0123456789abcdef0123456789abcdef",
        CallerSid = "S-1-5-21-3623811015-3361044348-30300820-1013",
        SessionId = "c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f",
    };

    [Fact]
    public void HandshakeParams_Validate_ContractExample_Passes()
    {
        // 对齐 contracts/ipc/examples/handshake_request.json
        var p = ValidParams();
        Assert.True(p.Validate(out var reason), reason);
    }

    [Fact]
    public void HandshakeParams_Validate_Branches()
    {
        var bad = ValidParams();
        // 逐字段破坏（每份独立副本），全部必须校验失败
        Assert.False(new HandshakeParams
        {
            ProtocolVersion = "1",
            Component = bad.Component,
            ComponentVersion = bad.ComponentVersion,
            Capabilities = bad.Capabilities,
            DeviceId = bad.DeviceId,
            CallerSid = bad.CallerSid,
            SessionId = bad.SessionId,
        }.Validate(out _), "protocol_version 格式错误必须拒绝");

        Assert.False(new HandshakeParams
        {
            ProtocolVersion = bad.ProtocolVersion,
            Component = "unknown_component",
            ComponentVersion = bad.ComponentVersion,
            Capabilities = bad.Capabilities,
            DeviceId = bad.DeviceId,
            CallerSid = bad.CallerSid,
            SessionId = bad.SessionId,
        }.Validate(out _), "未知 component 必须拒绝");

        Assert.False(new HandshakeParams
        {
            ProtocolVersion = bad.ProtocolVersion,
            Component = bad.Component,
            ComponentVersion = bad.ComponentVersion,
            Capabilities = new[] { "Status.Read" },
            DeviceId = bad.DeviceId,
            CallerSid = bad.CallerSid,
            SessionId = bad.SessionId,
        }.Validate(out _), "非法 capability 必须拒绝");

        Assert.False(new HandshakeParams
        {
            ProtocolVersion = bad.ProtocolVersion,
            Component = bad.Component,
            ComponentVersion = bad.ComponentVersion,
            Capabilities = bad.Capabilities,
            DeviceId = "short",
            CallerSid = bad.CallerSid,
            SessionId = bad.SessionId,
        }.Validate(out _), "device_id 过短必须拒绝");

        Assert.False(new HandshakeParams
        {
            ProtocolVersion = bad.ProtocolVersion,
            Component = bad.Component,
            ComponentVersion = bad.ComponentVersion,
            Capabilities = bad.Capabilities,
            DeviceId = bad.DeviceId,
            CallerSid = "not-a-sid",
            SessionId = bad.SessionId,
        }.Validate(out _), "caller_sid 非 SID 必须拒绝");

        Assert.False(new HandshakeParams
        {
            ProtocolVersion = bad.ProtocolVersion,
            Component = bad.Component,
            ComponentVersion = bad.ComponentVersion,
            Capabilities = bad.Capabilities,
            DeviceId = bad.DeviceId,
            CallerSid = bad.CallerSid,
            SessionId = "",
        }.Validate(out _), "session_id 缺失必须拒绝");
    }

    [Fact]
    public void HandshakeParams_Deserialize_FromContractRequestExample()
    {
        // contracts/ipc/examples/handshake_request.json（完整请求信封）
        var request = RequestEnvelope.Deserialize("""
            {
              "v": 1,
              "method": "ipc.handshake",
              "trace_id": "3f9d2c1a8b4e4f219c0d5a6b7e8f9012",
              "params": {
                "protocol_version": "1.0",
                "component": "bridge",
                "component_version": "0.1.0",
                "capabilities": ["status.read", "device.read", "runner.read"],
                "device_id": "0123456789abcdef0123456789abcdef",
                "caller_sid": "S-1-5-21-3623811015-3361044348-30300820-1013",
                "session_id": "c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f"
              }
            }
            """);

        Assert.NotNull(request);
        Assert.Equal("ipc.handshake", request.Method);
        var p = request.Params!.Value.Deserialize<HandshakeParams>(Json.Options);

        Assert.NotNull(p);
        Assert.Equal("bridge", p.Component);
        Assert.Equal(3, p.Capabilities.Count);
        Assert.True(p.Validate(out var reason), reason);
    }

    // ---- HandshakeResult ----

    [Fact]
    public void HandshakeResult_Serialize_MatchesContractResponse()
    {
        var result = new HandshakeResult
        {
            ProtocolVersion = "1.0",
            ComponentVersion = "7.0.0-fusion.1",
            Capabilities = new[] { "status.read", "device.read", "classroom.control", "policy.control", "runner.read" },
            SessionTtlSeconds = 28800,
            ServerTimeUnix = 1791214800,
        };

        var response = ResponseEnvelope.FromResult(result);
        var json = response.Serialize();
        using var doc = JsonDocument.Parse(json);
        var r = doc.RootElement.GetProperty("result");

        Assert.Equal("1.0", r.GetProperty("protocol_version").GetString());
        Assert.Equal("7.0.0-fusion.1", r.GetProperty("component_version").GetString());
        Assert.Equal(28800, r.GetProperty("session_ttl_s").GetInt32());
        Assert.Equal(1791214800, r.GetProperty("server_time_unix").GetInt64());
        Assert.Equal(5, r.GetProperty("capabilities").GetArrayLength());
    }
}
