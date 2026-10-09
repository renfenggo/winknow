using Winknow.ControlService;
using Winknow.Ipc.Commands;
using Winknow.Ipc.Protocol;
using Winknow.Ipc.Session;

namespace Winknow.ControlService.Tests;

/// <summary>
/// R06（GO_LIVE §3.4b）classroom.lock / classroom.unlock 行为测试：
/// ControlCommandHost 直连注册表分发（无管道），验证推送器绑定三态
/// （未绑定 / 推送失败 → UNAVAILABLE；成功 → pushed=true）与
/// method_registry.md v1 五要素、system 角色 + classroom.control 能力限制。
/// </summary>
public sealed class LockOverlayIpcTests
{
    private const string SystemSid = "S-1-5-18";
    private const string BridgeSid = "S-1-5-21-3623811015-3361044348-30300820-1013";

    private static ControlCommandHost CreateHost() =>
        new(null, "device-test-0001", "test", sid => sid == SystemSid);

    private static IpcConnectionSession SystemSession(params string[] capabilities) => new()
    {
        HandshakeCompleted = true,
        Component = "admin_tool",
        CallerSid = SystemSid,
        GrantedCapabilities = new HashSet<string>(capabilities, StringComparer.Ordinal),
    };

    private static IpcConnectionSession BridgeSession(params string[] capabilities) => new()
    {
        HandshakeCompleted = true,
        Component = "bridge",
        CallerSid = BridgeSid,
        GrantedCapabilities = new HashSet<string>(capabilities, StringComparer.Ordinal),
    };

    private static RequestEnvelope Request(string method) => new() { Method = method };

    [Fact]
    public void LockUnlockSpecs_MatchMethodRegistry()
    {
        // method_registry.md v1 五要素对齐（R06 新增两方法）
        var host = CreateHost();
        var specs = host.Registry.Specs.ToDictionary(s => s.Method, StringComparer.Ordinal);

        foreach (var method in new[] { "classroom.lock", "classroom.unlock" })
        {
            var spec = specs[method];
            Assert.Equal("classroom.control", spec.RequiredCapability);
            Assert.Equal(IpcCallerRole.System, Assert.Single(spec.AllowedRoles));
            Assert.Equal(TimeSpan.FromSeconds(15), spec.Timeout);
            Assert.Equal("full", spec.AuditLevel);
            Assert.NotNull(spec.Handler);
        }
    }

    [Fact]
    public async Task Lock_WithoutPusher_ReturnsUnavailable()
    {
        var host = CreateHost();

        var response = await host.DispatchAsync(
            Request("classroom.lock"), SystemSession("classroom.control"), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.Unavailable, response.Error!.Code);
    }

    [Fact]
    public async Task Lock_PusherReturnsFalse_ReturnsUnavailable()
    {
        var host = CreateHost();
        host.LockOverlayPusher = _ => Task.FromResult(false);

        var response = await host.DispatchAsync(
            Request("classroom.lock"), SystemSession("classroom.control"), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.Unavailable, response.Error!.Code);
        Assert.Contains("no session_agent", response.Error!.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Lock_PusherSucceeds_PushesShowAndReturnsPushed()
    {
        var actions = new List<string>();
        var host = CreateHost();
        host.LockOverlayPusher = action =>
        {
            actions.Add(action);
            return Task.FromResult(true);
        };

        var response = await host.DispatchAsync(
            Request("classroom.lock"), SystemSession("classroom.control"), CancellationToken.None);

        Assert.True(response.Ok, $"{response.Error?.Code} {response.Error?.Message}");
        Assert.Equal("show", Assert.Single(actions));
        Assert.True(response.Result!.Value.GetProperty("pushed").GetBoolean());
        Assert.Equal("show", response.Result!.Value.GetProperty("action").GetString());
    }

    [Fact]
    public async Task Unlock_PusherSucceeds_PushesHide()
    {
        var actions = new List<string>();
        var host = CreateHost();
        host.LockOverlayPusher = action =>
        {
            actions.Add(action);
            return Task.FromResult(true);
        };

        var response = await host.DispatchAsync(
            Request("classroom.unlock"), SystemSession("classroom.control"), CancellationToken.None);

        Assert.True(response.Ok, $"{response.Error?.Code} {response.Error?.Message}");
        Assert.Equal("hide", Assert.Single(actions));
        Assert.Equal("hide", response.Result!.Value.GetProperty("action").GetString());
    }

    [Fact]
    public async Task Lock_ByBridgeRole_Denied()
    {
        // classroom.* 仅 system 角色（管理员 SID）；bridge 组件即使被授予
        // classroom.control 能力也不得调用
        var host = CreateHost();

        var response = await host.DispatchAsync(
            Request("classroom.lock"), BridgeSession("classroom.control"), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.IpcSidNotAuthorized, response.Error!.Code);
    }

    [Fact]
    public async Task Lock_WithoutCapability_Denied()
    {
        // system 角色但未授予 classroom.control 能力（握手未请求/未交集）
        var host = CreateHost();

        var response = await host.DispatchAsync(
            Request("classroom.lock"), SystemSession("status.read"), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.IpcCapabilityMismatch, response.Error!.Code);
    }
}
