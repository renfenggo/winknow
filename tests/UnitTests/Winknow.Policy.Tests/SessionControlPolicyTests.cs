using Winknow.Policy;

namespace Winknow.Policy.Tests;

/// <summary>
/// P2-05 会话管控策略开关：KeyboardPolicyEnabled 默认关闭（钩子本体属阶段 7 灰度项）。
/// </summary>
public sealed class SessionControlPolicyTests
{
    [Fact]
    public void DefaultPolicy_KeyboardPolicyEnabled_ShouldBeFalse()
    {
        var policy = new PolicyFile();
        Assert.NotNull(policy.SessionControl);
        Assert.False(policy.SessionControl.KeyboardPolicyEnabled);
    }

    [Fact]
    public void EncodedJsonRoundTrip_KeyboardPolicyEnabled_ShouldPreserveValue()
    {
        var policy = new PolicyFile
        {
            Version = "7.0.0-test",
            PolicyId = "test-policy",
            SessionControl = new SessionControlSection { KeyboardPolicyEnabled = true }
        };

        var encoded = policy.ToEncodedJson();
        var decoded = PolicyFile.FromEncodedJson(encoded);

        Assert.NotNull(decoded);
        Assert.True(decoded!.SessionControl.KeyboardPolicyEnabled);
    }

    [Fact]
    public void FromEncodedJson_MissingSessionControlSection_ShouldFallBackToDefault()
    {
        // 旧版策略文件无 sessionControl 节 → 反序列化用默认值（关闭）
        var legacy = new
        {
            version = "6.0.0",
            policyId = "legacy"
        };
        var json = System.Text.Json.JsonSerializer.Serialize(legacy);
        var encoded = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(json));

        var decoded = PolicyFile.FromEncodedJson(encoded);

        Assert.NotNull(decoded);
        Assert.False(decoded!.SessionControl.KeyboardPolicyEnabled);
    }
}
