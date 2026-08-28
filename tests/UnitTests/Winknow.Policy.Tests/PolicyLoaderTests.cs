using System.Text.Json;
using Winknow.Core.Results;
using Winknow.Policy;

namespace Winknow.Policy.Tests;

/// <summary>
/// 策略加载器测试。
/// </summary>
public class PolicyLoaderTests
{
    private readonly PolicyLoader _loader = new();

    [Fact(DisplayName = "加载默认策略文件成功")]
    public void Load_DefaultPolicy_Success()
    {
        var policyPath = Path.Combine(
            AppContext.BaseDirectory, "policies", "default_policy_v7.0.json");
        if (!File.Exists(policyPath))
        {
            // 测试环境跳过
            return;
        }

        var result = _loader.Load(policyPath);

        Assert.True(result.IsSuccess);
        Assert.Equal("7.0.0", result.Data!.Version);
        Assert.Equal("default-classroom-v1", result.Data!.PolicyId);
    }

    [Fact(DisplayName = "不存在的文件返回 PathNotFound")]
    public void Load_NonexistentFile_PathNotFound()
    {
        var result = _loader.Load("C:\\nonexistent\\policy.json");

        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.PathNotFound, result.ErrorCode);
    }

    [Fact(DisplayName = "无效 JSON 返回 PolicyInvalid")]
    public void Load_InvalidJson_PolicyInvalid()
    {
        var tempFile = Path.GetTempFileName();
        File.WriteAllText(tempFile, "{ invalid json }");

        try
        {
            var result = _loader.Load(tempFile);

            Assert.False(result.IsSuccess);
            Assert.Equal(ErrorCode.PolicyInvalid, result.ErrorCode);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact(DisplayName = "版本不兼容返回 PolicyVersionMismatch")]
    public void Load_IncompatibleVersion_PolicyVersionMismatch()
    {
        var tempFile = Path.GetTempFileName();
        File.WriteAllText(tempFile, """
            {
                "Version": "6.0.0",
                "PolicyId": "test-v6",
                "CreatedAt": "2026-01-01T00:00:00Z",
                "Description": "V6 policy"
            }
            """);

        try
        {
            var result = _loader.Load(tempFile);

            Assert.False(result.IsSuccess);
            Assert.Equal(ErrorCode.PolicyVersionMismatch, result.ErrorCode);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact(DisplayName = "缺少 Version 返回 PolicyInvalid")]
    public void Load_MissingVersion_PolicyInvalid()
    {
        var tempFile = Path.GetTempFileName();
        File.WriteAllText(tempFile, """
            {
                "PolicyId": "test-no-version",
                "CreatedAt": "2026-01-01T00:00:00Z",
                "Description": "No version"
            }
            """);

        try
        {
            var result = _loader.Load(tempFile);

            Assert.False(result.IsSuccess);
            Assert.Equal(ErrorCode.PolicyInvalid, result.ErrorCode);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact(DisplayName = "完整策略解析成功")]
    public void Load_CompletePolicy_AllSectionsParsed()
    {
        var tempFile = Path.GetTempFileName();
        File.WriteAllText(tempFile, """
            {
                "Version": "7.0.0",
                "PolicyId": "test-complete",
                "CreatedAt": "2026-01-01T00:00:00Z",
                "Description": "Complete test policy",
                "SoftwareControl": {
                    "Whitelist": {
                        "ByPublisher": ["Microsoft", "Google"],
                        "ByPath": [{"Path": "C:\\\\Test\\\\app.exe", "Hash": "", "Description": "Test"}],
                        "ByHash": []
                    },
                    "HighRiskInterpreters": {"Blocked": ["powershell.exe"]}
                },
                "NetworkControl": {
                    "WebsiteWhitelist": {"Domains": ["example.com", "*.example.com"]},
                    "Proxy": {"Allowed": false, "ForceSystemProxy": true}
                },
                "UsbControl": {
                    "MassStorage": {"Enabled": false, "AdminOverride": true},
                    "HidDevices": {"Enabled": true}
                }
            }
            """);

        try
        {
            var result = _loader.Load(tempFile);

            Assert.True(result.IsSuccess);
            Assert.Equal("7.0.0", result.Data!.Version);
            Assert.Contains("Microsoft", result.Data!.SoftwareControl.Whitelist.ByPublisher);
            Assert.Contains("example.com", result.Data!.NetworkControl.WebsiteWhitelist.Domains);
            Assert.False(result.Data!.UsbControl.MassStorage.Enabled);
            Assert.True(result.Data!.UsbControl.HidDevices.Enabled);
            Assert.Contains("powershell.exe", result.Data!.SoftwareControl.HighRiskInterpreters.Blocked);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }
}
