using Winknow.ProcessControl;

namespace Winknow.ProcessControl.Tests;

/// <summary>
/// 进程信息数据类测试。
/// </summary>
public class ProcessInfoTests
{
    [Fact(DisplayName = "ProcessInfo 默认值正确")]
    public void ProcessInfo_DefaultValues()
    {
        var info = new ProcessInfo
        {
            ProcessId = 1234,
            ProcessName = "test"
        };

        Assert.Equal(1234, info.ProcessId);
        Assert.Equal("test", info.ProcessName);
        Assert.Equal(string.Empty, info.FilePath);
        Assert.Equal(string.Empty, info.CommandLine);
        Assert.Equal(string.Empty, info.UserSid);
        Assert.Equal(string.Empty, info.FileHash);
        Assert.Equal(string.Empty, info.SignatureSubject);
        Assert.False(info.IsSigned);
    }

    [Fact(DisplayName = "IsSigned 有签名时为 true")]
    public void IsSigned_WithSignature_True()
    {
        var info = new ProcessInfo
        {
            ProcessId = 1,
            ProcessName = "signed",
            SignatureSubject = "CN=Microsoft Windows"
        };

        Assert.True(info.IsSigned);
    }

    [Fact(DisplayName = "IsSigned 无签名时为 false")]
    public void IsSigned_NoSignature_False()
    {
        var info = new ProcessInfo
        {
            ProcessId = 2,
            ProcessName = "unsigned",
            SignatureSubject = string.Empty
        };

        Assert.False(info.IsSigned);
    }
}
