using System.Text;

namespace Winknow.Core.Tests;

public sealed class SecurityUtilsTests
{
    private const string HelloHash = "2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824";

    [Fact]
    public void ComputeSha256Hash_KnownText_ShouldReturnExpectedHash()
    {
        Assert.Equal(HelloHash, SecurityUtils.ComputeSha256Hash("hello"));
    }

    [Fact]
    public void ComputeSha256Hash_KnownBytes_ShouldReturnExpectedHash()
    {
        Assert.Equal(HelloHash, SecurityUtils.ComputeSha256Hash(Encoding.UTF8.GetBytes("hello")));
    }

    [Fact]
    public void ComputeSha256Hash_NullText_ShouldThrowArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => SecurityUtils.ComputeSha256Hash((string)null!));
    }

    [Fact]
    public void ComputeSha256HashFile_KnownFile_ShouldReturnExpectedHash()
    {
        var filePath = Path.Combine(Path.GetTempPath(), $"winknow-{Guid.NewGuid():N}.tmp");

        try
        {
            File.WriteAllText(filePath, "hello", new UTF8Encoding(false));
            Assert.Equal(HelloHash, SecurityUtils.ComputeSha256HashFile(filePath));
        }
        finally
        {
            File.Delete(filePath);
        }
    }

    [Fact]
    public void ComputeSha256HashFile_MissingFile_ShouldThrowFileNotFoundException()
    {
        var filePath = Path.Combine(Path.GetTempPath(), $"winknow-missing-{Guid.NewGuid():N}.tmp");
        Assert.Throws<FileNotFoundException>(() => SecurityUtils.ComputeSha256HashFile(filePath));
    }

    [Fact]
    public void GenerateRandomBytes_RequestedLength_ShouldReturnDifferentBuffers()
    {
        var first = SecurityUtils.GenerateRandomBytes(32);
        var second = SecurityUtils.GenerateRandomBytes(32);

        Assert.Equal(32, first.Length);
        Assert.Equal(32, second.Length);
        Assert.NotEqual(first, second);
    }

    [Fact]
    public void GenerateRandomBytes_NegativeLength_ShouldThrowArgumentOutOfRangeException()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => SecurityUtils.GenerateRandomBytes(-1));
    }

    [Fact]
    public void GenerateNonce_DefaultRequest_ShouldReturnSixteenBytes()
    {
        Assert.Equal(16, SecurityUtils.GenerateNonce().Length);
    }
}
