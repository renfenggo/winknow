using System.IO;
using System.Security.Cryptography;
using System.Text;
using Dapper;
using Microsoft.Data.Sqlite;
using Winknow.Core;
using Winknow.Core.Results;
using Winknow.Logging;
using Winknow.Security;

namespace Winknow.Security.Tests;

/// <summary>
/// 第 9 周"密钥、日志完整性与隐私治理"回归测试。
/// 覆盖验收项：
/// - 客户端不含签名私钥（KeyManifest 声明 CodeSigning.ContainsPrivateKey = false）
/// - 密码、密钥、恢复码不进入普通日志（LogCipher.IsSensitive + PrivacyPolicy.IsFieldAllowed）
/// - 默认不记录网页正文和学生代码正文（PrivacyPolicy.ExcludedFields）
/// - 修改或截断日志可被检测（HashChain.VerifyChain + LogCheckpointSigner.VerifyCheckpoint）
/// - 日志数据到期后安全删除（DataRetentionManager.PurgeExpired + SecureDeleteFile）
/// </summary>
public class Week9LogIntegrityTests
{
    private static string NewTempDir() =>
        Path.Combine(Path.GetTempPath(), $"wk9_{Guid.NewGuid():N}");

    private static string NewTempFile(string ext = ".bin") =>
        Path.Combine(Path.GetTempPath(), $"wk9_{Guid.NewGuid():N}{ext}");

    private static string NewTempDb() =>
        Path.Combine(Path.GetTempPath(), $"wk9_{Guid.NewGuid():N}.db");

    // ==================== KeyManifest ====================

    [Fact]
    public void KeyManifest_CreateDefault_ContainsExpectedKeys()
    {
        var manifest = KeyManifest.CreateDefault("test-device-001");

        Assert.Equal("test-device-001", manifest.DeviceId);
        Assert.Equal(5, manifest.Keys.Count);
        Assert.Contains(manifest.Keys, k => k.Purpose == KeyPurpose.CodeSigning);
        Assert.Contains(manifest.Keys, k => k.Purpose == KeyPurpose.LogEncryption);
        Assert.Contains(manifest.Keys, k => k.Purpose == KeyPurpose.LogCheckpoint);
        Assert.Contains(manifest.Keys, k => k.Purpose == KeyPurpose.Totp);
        Assert.Contains(manifest.Keys, k => k.Purpose == KeyPurpose.RecoveryCodes);
    }

    [Fact]
    public void KeyManifest_CodeSigning_DoesNotContainPrivateKey()
    {
        var manifest = KeyManifest.CreateDefault("test-device-002");
        var signing = manifest.Keys.Single(k => k.Purpose == KeyPurpose.CodeSigning);

        Assert.False(signing.ContainsPrivateKey);
        Assert.Equal(KeySource.ExternalHsm, signing.Source);
    }

    [Fact]
    public void KeyManifest_LogKeys_AreDeviceGenerated()
    {
        var manifest = KeyManifest.CreateDefault("test-device-003");
        var logEnc = manifest.Keys.Single(k => k.Purpose == KeyPurpose.LogEncryption);
        var logChk = manifest.Keys.Single(k => k.Purpose == KeyPurpose.LogCheckpoint);

        Assert.True(logEnc.ContainsPrivateKey);
        Assert.Equal(KeySource.DeviceGenerated, logEnc.Source);
        Assert.Equal("AES-256-GCM", logEnc.Algorithm);

        Assert.True(logChk.ContainsPrivateKey);
        Assert.Equal(KeySource.DeviceGenerated, logChk.Source);
        Assert.Equal("HMAC-SHA256", logChk.Algorithm);
    }

    // ==================== DpapiProtector ====================

    [Fact]
    public void DpapiProtector_ProtectUnprotect_Roundtrip_Succeeds()
    {
        var plaintext = Encoding.UTF8.GetBytes("sensitive-log-data-测试");
        var entropy = Encoding.UTF8.GetBytes("device-id-001");

        var ciphertext = DpapiProtector.Protect(plaintext, entropy);
        var recovered = DpapiProtector.Unprotect(ciphertext, entropy);

        Assert.Equal(plaintext, recovered);
    }

    [Fact]
    public void DpapiProtector_Protect_ProducesDifferentCiphertext()
    {
        var plaintext = Encoding.UTF8.GetBytes("same-data");
        var entropy = Encoding.UTF8.GetBytes("entropy");

        var ct1 = DpapiProtector.Protect(plaintext, entropy);
        var ct2 = DpapiProtector.Protect(plaintext, entropy);

        Assert.NotEqual(ct1, ct2);
    }

    [Fact]
    public void DpapiProtector_Unprotect_WrongEntropy_ThrowsCryptographicException()
    {
        var plaintext = Encoding.UTF8.GetBytes("secret");
        var entropy1 = Encoding.UTF8.GetBytes("entropy-1");
        var entropy2 = Encoding.UTF8.GetBytes("entropy-2");

        var ciphertext = DpapiProtector.Protect(plaintext, entropy1);

        Assert.Throws<CryptographicException>(() => DpapiProtector.Unprotect(ciphertext, entropy2));
    }

    [Fact]
    public void DpapiProtector_ProtectToFileUnprotectFromFile_Roundtrip_Succeeds()
    {
        var filePath = NewTempFile();
        var plaintext = Encoding.UTF8.GetBytes("key-material-12345");
        var entropy = Encoding.UTF8.GetBytes("device-id-002");

        try
        {
            var saveResult = DpapiProtector.ProtectToFile(filePath, plaintext, entropy);
            Assert.True(saveResult.IsSuccess);
            Assert.True(File.Exists(filePath));

            var loadResult = DpapiProtector.UnprotectFromFile(filePath, entropy);
            Assert.True(loadResult.IsSuccess);
            Assert.Equal(plaintext, loadResult.Data);
        }
        finally
        {
            if (File.Exists(filePath)) File.Delete(filePath);
        }
    }

    [Fact]
    public void DpapiProtector_UnprotectFromFile_NonExistentFile_ReturnsPathNotFound()
    {
        var result = DpapiProtector.UnprotectFromFile(Path.Combine(Path.GetTempPath(), "nonexistent_" + Guid.NewGuid().ToString("N") + ".key"));

        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.PathNotFound, result.ErrorCode);
    }

    // ==================== DeviceLogKeyGenerator ====================

    [Fact]
    public void DeviceLogKeyGenerator_GetOrCreateLogEncryptionKey_Returns32Bytes()
    {
        var dir = NewTempDir();
        Directory.CreateDirectory(dir);
        try
        {
            var gen = new DeviceLogKeyGenerator(dir, "device-key-test-001");
            var result = gen.GetOrCreateLogEncryptionKey();

            Assert.True(result.IsSuccess);
            Assert.Equal(32, result.Data!.Length);
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void DeviceLogKeyGenerator_GetOrCreateLogCheckpointKey_Returns32Bytes()
    {
        var dir = NewTempDir();
        Directory.CreateDirectory(dir);
        try
        {
            var gen = new DeviceLogKeyGenerator(dir, "device-key-test-002");
            var result = gen.GetOrCreateLogCheckpointKey();

            Assert.True(result.IsSuccess);
            Assert.Equal(32, result.Data!.Length);
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void DeviceLogKeyGenerator_SecondCall_ReturnsSameKey()
    {
        var dir = NewTempDir();
        Directory.CreateDirectory(dir);
        try
        {
            var gen1 = new DeviceLogKeyGenerator(dir, "device-key-test-003");
            var key1 = gen1.GetOrCreateLogEncryptionKey().Data!;

            var gen2 = new DeviceLogKeyGenerator(dir, "device-key-test-003");
            var key2 = gen2.GetOrCreateLogEncryptionKey().Data!;

            Assert.Equal(key1, key2);
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void DeviceLogKeyGenerator_DifferentDevice_ReturnsDifferentKey()
    {
        var dir = NewTempDir();
        Directory.CreateDirectory(dir);
        try
        {
            var gen1 = new DeviceLogKeyGenerator(dir, "device-A");
            var key1 = gen1.GetOrCreateLogEncryptionKey().Data!;

            var dir2 = NewTempDir();
            Directory.CreateDirectory(dir2);
            try
            {
                var gen2 = new DeviceLogKeyGenerator(dir2, "device-B");
                var key2 = gen2.GetOrCreateLogEncryptionKey().Data!;

                Assert.NotEqual(key1, key2);
            }
            finally
            {
                if (Directory.Exists(dir2)) Directory.Delete(dir2, true);
            }
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void DeviceLogKeyGenerator_GenerateManifest_DeclaresNoSigningPrivateKey()
    {
        var dir = NewTempDir();
        Directory.CreateDirectory(dir);
        try
        {
            var gen = new DeviceLogKeyGenerator(dir, "device-manifest-test");
            var manifest = gen.GenerateManifest("device-manifest-test");

            var signing = manifest.Keys.Single(k => k.Purpose == KeyPurpose.CodeSigning);
            Assert.False(signing.ContainsPrivateKey);
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void DeviceLogKeyGenerator_KeysExist_ReflectsCreationState()
    {
        var dir = NewTempDir();
        Directory.CreateDirectory(dir);
        try
        {
            var gen = new DeviceLogKeyGenerator(dir, "device-exist-test");
            Assert.False(gen.KeysExist());

            gen.GetOrCreateLogEncryptionKey();
            Assert.False(gen.KeysExist());

            gen.GetOrCreateLogCheckpointKey();
            Assert.True(gen.KeysExist());
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
        }
    }

    // ==================== LogCipher ====================

    [Fact]
    public void LogCipher_EncryptDecrypt_Roundtrip_Succeeds()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        using var cipher = new LogCipher(key);
        var plaintext = "敏感日志内容：用户 admin 执行了维护操作";

        var ciphertext = cipher.Encrypt(plaintext);
        var result = cipher.Decrypt(ciphertext);

        Assert.True(result.IsSuccess, result.ErrorMessage);
        Assert.Equal(plaintext, result.Data);
    }

    [Fact]
    public void LogCipher_Encrypt_ProducesDifferentCiphertext()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        using var cipher = new LogCipher(key);
        var plaintext = "same-content";

        var ct1 = cipher.Encrypt(plaintext);
        var ct2 = cipher.Encrypt(plaintext);

        Assert.NotEqual(ct1, ct2);
    }

    [Fact]
    public void LogCipher_Decrypt_TamperedCiphertext_ReturnsFailure()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        using var cipher = new LogCipher(key);
        var ciphertext = cipher.Encrypt("original-data");

        var bytes = Convert.FromBase64String(ciphertext);
        bytes[^1] ^= 0xFF;
        var tampered = Convert.ToBase64String(bytes);

        var result = cipher.Decrypt(tampered);

        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.DecryptionFailed, result.ErrorCode);
    }

    [Fact]
    public void LogCipher_Decrypt_DifferentKey_ReturnsFailure()
    {
        var key1 = RandomNumberGenerator.GetBytes(32);
        var key2 = RandomNumberGenerator.GetBytes(32);
        using var cipher1 = new LogCipher(key1);
        using var cipher2 = new LogCipher(key2);

        var ciphertext = cipher1.Encrypt("secret-data");
        var result = cipher2.Decrypt(ciphertext);

        Assert.False(result.IsSuccess);
    }

    [Theory]
    [InlineData("Password", true)]
    [InlineData("PrivateKey", true)]
    [InlineData("RecoveryCode", true)]
    [InlineData("TotpSecret", true)]
    [InlineData("Token", true)]
    [InlineData("ProcessName", false)]
    [InlineData("DeviceId", false)]
    [InlineData("Timestamp", false)]
    public void LogCipher_IsSensitive_DetectsSensitiveFields(string fieldName, bool expected)
    {
        Assert.Equal(expected, LogCipher.IsSensitive(fieldName));
    }

    [Theory]
    [InlineData("WebPageContent", true)]
    [InlineData("PageBody", true)]
    [InlineData("SourceCode", true)]
    [InlineData("StudentCode", true)]
    [InlineData("ProcessName", false)]
    [InlineData("EventTime", false)]
    public void LogCipher_IsDefaultExcluded_DetectsExcludedFields(string fieldName, bool expected)
    {
        Assert.Equal(expected, LogCipher.IsDefaultExcluded(fieldName));
    }

    // ==================== HashChain ====================

    [Fact]
    public void HashChain_ComputeChainHash_ProducesValidHexHash()
    {
        var chain = new HashChain();
        var hash = chain.ComputeChainHash("record-1");

        Assert.Equal(64, hash.Length);
        Assert.Matches("^[0-9a-f]{64}$", hash);
    }

    [Fact]
    public void HashChain_ComputeChainHash_SequentialRecords_ChainForward()
    {
        var chain = new HashChain();
        var hash1 = chain.ComputeChainHash("record-1");
        var hash2 = chain.ComputeChainHash("record-2");
        var hash3 = chain.ComputeChainHash("record-3");

        Assert.NotEqual(hash1, hash2);
        Assert.NotEqual(hash2, hash3);
        Assert.NotEqual(hash1, hash3);
    }

    [Fact]
    public void HashChain_VerifyChainLink_CorrectLink_ReturnsTrue()
    {
        var chain = new HashChain();
        var prev = chain.CurrentHash;
        var record = "test-record";
        var hash = chain.ComputeChainHash(record);

        Assert.True(HashChain.VerifyChainLink(record, prev, hash));
    }

    [Fact]
    public void HashChain_VerifyChainLink_TamperedRecord_ReturnsFalse()
    {
        var chain = new HashChain();
        var prev = chain.CurrentHash;
        var hash = chain.ComputeChainHash("original-record");

        Assert.False(HashChain.VerifyChainLink("tampered-record", prev, hash));
    }

    [Fact]
    public void HashChain_VerifyChain_EmptyChain_ReturnsSuccess()
    {
        var result = HashChain.VerifyChain(new List<HashChainEntry>());
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void HashChain_VerifyChain_ValidChain_ReturnsSuccess()
    {
        var chain = new HashChain();
        var entries = new List<HashChainEntry>();
        var prev = chain.CurrentHash;

        for (var i = 0; i < 5; i++)
        {
            var record = $"record-{i}";
            var hash = chain.ComputeChainHash(record);
            entries.Add(new HashChainEntry { Record = record, PreviousHash = prev, Hash = hash });
            prev = hash;
        }

        var result = HashChain.VerifyChain(entries);
        Assert.True(result.IsSuccess);
        Assert.Equal(-1, result.Data);
    }

    [Fact]
    public void HashChain_VerifyChain_TamperedMiddleRecord_DetectsBreak()
    {
        var chain = new HashChain();
        var entries = new List<HashChainEntry>();
        var prev = chain.CurrentHash;

        for (var i = 0; i < 5; i++)
        {
            var record = $"record-{i}";
            var hash = chain.ComputeChainHash(record);
            entries.Add(new HashChainEntry { Record = record, PreviousHash = prev, Hash = hash });
            prev = hash;
        }

        // 篡改第 2 条记录的内容
        entries[2] = new HashChainEntry
        {
            Record = "tampered-record-2",
            PreviousHash = entries[2].PreviousHash,
            Hash = entries[2].Hash
        };

        var result = HashChain.VerifyChain(entries);
        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.HashMismatch, result.ErrorCode);
    }

    [Fact]
    public void HashChain_VerifyChain_DeletedRecord_DetectsBreak()
    {
        var chain = new HashChain();
        var entries = new List<HashChainEntry>();
        var prev = chain.CurrentHash;

        for (var i = 0; i < 5; i++)
        {
            var record = $"record-{i}";
            var hash = chain.ComputeChainHash(record);
            entries.Add(new HashChainEntry { Record = record, PreviousHash = prev, Hash = hash });
            prev = hash;
        }

        // 删除中间记录（模拟截断）
        entries.RemoveAt(2);

        var result = HashChain.VerifyChain(entries);
        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.HashMismatch, result.ErrorCode);
    }

    [Fact]
    public void HashChain_Reset_AllowsContinuation()
    {
        var chain1 = new HashChain();
        chain1.ComputeChainHash("record-a");
        var tailHash = chain1.CurrentHash;

        var chain2 = new HashChain(tailHash);
        var hash = chain2.ComputeChainHash("record-b");

        Assert.True(HashChain.VerifyChainLink("record-b", tailHash, hash));
    }

    // ==================== LogCheckpointSigner ====================

    [Fact]
    public void LogCheckpointSigner_CreateCheckpoint_ReturnsSignedCheckpoint()
    {
        var hmacKey = RandomNumberGenerator.GetBytes(32);
        using var signer = new LogCheckpointSigner(hmacKey);

        var cp = signer.CreateCheckpoint("abcdef1234567890", 100);

        Assert.Equal("abcdef1234567890", cp.ChainTailHash);
        Assert.Equal(100, cp.RecordCount);
        Assert.False(string.IsNullOrEmpty(cp.Signature));
        Assert.False(string.IsNullOrEmpty(cp.CreatedAt));
    }

    [Fact]
    public void LogCheckpointSigner_VerifyCheckpoint_ValidSignature_ReturnsTrue()
    {
        var hmacKey = RandomNumberGenerator.GetBytes(32);
        using var signer = new LogCheckpointSigner(hmacKey);

        var cp = signer.CreateCheckpoint("tail-hash-001", 50);
        Assert.True(signer.VerifyCheckpoint(cp));
    }

    [Fact]
    public void LogCheckpointSigner_VerifyCheckpoint_TamperedCheckpoint_ReturnsFalse()
    {
        var hmacKey = RandomNumberGenerator.GetBytes(32);
        using var signer = new LogCheckpointSigner(hmacKey);

        var cp = signer.CreateCheckpoint("tail-hash-002", 50);
        // init-only 属性不可变，创建篡改副本（保留原签名，修改记录数）
        var tampered = new LogCheckpoint
        {
            ChainTailHash = cp.ChainTailHash,
            RecordCount = 999,
            CreatedAt = cp.CreatedAt,
            Signature = cp.Signature
        };

        Assert.False(signer.VerifyCheckpoint(tampered));
    }

    [Fact]
    public void LogCheckpointSigner_VerifyCheckpoint_TamperedTailHash_ReturnsFalse()
    {
        var hmacKey = RandomNumberGenerator.GetBytes(32);
        using var signer = new LogCheckpointSigner(hmacKey);

        var cp = signer.CreateCheckpoint("original-tail", 50);
        // init-only 属性不可变，创建篡改副本（保留原签名，修改链尾 Hash）
        var tampered = new LogCheckpoint
        {
            ChainTailHash = "tampered-tail",
            RecordCount = cp.RecordCount,
            CreatedAt = cp.CreatedAt,
            Signature = cp.Signature
        };

        Assert.False(signer.VerifyCheckpoint(tampered));
    }

    [Fact]
    public void LogCheckpointSigner_VerifyContinuity_NoPreviousCheckpoint_ReturnsSuccess()
    {
        var hmacKey = RandomNumberGenerator.GetBytes(32);
        using var signer = new LogCheckpointSigner(hmacKey);

        var result = signer.VerifyContinuity(null, "current-tail");
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void LogCheckpointSigner_VerifyContinuity_ValidPreviousCheckpoint_ReturnsSuccess()
    {
        var hmacKey = RandomNumberGenerator.GetBytes(32);
        using var signer = new LogCheckpointSigner(hmacKey);

        var cp = signer.CreateCheckpoint("previous-tail", 100);
        var result = signer.VerifyContinuity(cp, "previous-tail");

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void LogCheckpointSigner_VerifyContinuity_TamperedPreviousCheckpoint_ReturnsFailure()
    {
        var hmacKey = RandomNumberGenerator.GetBytes(32);
        using var signer = new LogCheckpointSigner(hmacKey);

        var cp = signer.CreateCheckpoint("previous-tail", 100);
        // init-only 属性不可变，创建篡改副本（保留原签名，修改记录数使签名失效）
        var tampered = new LogCheckpoint
        {
            ChainTailHash = cp.ChainTailHash,
            RecordCount = 0,
            CreatedAt = cp.CreatedAt,
            Signature = cp.Signature
        };

        var result = signer.VerifyContinuity(tampered, "current-tail");
        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCode.SignatureInvalid, result.ErrorCode);
    }

    [Fact]
    public void LogCheckpointSigner_DifferentKeys_ProduceDifferentSignatures()
    {
        var key1 = RandomNumberGenerator.GetBytes(32);
        var key2 = RandomNumberGenerator.GetBytes(32);

        using var signer1 = new LogCheckpointSigner(key1);
        using var signer2 = new LogCheckpointSigner(key2);

        var cp1 = signer1.CreateCheckpoint("same-tail", 100);
        var cp2 = signer2.CreateCheckpoint("same-tail", 100);

        Assert.NotEqual(cp1.Signature, cp2.Signature);
    }

    // ==================== EventLogAnchor ====================

    [Fact]
    public void EventLogAnchor_Initialize_DoesNotThrow()
    {
        var anchor = new EventLogAnchor("WinknowTest_" + Guid.NewGuid().ToString("N")[..8]);
        var result = anchor.Initialize();

        // 非管理员可能失败，但不应抛异常
        Assert.NotNull(result);
        anchor.Dispose();
    }

    [Fact]
    public void EventLogAnchor_WriteAnchor_DegradedMode_DoesNotThrow()
    {
        var anchor = new EventLogAnchor("WinknowTest_" + Guid.NewGuid().ToString("N")[..8]);
        var result = anchor.WriteAnchor("Test event", eventId: 9999);

        // 可能成功或降级失败，但不应抛异常
        Assert.NotNull(result);
        anchor.Dispose();
    }

    // ==================== DataRetentionManager ====================

    [Fact]
    public void DataRetentionManager_PurgeExpired_NoDatabase_ReturnsZero()
    {
        var dbPath = NewTempDb();
        var mgr = new DataRetentionManager(dbPath);

        var result = mgr.PurgeExpired();

        Assert.True(result.IsSuccess);
        Assert.Equal(0, result.Data);
    }

    [Fact]
    public void DataRetentionManager_PurgeExpired_WithExpiredRecords_DeletesRecords()
    {
        var dbPath = NewTempDb();
        try
        {
            // 创建审计表并插入过期记录
            using (var conn = new SqliteConnection($"Data Source={dbPath}"))
            {
                conn.Open();
                conn.Execute("CREATE TABLE maintenance_audit (id INTEGER PRIMARY KEY, timestamp TEXT, action TEXT)");
                var oldTimestamp = DateTimeOffset.UtcNow.AddDays(-60).ToString("O");
                conn.Execute("INSERT INTO maintenance_audit (timestamp, action) VALUES (@Ts, @Act)",
                    new { Ts = oldTimestamp, Act = "old-action" });
            }

            var mgr = new DataRetentionManager(dbPath, retentionDays: 30);
            var result = mgr.PurgeExpired();

            Assert.True(result.IsSuccess);
            Assert.Equal(1, result.Data);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (File.Exists(dbPath)) File.Delete(dbPath);
        }
    }

    [Fact]
    public void DataRetentionManager_PurgeExpired_WithRecentRecords_DeletesNothing()
    {
        var dbPath = NewTempDb();
        try
        {
            using (var conn = new SqliteConnection($"Data Source={dbPath}"))
            {
                conn.Open();
                conn.Execute("CREATE TABLE maintenance_audit (id INTEGER PRIMARY KEY, timestamp TEXT, action TEXT)");
                var recentTimestamp = DateTimeOffset.UtcNow.AddDays(-1).ToString("O");
                conn.Execute("INSERT INTO maintenance_audit (timestamp, action) VALUES (@Ts, @Act)",
                    new { Ts = recentTimestamp, Act = "recent-action" });
            }

            var mgr = new DataRetentionManager(dbPath, retentionDays: 30);
            var result = mgr.PurgeExpired();

            Assert.True(result.IsSuccess);
            Assert.Equal(0, result.Data);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (File.Exists(dbPath)) File.Delete(dbPath);
        }
    }

    [Fact]
    public void DataRetentionManager_SecureDeleteFile_NonExistentFile_ReturnsSuccess()
    {
        var mgr = new DataRetentionManager(NewTempDb());
        var result = mgr.SecureDeleteFile(Path.Combine(Path.GetTempPath(), "nonexistent_" + Guid.NewGuid().ToString("N") + ".tmp"));

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void DataRetentionManager_SecureDeleteFile_ExistingFile_DeletesFile()
    {
        var filePath = NewTempFile(".tmp");
        File.WriteAllText(filePath, "sensitive data that needs secure deletion");
        var mgr = new DataRetentionManager(NewTempDb());

        var result = mgr.SecureDeleteFile(filePath);

        Assert.True(result.IsSuccess);
        Assert.False(File.Exists(filePath));
    }

    [Fact]
    public void DataRetentionManager_RetentionDays_DefaultIs30()
    {
        var mgr = new DataRetentionManager(NewTempDb());
        Assert.Equal(30, mgr.RetentionDays);
    }

    [Fact]
    public void DataRetentionManager_RetentionDays_CustomValueApplied()
    {
        var mgr = new DataRetentionManager(NewTempDb(), retentionDays: 90);
        Assert.Equal(90, mgr.RetentionDays);
    }

    [Fact]
    public void DataRetentionManager_GetDatabaseSize_NoFile_ReturnsZero()
    {
        var mgr = new DataRetentionManager(NewTempDb());
        Assert.Equal(0, mgr.GetDatabaseSize());
    }

    // ==================== PrivacyPolicy ====================

    [Theory]
    [InlineData("Password", false)]
    [InlineData("PrivateKey", false)]
    [InlineData("RecoveryCode", false)]
    [InlineData("SourceCode", false)]
    [InlineData("WebPageContent", false)]
    [InlineData("Token", false)]
    [InlineData("ProcessName", true)]
    [InlineData("DeviceId", true)]
    [InlineData("Timestamp", true)]
    public void PrivacyPolicy_IsFieldAllowed_FiltersCorrectly(string fieldName, bool expected)
    {
        Assert.Equal(expected, PrivacyPolicy.IsFieldAllowed(fieldName));
    }

    [Theory]
    [InlineData("DeviceId", true)]
    [InlineData("ProcessName", true)]
    [InlineData("Timestamp", true)]
    [InlineData("WebsiteDomain", true)]
    [InlineData("Password", false)]
    [InlineData("SourceCode", false)]
    [InlineData("CustomField", false)]
    public void PrivacyPolicy_IsCollectedByDefault_FiltersCorrectly(string fieldName, bool expected)
    {
        Assert.Equal(expected, PrivacyPolicy.IsCollectedByDefault(fieldName));
    }

    [Fact]
    public void PrivacyPolicy_FilterFields_RemovesExcludedFields()
    {
        var fields = new Dictionary<string, string?>
        {
            { "DeviceId", "device-001" },
            { "ProcessName", "powershell.exe" },
            { "Password", "secret123" },
            { "SourceCode", "var x = 1;" },
            { "Timestamp", "2026-08-29T10:00:00Z" }
        };

        var filtered = PrivacyPolicy.FilterFields(fields);

        Assert.Equal(3, filtered.Count);
        Assert.Contains("DeviceId", filtered.Keys);
        Assert.Contains("ProcessName", filtered.Keys);
        Assert.Contains("Timestamp", filtered.Keys);
        Assert.DoesNotContain("Password", filtered.Keys);
        Assert.DoesNotContain("SourceCode", filtered.Keys);
    }

    [Fact]
    public void PrivacyPolicy_GetSummary_ContainsKeyPhrases()
    {
        var summary = PrivacyPolicy.GetSummary();

        Assert.Contains("Winknow V7.0 隐私声明", summary);
        Assert.Contains("网页正文", summary);
        Assert.Contains("学生代码正文", summary);
        Assert.Contains("密码", summary);
        Assert.Contains("AES-256-GCM", summary);
        Assert.Contains("哈希链", summary);
    }

    [Fact]
    public void PrivacyPolicy_ExcludedFields_ContainsAllCredentialTypes()
    {
        Assert.Contains("Password", PrivacyPolicy.ExcludedFields);
        Assert.Contains("PrivateKey", PrivacyPolicy.ExcludedFields);
        Assert.Contains("RecoveryCode", PrivacyPolicy.ExcludedFields);
        Assert.Contains("Token", PrivacyPolicy.ExcludedFields);
    }

    [Fact]
    public void PrivacyPolicy_ExcludedFields_ContainsAllContentTypes()
    {
        Assert.Contains("WebPageContent", PrivacyPolicy.ExcludedFields);
        Assert.Contains("SourceCode", PrivacyPolicy.ExcludedFields);
        Assert.Contains("StudentCode", PrivacyPolicy.ExcludedFields);
    }
}
