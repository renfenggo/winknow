using System.IO;
using System.Threading;
using Winknow.Core.Results;
using Winknow.Logging;
using Winknow.Security;

namespace Winknow.Security.Tests;

/// <summary>
/// 第 6 周"维护模式与授权卸载"回归测试。
/// 覆盖验收项：
/// - 无授权不能进入维护模式（密码/TOTP/恢复码错误均失败）
/// - 恢复码不能重复使用（VerifyAndConsume 第二次返回 false）
/// - 维护超时后自动恢复保护（Timer 触发 OnExit(true)）
/// </summary>
public class Week6MaintenanceTests
{
    private const string MaintenancePwd = "Passw0rd!";
    private static readonly byte[] SessionSecret = new byte[20];
    private static readonly string PasswordHash = MaintenancePassword.Hash(MaintenancePwd);

    private static string NewTempFile() => Path.Combine(Path.GetTempPath(), $"wk6_{Guid.NewGuid():N}.json");

    private static string NewTempDb() => Path.Combine(Path.GetTempPath(), $"wk6_{Guid.NewGuid():N}.db");

    [Fact]
    public void MaintenancePassword_Hash_Verify_CorrectPassword_Succeeds()
    {
        Assert.True(MaintenancePassword.Verify(MaintenancePwd, PasswordHash));
    }

    [Fact]
    public void MaintenancePassword_Verify_WrongPassword_Fails()
    {
        Assert.False(MaintenancePassword.Verify("wrong-password", PasswordHash));
    }

    [Fact]
    public void MaintenancePassword_Verify_InvalidHashFormat_Fails()
    {
        Assert.False(MaintenancePassword.Verify(MaintenancePwd, "garbage"));
    }

    [Fact]
    public void MaintenancePassword_Hash_DifferentSalt_DifferentHash()
    {
        var h1 = MaintenancePassword.Hash(MaintenancePwd);
        var h2 = MaintenancePassword.Hash(MaintenancePwd);
        Assert.NotEqual(h1, h2);
    }

    [Fact]
    public void TotpGenerator_GenerateCode_Is6Digits()
    {
        var code = TotpGenerator.GenerateCode(SessionSecret);
        Assert.Equal(6, code.Length);
        Assert.All(code.ToCharArray(), c => Assert.True(char.IsDigit(c)));
    }

    [Fact]
    public void TotpGenerator_Verify_CorrectCode_Succeeds()
    {
        var now = DateTimeOffset.UtcNow;
        var code = TotpGenerator.GenerateCode(SessionSecret, now);
        Assert.True(TotpGenerator.Verify(SessionSecret, code, now));
    }

    [Fact]
    public void TotpGenerator_Verify_WrongCode_Fails()
    {
        Assert.False(TotpGenerator.Verify(SessionSecret, "999999"));
    }

    [Fact]
    public void TotpGenerator_Verify_WrongLength_Fails()
    {
        Assert.False(TotpGenerator.Verify(SessionSecret, "12345"));
    }

    [Fact]
    public void TotpGenerator_Base32_RoundTrip()
    {
        var original = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        var encoded = "AEBAGBAFAYDQQCIK";
        var decoded = TotpGenerator.Base32Decode(encoded);
        Assert.Equal(original, decoded);
    }

    [Fact]
    public void RecoveryCodeStore_GenerateCodes_ReturnsRequestedCount()
    {
        var store = new RecoveryCodeStore(NewTempFile());
        var codes = store.GenerateCodes(5);
        Assert.Equal(5, codes.Count);
        Assert.Equal(5, store.RemainingCount());
    }

    [Fact]
    public void RecoveryCodeStore_VerifyAndConsume_Success_Then_SecondUse_Fails()
    {
        var store = new RecoveryCodeStore(NewTempFile());
        var codes = store.GenerateCodes(3);
        var first = codes[0];

        Assert.True(store.VerifyAndConsume(first));
        Assert.Equal(2, store.RemainingCount());
        // 验收：恢复码不能重复使用
        Assert.False(store.VerifyAndConsume(first));
        Assert.Equal(2, store.RemainingCount());
    }

    [Fact]
    public void RecoveryCodeStore_VerifyAndConsume_WrongCode_Fails()
    {
        var store = new RecoveryCodeStore(NewTempFile());
        store.GenerateCodes(3);
        Assert.False(store.VerifyAndConsume("XXXX-XXXX-XXXX-XXXX"));
    }

    [Fact]
    public void RecoveryCodeStore_VerifyAndConsume_CaseInsensitive()
    {
        var store = new RecoveryCodeStore(NewTempFile());
        var codes = store.GenerateCodes(1);
        Assert.True(store.VerifyAndConsume(codes[0].ToLowerInvariant()));
    }

    [Fact]
    public void MaintenanceSession_Enter_CorrectCredentials_Activates()
    {
        var t = BuildSession();
        var code = TotpGenerator.GenerateCode(SessionSecret);
        var r = t.Session.Enter(MaintenancePwd, code, "admin", "test");
        Assert.True(r.IsSuccess);
        Assert.True(t.Session.IsActive);
        Assert.True(t.EnterCalled.Value);
        t.Session.Exit("admin");
    }

    [Fact]
    public void MaintenanceSession_Enter_WrongPassword_Fails_Unauthorized()
    {
        var t = BuildSession();
        var code = TotpGenerator.GenerateCode(SessionSecret);
        var r = t.Session.Enter("wrong", code, "admin", "test");
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.Unauthorized, r.ErrorCode);
        Assert.False(t.Session.IsActive);
    }

    [Fact]
    public void MaintenanceSession_Enter_WrongTotp_Fails_Unauthorized()
    {
        var t = BuildSession();
        var r = t.Session.Enter(MaintenancePwd, "000000", "admin", "test");
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.Unauthorized, r.ErrorCode);
    }

    [Fact]
    public void MaintenanceSession_EnterWithRecoveryCode_Success_And_OneTimeOnly()
    {
        // 共享同一个 store，验证恢复码一次性
        var storePath = NewTempFile();
        var store = new RecoveryCodeStore(storePath);
        var codes = store.GenerateCodes(3);
        var first = codes[0];

        var t1 = BuildSession(existingStore: store);
        var r1 = t1.Session.EnterWithRecoveryCode(first, "admin", "emergency");
        Assert.True(r1.IsSuccess);
        Assert.True(t1.Session.IsActive);
        t1.Session.Exit("admin");

        // 同一恢复码再次使用（同 store）应失败
        var t2 = BuildSession(existingStore: store);
        var r2 = t2.Session.EnterWithRecoveryCode(first, "admin", "emergency2");
        Assert.False(r2.IsSuccess);
        Assert.Equal(ErrorCode.Unauthorized, r2.ErrorCode);
    }

    [Fact]
    public void MaintenanceSession_EnterWithRecoveryCode_WrongCode_Fails()
    {
        var t = BuildSession();
        var r = t.Session.EnterWithRecoveryCode("XXXX-XXXX-XXXX-XXXX", "admin", "bad");
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.Unauthorized, r.ErrorCode);
    }

    [Fact]
    public void MaintenanceSession_Reentry_Fails()
    {
        var t = BuildSession();
        var code = TotpGenerator.GenerateCode(SessionSecret);
        t.Session.Enter(MaintenancePwd, code, "admin", "test");
        var r = t.Session.Enter(MaintenancePwd, code, "admin", "again");
        Assert.False(r.IsSuccess);
        t.Session.Exit("admin");
    }

    [Fact]
    public void MaintenanceSession_Exit_Deactivates()
    {
        var t = BuildSession();
        var code = TotpGenerator.GenerateCode(SessionSecret);
        t.Session.Enter(MaintenancePwd, code, "admin", "test");
        var r = t.Session.Exit("admin");
        Assert.True(r.IsSuccess);
        Assert.False(t.Session.IsActive);
        Assert.True(t.ExitCalled.Value);
    }

    [Fact]
    public void MaintenanceSession_Timeout_AutoExits()
    {
        var t = BuildSession(timeoutMinutes: 0);
        var code = TotpGenerator.GenerateCode(SessionSecret);
        t.Session.Enter(MaintenancePwd, code, "admin", "timeout-test");
        // 等待 Timer 回调（dueMs=0，但调度有延迟）
        for (var i = 0; i < 30 && t.Session.IsActive; i++)
        {
            Thread.Sleep(100);
        }
        Assert.False(t.Session.IsActive);
        Assert.True(t.ExitCalled.Value);
    }

    [Fact]
    public void MaintenanceSession_Extend_NegativeMinutes_Fails()
    {
        var t = BuildSession();
        var r = t.Session.Extend(-5, "admin");
        Assert.False(r.IsSuccess);
        Assert.Equal(ErrorCode.InvalidParameter, r.ErrorCode);
    }

    [Fact]
    public void MaintenanceSession_Extend_WhenInactive_Fails()
    {
        var t = BuildSession();
        var r = t.Session.Extend(10, "admin");
        Assert.False(r.IsSuccess);
    }

    [Fact]
    public void MaintenanceAuditLog_RecordEntry_QueryRecent()
    {
        var log = new MaintenanceAuditLog(NewTempDb());
        log.RecordEntry("admin", "enter", "test", "ok");
        log.RecordEntry("admin", "exit", null, "done");

        var entries = log.QueryRecent(10);
        Assert.Equal(2, entries.Count);
        Assert.Equal("exit", entries[0].Operation); // 倒序
        Assert.Equal("enter", entries[1].Operation);
        Assert.Equal("admin", entries[0].Actor);
    }

    private static TestSession BuildSession(int timeoutMinutes = 15, RecoveryCodeStore? existingStore = null)
    {
        var enterCalled = new Flag();
        var exitCalled = new Flag();
        RecoveryCodeStore store;
        IReadOnlyList<string> codes;
        if (existingStore is null)
        {
            store = new RecoveryCodeStore(NewTempFile());
            codes = store.GenerateCodes(3);
        }
        else
        {
            store = existingStore;
            codes = Array.Empty<string>(); // 调用方已自行生成
        }

        var session = new MaintenanceSession(new MaintenanceSessionOptions
        {
            PasswordHash = PasswordHash,
            TotpSecret = SessionSecret,
            RecoveryCodes = store,
            DefaultTimeoutMinutes = timeoutMinutes,
            OnEnter = () => enterCalled.Set(),
            OnExit = _ => exitCalled.Set(),
            OnAudit = (_, _, _, _) => { }
        });

        return new TestSession(session, codes, enterCalled, exitCalled);
    }

    private sealed record TestSession(
        MaintenanceSession Session,
        IReadOnlyList<string> Codes,
        Flag EnterCalled,
        Flag ExitCalled);

    private sealed class Flag
    {
        private int _value;
        public bool Value => _value != 0;
        public void Set() => Interlocked.Exchange(ref _value, 1);
    }
}
