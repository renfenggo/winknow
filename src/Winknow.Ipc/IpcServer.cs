using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Extensions.Logging;
using Winknow.Core;
using Winknow.Core.Results;

namespace Winknow.Ipc;

/// <summary>
/// 握手上下文（服务端准入回调入参，P2-01）。
/// </summary>
public sealed class IpcHandshakeContext
{
    /// <summary>服务端 Impersonation 取得的真实 SID。</summary>
    public required string RealSid { get; init; }

    /// <summary>客户端进程 PID。</summary>
    public required int Pid { get; init; }

    /// <summary>客户端所在 WTS 会话 ID。</summary>
    public required int SessionId { get; init; }

    /// <summary>客户端声明的设备 ID。</summary>
    public string DeviceId { get; init; } = string.Empty;

    /// <summary>客户端组件版本。</summary>
    public string ClientVersion { get; init; } = string.Empty;
}

/// <summary>
/// 已通过握手的连接上下文（消息回调入参，含会话路由信息）。
/// </summary>
public sealed class IpcConnectionContext
{
    /// <summary>真实 SID（Impersonation 凭证）。</summary>
    public required string RealSid { get; init; }

    /// <summary>消息体声明的 SID（仅审计）。</summary>
    public string ClaimedSid { get; init; } = string.Empty;

    /// <summary>客户端进程 PID。</summary>
    public required int Pid { get; init; }

    /// <summary>WTS 会话 ID（会话路由键）。</summary>
    public required int SessionId { get; init; }

    /// <summary>连接建立时间。</summary>
    public required DateTimeOffset ConnectedAt { get; init; }

    /// <summary>服务端随机挑战（base64）。</summary>
    public string ServerNonce { get; init; } = string.Empty;
}

/// <summary>
/// 单个已认证的客户端连接（服务端视角，支持向客户端推送与请求-响应）。
/// </summary>
public sealed class IpcConnection : IAsyncDisposable
{
    private readonly NamedPipeServerStream _stream;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly ConcurrentDictionary<uint, TaskCompletionSource<IpcMessage>> _pendingResponses = new();

    internal IpcConnection(NamedPipeServerStream stream, IpcConnectionContext context)
    {
        _stream = stream;
        Context = context;
    }

    /// <summary>连接上下文。</summary>
    public IpcConnectionContext Context { get; }

    /// <summary>底层管道是否仍然连通。</summary>
    public bool IsConnected => _stream.IsConnected;

    /// <summary>向客户端发送单向消息。</summary>
    public async Task<Result<object>> SendAsync(ushort messageType, byte[] payload, CancellationToken cancellationToken = default)
    {
        if (!_stream.IsConnected)
        {
            return Result<object>.Failure(ErrorCode.IpcConnectionFailed, "Connection closed.");
        }

        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var message = IpcMessage.Create(0, messageType, payload);
            await IpcServer.WriteFramedAsync(_stream, message, cancellationToken).ConfigureAwait(false);
            return Result<object>.Success(new object());
        }
        catch (Exception ex)
        {
            return Result<object>.Failure(ErrorCode.IpcConnectionFailed, ex.Message);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <summary>
    /// 发送请求并等待匹配的响应（RequestId + expectedResponseType）。
    /// </summary>
    public async Task<Result<IpcMessage>> SendRequestAsync(
        ushort messageType,
        byte[] payload,
        ushort expectedResponseType,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        if (!_stream.IsConnected)
        {
            return Result<IpcMessage>.Failure(ErrorCode.IpcConnectionFailed, "Connection closed.");
        }

        var requestId = IpcServer.NextServerRequestId();
        var tcs = new TaskCompletionSource<IpcMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_pendingResponses.TryAdd(requestId, tcs))
        {
            return Result<IpcMessage>.Failure(ErrorCode.InvalidParameter, "Duplicate request id.");
        }

        try
        {
            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var message = IpcMessage.Create(requestId, messageType, payload);
                await IpcServer.WriteFramedAsync(_stream, message, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _writeLock.Release();
            }

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(timeout ?? TimeSpan.FromMilliseconds(IpcConstants.RequestTimeoutMs));

            var completed = await Task.WhenAny(tcs.Task, Task.Delay(Timeout.Infinite, timeoutCts.Token)).ConfigureAwait(false);
            if (completed == tcs.Task)
            {
                return Result<IpcMessage>.Success(await tcs.Task.ConfigureAwait(false));
            }

            return Result<IpcMessage>.Failure(ErrorCode.IpcTimeout, "Request timed out waiting for response.");
        }
        catch (OperationCanceledException)
        {
            return Result<IpcMessage>.Failure(ErrorCode.IpcTimeout, "Request cancelled or timed out.");
        }
        catch (Exception ex)
        {
            return Result<IpcMessage>.Failure(ErrorCode.IpcConnectionFailed, ex.Message);
        }
        finally
        {
            _pendingResponses.TryRemove(requestId, out _);
        }
    }

    /// <summary>尝试把收到的消息派发给等待中的请求（响应消息）。</summary>
    internal bool TryCompletePending(IpcMessage message)
    {
        if (_pendingResponses.TryGetValue(message.RequestId, out var tcs))
        {
            return tcs.TrySetResult(message);
        }
        return false;
    }

    /// <summary>失败所有挂起请求（连接关闭时）。</summary>
    internal void FailPending(Exception reason)
    {
        foreach (var kvp in _pendingResponses)
        {
            kvp.Value.TrySetException(reason);
            _pendingResponses.TryRemove(kvp.Key, out _);
        }
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        FailPending(new IOException("Connection closed."));
        await _stream.DisposeAsync().ConfigureAwait(false);
        _writeLock.Dispose();
    }
}

/// <summary>
/// Named Pipe 服务端（P2-01 重构）。
///
/// 连接模型（ADR-001/TD-05）：
/// 1. Pipe ACL 创建时一次性设置：SYSTEM/Administrators 完全控制、Authenticated Users 读写
///    （管道 ACL 不支持按 SID 动态放行，登记学生准入在应用层完成）。
/// 2. 连接建立 → 服务端 Impersonation 取真实 SID → 首条消息必须是 Hello（版本/PID/SessionId/DeviceId/ClientNonce）。
/// 3. 准入 = 真实 SID 在允许集合且应用层回调（会话登记表）放行 → 回 HelloAck（含 ServerNonce）。
/// 4. 通过后进入消息循环：每条消息按真实 SID 验证 + 连接级 RequestId 单调 + 全局 Nonce 防重放。
/// </summary>
public sealed class IpcServer : IAsyncDisposable
{
    private readonly string _pipeName;
    private readonly IpcAuthenticator _authenticator;
    private readonly Func<IpcHandshakeContext, bool>? _admissionCheck;
    private readonly string? _expectedDeviceId;
    private readonly ILogger<IpcServer>? _logger;
    private readonly CancellationTokenSource _cts = new();
    private readonly ConcurrentDictionary<int, IpcConnection> _sessionConnections = new();
    private static uint _serverRequestIdCounter;
    private Task? _listenTask;

    /// <summary>接收到有效消息时触发（含发送方连接上下文）。</summary>
    public event Func<IpcMessage, IpcConnectionContext, CancellationToken, Task>? MessageReceived;

    /// <summary>连接通过握手并注册后触发（SessionManager 订阅用于会话路由）。</summary>
    public event Action<IpcConnection>? ConnectionOpened;

    /// <summary>连接关闭（断开/失败）后触发。</summary>
    public event Action<IpcConnection>? ConnectionClosed;

    /// <summary>
    /// 创建 Named Pipe 服务端。
    /// </summary>
    /// <param name="pipeName">管道名。</param>
    /// <param name="authenticator">身份验证器（真实 SID 验证与 Nonce 防重放）。</param>
    /// <param name="logger">可选日志。</param>
    /// <param name="admissionCheck">可选应用层准入回调（如会话登记表比对）；返回 false 拒绝握手。</param>
    /// <param name="expectedDeviceId">可选本机设备 ID（握手时校验客户端 DeviceId）。</param>
    public IpcServer(
        string pipeName,
        IpcAuthenticator authenticator,
        ILogger<IpcServer>? logger = null,
        Func<IpcHandshakeContext, bool>? admissionCheck = null,
        string? expectedDeviceId = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(pipeName);
        ArgumentNullException.ThrowIfNull(authenticator);

        _pipeName = pipeName;
        _authenticator = authenticator;
        _logger = logger;
        _admissionCheck = admissionCheck;
        _expectedDeviceId = expectedDeviceId;
    }

    /// <summary>
    /// 启动监听循环。
    /// </summary>
    public Task StartAsync()
    {
        if (_listenTask is not null)
        {
            throw new InvalidOperationException("IPC server is already running.");
        }

        _listenTask = ListenLoopAsync(_cts.Token);
        return Task.CompletedTask;
    }

    /// <summary>
    /// 停止监听。
    /// </summary>
    public async Task StopAsync()
    {
        _cts.Cancel();
        if (_listenTask is not null)
        {
            await _listenTask.ConfigureAwait(false);
        }
    }

    /// <summary>按 WTS 会话 ID 查找活动连接（向指定会话 Agent 推送命令用）。</summary>
    public bool TryGetSession(int sessionId, out IpcConnection? connection)
    {
        return _sessionConnections.TryGetValue(sessionId, out connection) && connection is { IsConnected: true };
    }

    /// <summary>当前已注册会话的连接数（监控/测试用）。</summary>
    public int ActiveSessionCount => _sessionConnections.Count;

    internal static uint NextServerRequestId() => Interlocked.Increment(ref _serverRequestIdCounter);

    internal static async Task WriteFramedAsync(Stream stream, IpcMessage message, CancellationToken cancellationToken)
    {
        var bytes = message.ToBytes();
        var lengthPrefix = new byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(lengthPrefix, (uint)bytes.Length);

        await stream.WriteAsync(lengthPrefix, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task ListenLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            NamedPipeServerStream pipeStream;
            try
            {
                pipeStream = CreateSecurePipeStream();
            }
            catch (Exception ex)
            {
                // 管道实例创建失败（如非 SYSTEM 进程受 ACL 限制无法创建后续实例）：
                // 不让异常逃出监听循环，延迟后重试；收到停止请求则退出。
                _logger?.LogError(ex, "IPC server failed to create pipe instance {PipeName}.", _pipeName);
                try
                {
                    await Task.Delay(500, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                continue;
            }

            try
            {
                await pipeStream.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);

                // 处理连接（不阻塞监听循环）
                _ = HandleConnectionAsync(pipeStream, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                pipeStream.Dispose();
                break;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "IPC server accept failed for pipe {PipeName}.", _pipeName);
                pipeStream.Dispose();
            }
        }
    }

    private NamedPipeServerStream CreateSecurePipeStream()
    {
        // Pipe ACL（创建时一次性设置，ADR-001/TD-05）：
        // SYSTEM/Administrators 完全控制 + Authenticated Users 最小读写（拒绝匿名/来宾连接）
        var security = new PipeSecurity();

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));

        return NamedPipeServerStreamAcl.Create(
            _pipeName,
            PipeDirection.InOut,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            inBufferSize: 4096,
            outBufferSize: 4096,
            pipeSecurity: security,
            inheritability: HandleInheritability.None);
    }

    private async Task HandleConnectionAsync(NamedPipeServerStream pipeStream, CancellationToken cancellationToken)
    {
        IpcConnection? connection = null;
        var realSid = string.Empty;

        try
        {
            using (pipeStream)
            {
                // ── 握手阶段（TD-05）──
                // Windows 管道语义：服务端必须先从管道读取一次客户端数据（Hello），
                // 之后 RunAsClient（ImpersonateNamedPipeClient）才能取得客户端身份。
                IpcMessage? hello;
                using (var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
                {
                    handshakeCts.CancelAfter(IpcConstants.HandshakeTimeoutMs);
                    var first = await ReadMessageAsync(pipeStream, handshakeCts.Token).ConfigureAwait(false);
                    if (!first.IsSuccess)
                    {
                        _logger?.LogWarning("IPC handshake failed: {Error}", first.ErrorMessage);
                        return;
                    }
                    hello = first.Data!;
                }

                realSid = GetImpersonatedSid(pipeStream);
                if (string.IsNullOrEmpty(realSid))
                {
                    _logger?.LogWarning("IPC handshake rejected: no impersonated identity.");
                    return;
                }

                if (hello.MessageType != IpcConstants.MessageTypeHello ||
                    hello.Payload.Length == 0 ||
                    hello.Payload.Length > IpcConstants.MaxHandshakePayloadBytes)
                {
                    _logger?.LogWarning("IPC handshake rejected: first message must be a valid Hello (type=0x{Type:X4}, len={Len}).",
                        hello.MessageType, hello.Payload.Length);
                    return;
                }

                var helloPayload = IpcProtocol.Decode<HelloPayload>(hello.Payload);
                if (helloPayload is null || helloPayload.ProtocolVersion != IpcMessage.CurrentVersion)
                {
                    _logger?.LogWarning("IPC handshake rejected: malformed Hello or unsupported version.");
                    return;
                }

                if (_expectedDeviceId is not null &&
                    !string.IsNullOrEmpty(helloPayload.DeviceId) &&
                    !SecurityUtils.FixedTimeEquals(helloPayload.DeviceId, _expectedDeviceId))
                {
                    _logger?.LogWarning("IPC handshake rejected: device id mismatch (sid={Sid}, session={Session}).",
                        realSid, helloPayload.SessionId);
                    return;
                }

                // 应用层准入：真实 SID 白名单 + 会话登记表回调（登记学生会话判定）
                var handshakeContext = new IpcHandshakeContext
                {
                    RealSid = realSid,
                    Pid = helloPayload.Pid,
                    SessionId = helloPayload.SessionId,
                    DeviceId = helloPayload.DeviceId,
                    ClientVersion = helloPayload.ClientVersion
                };

                var granted = _authenticator.IsSidAllowed(realSid) &&
                              (_admissionCheck?.Invoke(handshakeContext) ?? true);

                var serverNonce = Convert.ToBase64String(SecurityUtils.GenerateNonce());
                var ack = new HelloAckPayload
                {
                    ProtocolVersion = IpcMessage.CurrentVersion,
                    Granted = granted,
                    Reason = granted ? null : "Access denied by admission policy.",
                    ServerNonce = serverNonce
                };

                var ackMessage = IpcMessage.CreateResponse(hello, IpcConstants.MessageTypeHelloAck, IpcProtocol.Encode(ack));
                if (!await TryWriteAsync(pipeStream, ackMessage, cancellationToken).ConfigureAwait(false))
                {
                    return;
                }

                if (!granted)
                {
                    // 审计：真实 SID、声明 PID/会话、拒绝原因
                    _logger?.LogWarning(
                        "IPC admission denied: sid={Sid} claimedPid={Pid} session={Session} version={Version}.",
                        realSid, helloPayload.Pid, helloPayload.SessionId, helloPayload.ClientVersion);
                    return;
                }

                _logger?.LogInformation(
                    "IPC connection granted: sid={Sid} pid={Pid} session={Session} version={Version}.",
                    realSid, helloPayload.Pid, helloPayload.SessionId, helloPayload.ClientVersion);

                connection = new IpcConnection(pipeStream, new IpcConnectionContext
                {
                    RealSid = realSid,
                    ClaimedSid = hello.SenderSid,
                    Pid = helloPayload.Pid,
                    SessionId = helloPayload.SessionId,
                    ConnectedAt = DateTimeOffset.UtcNow,
                    ServerNonce = serverNonce
                });

                // 注册会话路由（同会话重复连接以后到者为准）并广播
                _sessionConnections[connection.Context.SessionId] = connection;
                try
                {
                    ConnectionOpened?.Invoke(connection);
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "ConnectionOpened handler error (session={Session}).", connection.Context.SessionId);
                }

                // ── 消息循环：每条消息按真实 SID 验证 + 连接级防重放 ──
                var guard = new IpcConnectionGuard();
                while (pipeStream.IsConnected && !cancellationToken.IsCancellationRequested)
                {
                    var messageResult = await ReadMessageAsync(pipeStream, cancellationToken).ConfigureAwait(false);
                    if (!messageResult.IsSuccess)
                    {
                        break;
                    }

                    var message = messageResult.Data!;

                    // 响应消息（StatusAck 等）优先派发给挂起请求
                    if (connection.TryCompletePending(message))
                    {
                        continue;
                    }

                    var validation = _authenticator.ValidateMessage(message, realSid);
                    if (!validation.IsSuccess)
                    {
                        _logger?.LogWarning(
                            "IPC message rejected: {ErrorCode} {Message} (sid={Sid}, requestId={RequestId}, type=0x{Type:X4})",
                            validation.ErrorCode, validation.ErrorMessage, realSid, message.RequestId, message.MessageType);

                        var errorResponse = IpcMessage.CreateResponse(
                            message,
                            IpcConstants.MessageTypeError,
                            Encoding.UTF8.GetBytes(validation.ErrorMessage ?? "Unknown error"));
                        if (!await TryWriteAsync(pipeStream, errorResponse, cancellationToken).ConfigureAwait(false))
                        {
                            break;
                        }
                        continue;
                    }

                    if (!guard.Track(message.RequestId))
                    {
                        _logger?.LogWarning(
                            "IPC replay suspected: requestId={RequestId} not increasing on connection (sid={Sid}, type=0x{Type:X4}).",
                            message.RequestId, realSid, message.MessageType);

                        var replayResponse = IpcMessage.CreateResponse(
                            message,
                            IpcConstants.MessageTypeError,
                            Encoding.UTF8.GetBytes("RequestId replay detected."));
                        if (!await TryWriteAsync(pipeStream, replayResponse, cancellationToken).ConfigureAwait(false))
                        {
                            break;
                        }
                        continue;
                    }

                    if (MessageReceived is not null)
                    {
                        await MessageReceived.Invoke(message, connection.Context, cancellationToken).ConfigureAwait(false);
                    }
                }
            }
        }
        catch (OperationCanceledException)
        {
            // 正常关闭
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "IPC connection handler error (sid={Sid}).", realSid);
        }
        finally
        {
            if (connection is not null)
            {
                _sessionConnections.TryRemove(connection.Context.SessionId, out _);
                try
                {
                    ConnectionClosed?.Invoke(connection);
                }
                finally
                {
                    await connection.DisposeAsync().ConfigureAwait(false);
                }
            }
        }
    }

    private string GetImpersonatedSid(NamedPipeServerStream pipeStream)
    {
        var sid = string.Empty;
        try
        {
            // Pipe Impersonation：在客户端安全上下文中读取当前身份（仅取 SID，不做其他操作）。
            // RunAsClient 只接受无返回值委托，用闭包捕获结果。
            pipeStream.RunAsClient(() =>
            {
                sid = WindowsIdentity.GetCurrent().User?.Value ?? string.Empty;
            });
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "IPC impersonation failed, dropping connection.");
        }

        return sid;
    }

    private async Task<bool> TryWriteAsync(Stream stream, IpcMessage message, CancellationToken cancellationToken)
    {
        try
        {
            await WriteFramedAsync(stream, message, cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "IPC write failed, connection likely closed.");
            return false;
        }
    }

    private static async Task<Result<IpcMessage>> ReadMessageAsync(Stream stream, CancellationToken cancellationToken)
    {
        try
        {
            // 先读取长度前缀（4 字节，小端序）
            var lengthBuffer = new byte[4];
            var bytesRead = await ReadExactAsync(stream, lengthBuffer, 4, cancellationToken).ConfigureAwait(false);
            if (bytesRead < 4)
            {
                return Result<IpcMessage>.Failure(ErrorCode.IpcConnectionFailed, "Connection closed before length prefix.");
            }

            var messageLength = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(lengthBuffer);
            if (messageLength == 0 || messageLength > (uint)IpcConstants.MaxMessageLength)
            {
                return Result<IpcMessage>.Failure(ErrorCode.InvalidParameter, "Message length out of bounds.");
            }

            var messageBuffer = new byte[messageLength];
            bytesRead = await ReadExactAsync(stream, messageBuffer, (int)messageLength, cancellationToken).ConfigureAwait(false);
            if (bytesRead < messageLength)
            {
                return Result<IpcMessage>.Failure(ErrorCode.IpcConnectionFailed, "Connection closed before full message.");
            }

            var message = IpcMessage.FromBytes(messageBuffer);
            return Result<IpcMessage>.Success(message);
        }
        catch (OperationCanceledException)
        {
            return Result<IpcMessage>.Failure(ErrorCode.IpcTimeout, "Read timed out.");
        }
        catch (Exception ex)
        {
            return Result<IpcMessage>.Failure(ErrorCode.IpcConnectionFailed, ex.Message);
        }
    }

    private static async Task<int> ReadExactAsync(Stream stream, byte[] buffer, int count, CancellationToken cancellationToken)
    {
        var totalRead = 0;
        while (totalRead < count)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(totalRead, count - totalRead), cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }
            totalRead += read;
        }
        return totalRead;
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
        _cts.Dispose();
    }
}
