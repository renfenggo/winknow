using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Extensions.Logging;
using Winknow.Core.Results;
using Winknow.Ipc.Protocol;
using Winknow.Ipc.Session;

namespace Winknow.Ipc;

/// <summary>业务请求上下文（仅握手完成后触发）。</summary>
public sealed class IpcRequestContext
{
    /// <summary>原始请求帧（含帧头安全元数据与 payload）。</summary>
    public required IpcMessage Message { get; init; }

    /// <summary>连接会话（已协商能力、调用方身份）。</summary>
    public required IpcConnectionSession Session { get; init; }
}

/// <summary>
/// 已握手连接的注册项（R06 推送通道）：服务端主动下发帧与连接处理循环的
/// Ack/Response 写入共享同一管道流，须经 [WriteLock] 串行化，防止交错写坏帧。
/// </summary>
internal sealed class IpcConnectionRegistration : IAsyncDisposable
{
    public required NamedPipeServerStream Stream { get; init; }

    public required IpcConnectionSession Session { get; init; }

    public SemaphoreSlim WriteLock { get; } = new(1, 1);

    public async ValueTask DisposeAsync()
    {
        WriteLock.Dispose();
        await ValueTask.CompletedTask.ConfigureAwait(false);
    }
}

/// <summary>
/// Named Pipe 服务端。
///
/// 安全配置（见《V7.0 组件架构设计》第 6.2 节）：
/// - SYSTEM：完全控制
/// - Administrators：完全控制
/// - 当前会话用户：读写
/// - 其他：拒绝
///
/// M2 起引入连接期握手状态机（ADR-001）：首个业务帧必须是 ipc.handshake；
/// 版本不兼容/设备不匹配/身份不一致显式拒绝并断连。握手前发送业务帧返回
/// IPC_HANDSHAKE_REQUIRED（连接保留，可补握手）。旧帧类型（Heartbeat/策略等）
/// 保持既有 MessageReceived + Ack 行为以兼容 SessionAgent。
/// </summary>
public sealed class IpcServer : IAsyncDisposable
{
    private readonly string _pipeName;
    private readonly IpcAuthenticator _authenticator;
    private readonly IpcHandshakeValidator _handshakeValidator;
    private readonly ILogger<IpcServer>? _logger;
    private readonly CancellationTokenSource _cts = new();
    private readonly ConcurrentDictionary<string, IpcConnectionRegistration> _componentConnections =
        new(StringComparer.Ordinal);
    private Task? _listenTask;

    /// <summary>接收到有效消息（心跳与旧帧类型）时触发，服务端自动回 Ack。</summary>
    public event Func<IpcMessage, CancellationToken, Task>? MessageReceived;

    /// <summary>接收到业务请求帧（握手完成后）时触发；返回值作为 Response 帧回写。</summary>
    public event Func<IpcRequestContext, CancellationToken, Task<ResponseEnvelope>>? RequestReceived;

    /// <summary>指定组件当前是否有已握手的活跃连接（R06 推送通道查询）。</summary>
    public bool IsComponentConnected(string component) =>
        _componentConnections.TryGetValue(component, out var reg) && reg.Stream.IsConnected;

    /// <summary>
    /// 向指定组件的当前连接推送一帧（R06 服务端主动下发：锁屏遮罩等）。
    ///
    /// 推送帧 requestId 恒为 0（非请求-响应语义，客户端接收循环不校验）；
    /// 写入与连接处理循环的 Ack/Response 经连接写锁串行。无活跃连接或写入
    /// 失败返回 false（连接坏损由读循环自行发现并清理注册表）。
    /// </summary>
    public async Task<bool> TryPushToComponentAsync(
        string component, ushort messageType, byte[] payload, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(component);

        if (!_componentConnections.TryGetValue(component, out var registration)
            || !registration.Stream.IsConnected)
        {
            return false;
        }

        var serverSid = WindowsIdentity.GetCurrent().User?.Value ?? string.Empty;
        var frame = IpcMessage.Create(
            requestId: 0,
            messageType: messageType,
            payload: payload,
            senderSid: serverSid);

        try
        {
            await WriteMessageLockedAsync(registration, frame, cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or OperationCanceledException)
        {
            _logger?.LogWarning(ex, "IPC push to component {Component} failed.", component);
            return false;
        }
    }

    /// <summary>
    /// 创建 Named Pipe 服务端。
    /// </summary>
    public IpcServer(string pipeName, IpcAuthenticator authenticator, IpcHandshakeValidator handshakeValidator,
        ILogger<IpcServer>? logger = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(pipeName);
        ArgumentNullException.ThrowIfNull(authenticator);
        ArgumentNullException.ThrowIfNull(handshakeValidator);

        _pipeName = pipeName;
        _authenticator = authenticator;
        _handshakeValidator = handshakeValidator;
        _logger = logger;
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

    private async Task ListenLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            NamedPipeServerStream pipeStream;
            try
            {
                pipeStream = CreateSecurePipeStream();
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
            {
                // 创建后续实例失败不应让监听任务整体崩溃（原异常在 try 外传播，
                // 只会在 StopAsync 时上浮，极难定位）：记日志、短暂退避后重试
                _logger?.LogError(ex, "IPC server failed to create a pipe instance for {PipeName}; retrying.", _pipeName);
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
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
        // Pipe ACL permits only authenticated local users to establish a connection;
        // authorization is then bound to the impersonated SID, never to wire metadata.
        var security = new PipeSecurity();

        var systemIdentity = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        security.AddAccessRule(new PipeAccessRule(
            systemIdentity,
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        var adminsIdentity = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        security.AddAccessRule(new PipeAccessRule(
            adminsIdentity,
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        var usersIdentity = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
        security.AddAccessRule(new PipeAccessRule(
            usersIdentity,
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));

        // 创建后续实例需要对既有管道对象持有 CreatePipeInstance 权限：SYSTEM/Administrators
        // 规则已覆盖生产服务身份。若以其他本地身份运行（开发/测试环境下的普通用户，
        // UAC 非提升令牌中 Administrators SID 仅 deny-only），BuiltinUsers 的 ReadWrite 不含
        // CreatePipeInstance，首个客户端接入后监听循环创建第二实例将被 ACCESS DENIED，
        // 因此对非 SYSTEM 的当前运行身份授予完全控制。
        using var currentIdentity = WindowsIdentity.GetCurrent();
        var currentSid = currentIdentity.User;
        if (currentSid is not null && !currentSid.Equals(systemIdentity))
        {
            security.AddAccessRule(new PipeAccessRule(
                currentSid,
                PipeAccessRights.FullControl,
                AccessControlType.Allow));
        }

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
        try
        {
            using (pipeStream)
            {
                var session = new IpcConnectionSession();
                var serverSid = WindowsIdentity.GetCurrent().User?.Value ?? string.Empty;
                var registration = new IpcConnectionRegistration { Stream = pipeStream, Session = session };
                IpcConnectionRegistration? registered = null;

                try
                {
                    while (pipeStream.IsConnected && !cancellationToken.IsCancellationRequested)
                    {
                        var actualSenderSid = GetClientSid(pipeStream);
                        if (actualSenderSid is null)
                        {
                            _logger?.LogWarning("IPC connection rejected because the client identity could not be determined.");
                            break;
                        }

                        var messageResult = await ReadMessageAsync(pipeStream, cancellationToken).ConfigureAwait(false);
                        if (!messageResult.IsSuccess)
                        {
                            _logger?.LogWarning("IPC read failed: {Error}", messageResult.ErrorMessage);
                            break;
                        }

                        var message = messageResult.Data!;
                        var validation = _authenticator.ValidateMessage(message, actualSenderSid: actualSenderSid);
                        if (!validation.IsSuccess)
                        {
                            _logger?.LogWarning("IPC message rejected: {ErrorCode} {Message}",
                                validation.ErrorCode, validation.ErrorMessage);

                            // 帧级校验失败：JSON 错误信封（契约化 payload），连接保留供诊断与重试；
                            // 动态 SID 过期显式区分 IPC_SID_EXPIRED（ADR-002），其余归入未授权
                            var frameErrorCode = validation.ErrorCode == Winknow.Core.Results.ErrorCode.IpcSidExpired
                                ? IpcErrorCodes.IpcSidExpired
                                : IpcErrorCodes.IpcSidNotAuthorized;
                            await WriteErrorResponseLockedAsync(registration, message.RequestId,
                                frameErrorCode,
                                $"frame rejected: {validation.ErrorMessage}",
                                closeConnection: false, serverSid, cancellationToken).ConfigureAwait(false);
                            continue;
                        }

                        // 连接级 RequestId 单调检查（防乱序回退）：跨连接重放由 Nonce 全局查重承担，
                        // 同一 SID 的多客户端并发各自维护独立 RequestId 时钟（ADR-002），不可跨连接比较
                        if (session.LastSeenRequestId.HasValue && message.RequestId <= session.LastSeenRequestId.Value)
                        {
                            await WriteErrorResponseLockedAsync(registration, message.RequestId,
                                IpcErrorCodes.IpcReplayDetected,
                                "request id must strictly increase within a connection.",
                                closeConnection: false, serverSid, cancellationToken).ConfigureAwait(false);
                            continue;
                        }

                        session.LastSeenRequestId = message.RequestId;

                        switch (message.MessageType)
                        {
                            case IpcConstants.MessageTypeHandshake:
                            {
                                if (session.HandshakeCompleted)
                                {
                                    await WriteErrorResponseLockedAsync(registration, message.RequestId,
                                        IpcErrorCodes.InvalidArgument, "handshake already completed.",
                                        closeConnection: false, serverSid, cancellationToken).ConfigureAwait(false);
                                    break;
                                }

                                var outcome = _handshakeValidator.Handle(message.Payload, message.SenderSid);
                                _logger?.LogInformation(
                                    "IPC handshake {Result} for sid {Sid} component {Component}: capabilities [{Capabilities}]",
                                    outcome.Accepted ? "accepted" : "rejected",
                                    message.SenderSid,
                                    session.Component,
                                    string.Join(",", outcome.GrantedCapabilities));

                                await WriteResponseFrameLockedAsync(registration, message.RequestId, outcome.Response, serverSid, cancellationToken)
                                    .ConfigureAwait(false);

                                if (outcome.CloseConnection)
                                {
                                    return;
                                }

                                if (outcome.Accepted)
                                {
                                    session.HandshakeCompleted = true;
                                    session.GrantedCapabilities = outcome.GrantedCapabilities;
                                    session.SessionId = outcome.SessionId;
                                    session.CallerSid = message.SenderSid;
                                    session.Component = outcome.Component;

                                    // R06 推送通道注册：同组件新连接覆盖旧注册（旧连接断连时
                                    // identity check 防止误删新注册）
                                    _componentConnections[session.Component] = registration;
                                    registered = registration;
                                }

                                break;
                            }

                            case IpcConstants.MessageTypeRequest:
                            {
                                if (!session.HandshakeCompleted)
                                {
                                    await WriteErrorResponseLockedAsync(registration, message.RequestId,
                                        IpcErrorCodes.IpcHandshakeRequired,
                                        "first frame must be ipc.handshake.",
                                        closeConnection: false, serverSid, cancellationToken).ConfigureAwait(false);
                                    break;
                                }

                                var context = new IpcRequestContext { Message = message, Session = session };
                                ResponseEnvelope response;
                                if (RequestReceived is null)
                                {
                                    response = ResponseEnvelope.FromError(ErrorEnvelope.Create(
                                        IpcErrorCodes.NotImplemented, "no request handler registered."));
                                }
                                else
                                {
                                    try
                                    {
                                        response = await RequestReceived.Invoke(context, cancellationToken).ConfigureAwait(false);
                                    }
                                    catch (Exception ex)
                                    {
                                        _logger?.LogError(ex, "IPC request handler failed for request {RequestId}.", message.RequestId);
                                        response = ResponseEnvelope.FromError(ErrorEnvelope.Create(
                                            IpcErrorCodes.InternalError, "request handler failed."));
                                    }
                                }

                                await WriteResponseFrameLockedAsync(registration, message.RequestId, response, serverSid, cancellationToken)
                                    .ConfigureAwait(false);
                                break;
                            }

                            default:
                            {
                                // 心跳与旧帧类型：保持既有 MessageReceived + Ack 行为（SessionAgent 兼容）
                                if (MessageReceived is not null)
                                {
                                    await MessageReceived.Invoke(message, cancellationToken).ConfigureAwait(false);
                                }

                                var ack = IpcMessage.Create(
                                    requestId: message.RequestId,
                                    messageType: IpcConstants.MessageTypeAck,
                                    payload: Array.Empty<byte>(),
                                    senderSid: serverSid);
                                await WriteMessageLockedAsync(registration, ack, cancellationToken).ConfigureAwait(false);
                                break;
                            }
                        }
                    }
                }
                finally
                {
                    // 连接结束注销推送注册（仅当注册仍指向本连接时移除，防止误删同组件重连的新注册）
                    if (registered is not null
                        && _componentConnections.TryGetValue(registered.Session.Component, out var current)
                        && ReferenceEquals(current, registered))
                    {
                        _componentConnections.TryRemove(registered.Session.Component, out _);
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
            _logger?.LogError(ex, "IPC connection handler error.");
        }
    }

    private static async Task WriteMessageLockedAsync(
        IpcConnectionRegistration registration, IpcMessage message, CancellationToken cancellationToken)
    {
        await registration.WriteLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await WriteMessageAsync(registration.Stream, message, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            registration.WriteLock.Release();
        }
    }

    private static async Task WriteResponseFrameLockedAsync(
        IpcConnectionRegistration registration, uint requestId, ResponseEnvelope response,
        string serverSid, CancellationToken cancellationToken)
    {
        var frame = IpcMessage.Create(
            requestId: requestId,
            messageType: IpcConstants.MessageTypeResponse,
            payload: Encoding.UTF8.GetBytes(response.Serialize()),
            senderSid: serverSid);
        await WriteMessageLockedAsync(registration, frame, cancellationToken).ConfigureAwait(false);
    }

    private static async Task WriteErrorResponseLockedAsync(
        IpcConnectionRegistration registration, uint requestId, string code, string message,
        bool closeConnection, string serverSid, CancellationToken cancellationToken)
    {
        var response = ResponseEnvelope.FromError(ErrorEnvelope.Create(code, message, details: closeConnection
            ? new Dictionary<string, object?> { ["close"] = true }
            : null));
        await WriteResponseFrameLockedAsync(registration, requestId, response, serverSid, cancellationToken)
            .ConfigureAwait(false);
    }

    private static string? GetClientSid(NamedPipeServerStream pipeStream)
    {
        string? sid = null;
        try
        {
            pipeStream.RunAsClient(() =>
            {
                sid = WindowsIdentity.GetCurrent(TokenAccessLevels.Query).User?.Value;
            });
            return sid;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
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
            if (messageLength == 0 || messageLength > IpcConstants.MaxMessageLength)
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
        catch (Exception ex)
        {
            return Result<IpcMessage>.Failure(ErrorCode.IpcConnectionFailed, ex.Message);
        }
    }

    private static async Task WriteMessageAsync(Stream stream, IpcMessage message, CancellationToken cancellationToken)
    {
        var bytes = message.ToBytes();
        var lengthPrefix = new byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(lengthPrefix, (uint)bytes.Length);

        await stream.WriteAsync(lengthPrefix, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
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
