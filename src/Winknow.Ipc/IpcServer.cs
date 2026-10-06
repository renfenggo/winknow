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
    private Task? _listenTask;

    /// <summary>接收到有效消息（心跳与旧帧类型）时触发，服务端自动回 Ack。</summary>
    public event Func<IpcMessage, CancellationToken, Task>? MessageReceived;

    /// <summary>接收到业务请求帧（握手完成后）时触发；返回值作为 Response 帧回写。</summary>
    public event Func<IpcRequestContext, CancellationToken, Task<ResponseEnvelope>>? RequestReceived;

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
            var pipeStream = CreateSecurePipeStream();

            try
            {
                await pipeStream.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);

                // 处理连接（不阻塞监听循环）
                _ = HandleConnectionAsync(pipeStream, cancellationToken);
            }
            catch (OperationCanceledException)
            {
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

                        // 帧级校验失败：JSON 错误信封（契约化 payload），连接保留供诊断与重试
                        await WriteErrorResponseAsync(pipeStream, message.RequestId,
                            IpcErrorCodes.IpcSidNotAuthorized,
                            $"frame rejected: {validation.ErrorMessage}",
                            closeConnection: false, serverSid, cancellationToken).ConfigureAwait(false);
                        continue;
                    }

                    switch (message.MessageType)
                    {
                        case IpcConstants.MessageTypeHandshake:
                        {
                            if (session.HandshakeCompleted)
                            {
                                await WriteErrorResponseAsync(pipeStream, message.RequestId,
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

                            await WriteResponseFrameAsync(pipeStream, message.RequestId, outcome.Response, serverSid, cancellationToken)
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
                            }

                            break;
                        }

                        case IpcConstants.MessageTypeRequest:
                        {
                            if (!session.HandshakeCompleted)
                            {
                                await WriteErrorResponseAsync(pipeStream, message.RequestId,
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

                            await WriteResponseFrameAsync(pipeStream, message.RequestId, response, serverSid, cancellationToken)
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
                            await WriteMessageAsync(pipeStream, ack, cancellationToken).ConfigureAwait(false);
                            break;
                        }
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

    private static async Task WriteResponseFrameAsync(Stream stream, uint requestId, ResponseEnvelope response,
        string serverSid, CancellationToken cancellationToken)
    {
        var frame = IpcMessage.Create(
            requestId: requestId,
            messageType: IpcConstants.MessageTypeResponse,
            payload: Encoding.UTF8.GetBytes(response.Serialize()),
            senderSid: serverSid);
        await WriteMessageAsync(stream, frame, cancellationToken).ConfigureAwait(false);
    }

    private static async Task WriteErrorResponseAsync(Stream stream, uint requestId, string code, string message,
        bool closeConnection, string serverSid, CancellationToken cancellationToken)
    {
        var response = ResponseEnvelope.FromError(ErrorEnvelope.Create(code, message, details: closeConnection
            ? new Dictionary<string, object?> { ["close"] = true }
            : null));
        await WriteResponseFrameAsync(stream, requestId, response, serverSid, cancellationToken).ConfigureAwait(false);
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
