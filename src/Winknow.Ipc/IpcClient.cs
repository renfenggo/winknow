using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO.Pipes;
using Microsoft.Extensions.Logging;
using Winknow.Core;
using Winknow.Core.Results;

namespace Winknow.Ipc;

/// <summary>
/// Named Pipe 客户端（P2-01/P2-04 重构）。
///
/// - 连接后自动完成 Hello/HelloAck 握手（版本、PID、SessionId、DeviceId、ClientNonce）；
/// - 支持"请求-响应"语义（响应沿用请求 RequestId，超时可控、幂等可重试）；
/// - SenderSid 仅作审计字段，服务端以 Impersonation 真实 SID 为准。
/// </summary>
public sealed class IpcClient : IAsyncDisposable
{
    private readonly string _pipeName;
    private readonly string _serverName;
    private readonly string _senderSid;
    private readonly string _deviceId;
    private readonly string _clientVersion;
    private readonly ILogger<IpcClient>? _logger;
    private readonly ConcurrentDictionary<uint, TaskCompletionSource<IpcMessage>> _pendingResponses = new();
    private NamedPipeClientStream? _stream;
    private uint _nextRequestId = 1;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private CancellationTokenSource? _receiveCts;

    /// <summary>接收到服务端消息时触发（非响应类消息）。</summary>
    public event Func<IpcMessage, CancellationToken, Task>? MessageReceived;

    /// <summary>接收循环终止（连接断开或读取错误）时触发；重连方据此进入退避重连。</summary>
    public event Action? Disconnected;

    /// <summary>最近一次握手结果（Granted 时含 ServerNonce）。</summary>
    public HelloAckPayload? Handshake { get; private set; }

    /// <summary>底层管道是否连通。</summary>
    public bool IsConnected => _stream?.IsConnected ?? false;

    /// <summary>
    /// 创建 IPC 客户端。
    /// </summary>
    /// <param name="pipeName">Pipe 名称。</param>
    /// <param name="senderSid">发送方 SID（仅审计字段；服务端按 Impersonation 真实 SID 校验）。</param>
    /// <param name="deviceId">本机设备 ID（握手用）。</param>
    /// <param name="clientVersion">客户端组件版本（握手用）。</param>
    /// <param name="serverName">服务器名（默认本机）。</param>
    /// <param name="logger">可选日志。</param>
    public IpcClient(
        string pipeName,
        string senderSid,
        string deviceId = "",
        string clientVersion = "",
        string? serverName = null,
        ILogger<IpcClient>? logger = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(pipeName);
        ArgumentException.ThrowIfNullOrEmpty(senderSid);

        _pipeName = pipeName;
        _senderSid = senderSid;
        _deviceId = deviceId;
        _clientVersion = clientVersion;
        _serverName = serverName ?? ".";
        _logger = logger;
    }

    /// <summary>
    /// 连接到服务端并完成握手（Hello → HelloAck）。
    /// </summary>
    public async Task<Result<object>> ConnectAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            _stream = new NamedPipeClientStream(
                _serverName,
                _pipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous);

            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            connectCts.CancelAfter(IpcConstants.ConnectionTimeoutMs);
            await _stream.ConnectAsync(connectCts.Token).ConfigureAwait(false);

            // 握手（Hello → 等待 HelloAck，超时按连接超时计）
            var hello = new HelloPayload
            {
                ProtocolVersion = IpcMessage.CurrentVersion,
                Pid = Environment.ProcessId,
                SessionId = CurrentSessionId,
                DeviceId = _deviceId,
                ClientNonce = Convert.ToBase64String(SecurityUtils.GenerateNonce()),
                ClientVersion = _clientVersion
            };

            using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            handshakeCts.CancelAfter(IpcConstants.ConnectionTimeoutMs);
            var ackMessage = await RoundTripAsync(
                IpcConstants.MessageTypeHello,
                IpcProtocol.Encode(hello),
                IpcConstants.MessageTypeHelloAck,
                handshakeCts.Token).ConfigureAwait(false);

            var ack = IpcProtocol.Decode<HelloAckPayload>(ackMessage.Payload);
            if (ack is null || !ack.Granted)
            {
                await DisconnectAsync().ConfigureAwait(false);
                return Result<object>.Failure(ErrorCode.Unauthorized, ack?.Reason ?? "Handshake denied.");
            }

            Handshake = ack;

            // 启动接收循环（处理服务端推送与响应）
            _receiveCts = new CancellationTokenSource();
            _ = ReceiveLoopAsync(_receiveCts.Token);
            _logger?.LogInformation("Connected and handshake granted (server nonce: {Nonce})", ack.ServerNonce);
            return Result<object>.Success(new object());
        }
        catch (OperationCanceledException)
        {
            return Result<object>.Failure(ErrorCode.IpcTimeout, "IPC connection/handshake timed out.");
        }
        catch (Exception ex)
        {
            return Result<object>.Failure(ErrorCode.IpcConnectionFailed, ex.Message);
        }
    }

    /// <summary>
    /// 主动断开连接（断线重连前调用；幂等）。
    /// </summary>
    public async Task DisconnectAsync()
    {
        _receiveCts?.Cancel();
        if (_stream is not null)
        {
            await _stream.DisposeAsync().ConfigureAwait(false);
            _stream = null;
        }
        FailPending(new IOException("Client disconnected."));
    }

    /// <summary>
    /// 发送单向消息。
    /// </summary>
    public async Task<Result<object>> SendAsync(ushort messageType, byte[] payload, CancellationToken cancellationToken = default)
    {
        if (_stream is null || !_stream.IsConnected)
        {
            return Result<object>.Failure(ErrorCode.IpcConnectionFailed, "Not connected to IPC server.");
        }

        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var message = IpcMessage.Create(
                requestId: _nextRequestId++,
                messageType: messageType,
                payload: payload,
                senderSid: _senderSid);

            await WriteFramedAsync(_stream, message, cancellationToken).ConfigureAwait(false);
            return Result<object>.Success(new object());
        }
        catch (Exception ex)
        {
            return Result<object>.Failure(ErrorCode.IpcConnectionFailed, ex.Message);
        }
        finally
        {
            _sendLock.Release();
        }
    }

    /// <summary>
    /// 发送请求并等待匹配响应（响应 RequestId 与请求一致）。
    /// 每次调用生成新 RequestId，天然幂等可重试。
    /// </summary>
    public async Task<Result<IpcMessage>> SendRequestAsync(
        ushort messageType,
        byte[] payload,
        ushort expectedResponseType,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        if (_stream is null || !_stream.IsConnected)
        {
            return Result<IpcMessage>.Failure(ErrorCode.IpcConnectionFailed, "Not connected to IPC server.");
        }

        var requestId = _nextRequestId++;
        var tcs = new TaskCompletionSource<IpcMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pendingResponses[requestId] = tcs;

        try
        {
            await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var message = IpcMessage.Create(requestId, messageType, payload, _senderSid);
                await WriteFramedAsync(_stream, message, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _sendLock.Release();
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

    /// <summary>
    /// 应答服务端请求（响应沿用请求的 RequestId，请求方据此匹配）。
    /// </summary>
    public async Task<Result<object>> SendResponseAsync(
        IpcMessage request,
        ushort responseType,
        byte[] payload,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (_stream is null || !_stream.IsConnected)
        {
            return Result<object>.Failure(ErrorCode.IpcConnectionFailed, "Not connected to IPC server.");
        }

        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var message = IpcMessage.CreateResponse(request, responseType, payload, _senderSid);
            await WriteFramedAsync(_stream, message, cancellationToken).ConfigureAwait(false);
            return Result<object>.Success(new object());
        }
        catch (Exception ex)
        {
            return Result<object>.Failure(ErrorCode.IpcConnectionFailed, ex.Message);
        }
        finally
        {
            _sendLock.Release();
        }
    }

    /// <summary>
    /// 发送心跳消息。
    /// </summary>
    public Task<Result<object>> SendHeartbeatAsync(CancellationToken cancellationToken = default)
    {
        return SendAsync(IpcConstants.MessageTypeHeartbeat, Array.Empty<byte>(), cancellationToken);
    }

    private async Task<IpcMessage> RoundTripAsync(
        ushort messageType,
        byte[] payload,
        ushort expectedResponseType,
        CancellationToken cancellationToken)
    {
        if (_stream is null)
        {
            throw new IOException("Stream closed.");
        }

        var requestId = _nextRequestId++;
        var tcs = new TaskCompletionSource<IpcMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pendingResponses[requestId] = tcs;

        // 握手期间接收循环尚未启动：先写请求，再同步读响应
        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var message = IpcMessage.Create(requestId, messageType, payload, _senderSid);
            await WriteFramedAsync(_stream, message, cancellationToken).ConfigureAwait(false);

            while (!cancellationToken.IsCancellationRequested)
            {
                var received = await ReadMessageAsync(_stream, cancellationToken).ConfigureAwait(false);
                if (received.RequestId == requestId && received.MessageType == expectedResponseType)
                {
                    return received;
                }

                // 非握手应答的提前消息：留给上层处理（握手阶段理论上不会有）
                _logger?.LogDebug("Unexpected message during handshake: type=0x{Type:X4}", received.MessageType);
            }

            throw new OperationCanceledException(cancellationToken);
        }
        finally
        {
            _pendingResponses.TryRemove(requestId, out _);
            _sendLock.Release();
        }
    }

    private async Task ReceiveLoopAsync(CancellationToken cancellationToken)
    {
        var stream = _stream;
        if (stream is null)
        {
            return;
        }

        try
        {
            while (stream.IsConnected && !cancellationToken.IsCancellationRequested)
            {
                var message = await ReadMessageAsync(stream, cancellationToken).ConfigureAwait(false);

                // 响应消息优先派发给等待中的请求
                if (_pendingResponses.TryGetValue(message.RequestId, out var tcs))
                {
                    tcs.TrySetResult(message);
                    continue;
                }

                if (MessageReceived is not null)
                {
                    await MessageReceived.Invoke(message, cancellationToken).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // 正常关闭
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "IPC client receive loop error.");
        }
        finally
        {
            FailPending(new IOException("Receive loop terminated."));
            try
            {
                Disconnected?.Invoke();
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Disconnected event handler threw.");
            }
        }
    }

    private void FailPending(Exception reason)
    {
        foreach (var kvp in _pendingResponses)
        {
            kvp.Value.TrySetException(reason);
            _pendingResponses.TryRemove(kvp.Key, out _);
        }
    }

    private static async Task WriteFramedAsync(Stream stream, IpcMessage message, CancellationToken cancellationToken)
    {
        var bytes = message.ToBytes();
        var lengthPrefix = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(lengthPrefix, (uint)bytes.Length);

        await stream.WriteAsync(lengthPrefix, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<IpcMessage> ReadMessageAsync(Stream stream, CancellationToken cancellationToken)
    {
        var lengthBuffer = new byte[4];
        var bytesRead = await ReadExactAsync(stream, lengthBuffer, 4, cancellationToken).ConfigureAwait(false);
        if (bytesRead < 4)
        {
            throw new IOException("Connection closed before length prefix.");
        }

        var messageLength = BinaryPrimitives.ReadUInt32LittleEndian(lengthBuffer);
        if (messageLength == 0 || messageLength > (uint)IpcConstants.MaxMessageLength)
        {
            throw new IOException($"Invalid message length: {messageLength}");
        }

        var messageBuffer = new byte[messageLength];
        bytesRead = await ReadExactAsync(stream, messageBuffer, (int)messageLength, cancellationToken).ConfigureAwait(false);
        if (bytesRead < messageLength)
        {
            throw new IOException("Connection closed before full message.");
        }

        return IpcMessage.FromBytes(messageBuffer);
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

    private static int CurrentSessionId => System.Diagnostics.Process.GetCurrentProcess().SessionId;

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        await DisconnectAsync().ConfigureAwait(false);
        _sendLock.Dispose();
    }
}
