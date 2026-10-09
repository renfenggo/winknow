using System.Buffers.Binary;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Winknow.Ipc.Protocol;
using Winknow.Ipc.Session;

namespace Winknow.Ipc;

/// <summary>
/// Named Pipe 客户端（DesktopBridge / 测试客户端侧，镜像 IpcServer 帧格式）：
/// 4 字节小端长度前缀 + IpcMessage 二进制帧，payload 为契约 JSON。
///
/// 连接后首帧必须是 ipc.handshake（ADR-001）；业务请求经 InvokeAsync 收发
/// RequestEnvelope / ResponseEnvelope。单连接串行复用（SemaphoreSlim）；
/// RequestId 以当前毫秒时间戳为种子单调递增，避免客户端重启后与服务端
/// 按 SID 维度的 RequestId 单调性检查（防重放）冲突。
/// </summary>
public sealed class IpcClient : IAsyncDisposable
{
    private readonly string _pipeName;
    private readonly SemaphoreSlim _ioLock = new(1, 1);
    private NamedPipeClientStream? _stream;
    private uint _lastRequestId = (uint)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    /// <summary>创建管道客户端。</summary>
    /// <param name="pipeName">目标管道名（默认 Winknow_Control）。</param>
    public IpcClient(string pipeName = IpcConstants.ControlPipeName)
    {
        ArgumentException.ThrowIfNullOrEmpty(pipeName);
        _pipeName = pipeName;
    }

    /// <summary>是否处于已连接状态。</summary>
    public bool IsConnected => _stream is { IsConnected: true };

    /// <summary>连接服务端管道（本机）。</summary>
    /// <param name="timeoutMs">连接超时（毫秒）。</param>
    /// <param name="cancellationToken">取消令牌。</param>
    public async Task ConnectAsync(int timeoutMs = IpcConstants.ConnectionTimeoutMs, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        await _ioLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Impersonation 级别是服务端 GetClientSid(RunAsClient) 判定调用方 SID 的前提；
            // 仅本机模拟（非 Delegation），与 IpcServer 的 SID 绑定安全模型一致。
            var stream = new NamedPipeClientStream(
                serverName: ".",
                pipeName: _pipeName,
                direction: PipeDirection.InOut,
                options: PipeOptions.Asynchronous,
                impersonationLevel: TokenImpersonationLevel.Impersonation);
            await stream.ConnectAsync(timeoutMs, cancellationToken).ConfigureAwait(false);
            _stream?.Dispose();
            _stream = stream;
        }
        finally
        {
            _ioLock.Release();
        }
    }

    /// <summary>
    /// 发送连接期握手并返回响应信封（ok=false 表示被拒：
    /// 版本不兼容 / 设备不匹配 / 身份不一致等，见 IpcHandshakeValidator）。
    /// </summary>
    /// <param name="handshake">握手参数。</param>
    /// <param name="cancellationToken">取消令牌。</param>
    public async Task<ResponseEnvelope> HandshakeAsync(HandshakeParams handshake, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handshake);

        var request = new RequestEnvelope
        {
            Method = HandshakeParams.MethodName,
            Params = JsonSerializer.SerializeToElement(handshake, Protocol.Json.Options),
        };

        return await SendAndReceiveAsync(
            IpcConstants.MessageTypeHandshake, request.Serialize(), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// 发送业务请求并等待响应。请求级超时（IpcConstants.RequestTimeoutMs）返回
    /// TIMEOUT 错误信封；连接中断抛出 IOException，由调用方决定重连。
    /// </summary>
    /// <param name="request">请求信封。</param>
    /// <param name="cancellationToken">取消令牌。</param>
    public async Task<ResponseEnvelope> InvokeAsync(RequestEnvelope request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(IpcConstants.RequestTimeoutMs);
        try
        {
            return await SendAndReceiveAsync(
                IpcConstants.MessageTypeRequest, request.Serialize(), timeoutCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return ResponseEnvelope.FromError(ErrorEnvelope.Create(
                IpcErrorCodes.Timeout, "request timed out at client.", request.TraceId));
        }
    }

    /// <summary>
    /// 发送旧帧类型心跳并等待 Ack（ADR-001 兼容路径，SessionAgent 周期保活用；
    /// 服务端对旧帧类型保持 MessageReceived + Ack 行为）。
    /// </summary>
    /// <param name="cancellationToken">取消令牌。</param>
    public async Task SendHeartbeatAsync(CancellationToken cancellationToken = default)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(IpcConstants.RequestTimeoutMs);
        try
        {
            await SendAndReceiveFrameAsync(
                IpcConstants.MessageTypeHeartbeat,
                payloadJson: null,
                expectedFrameType: IpcConstants.MessageTypeAck,
                timeoutCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new IOException("heartbeat timed out at client.");
        }
    }

    /// <summary>
    /// 只写不发等待 Ack 的心跳帧（R06 双工接收模式）：配合 [ReadServerFrameAsync]
    /// 独占接收循环使用——服务端可主动推送帧（如 LockOverlay），Ack 与推送帧
    /// 统一由接收循环消费，此处不得读流。
    /// </summary>
    public async Task WriteHeartbeatAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        var stream = _stream;
        if (stream is not { IsConnected: true })
        {
            throw new IOException("IPC client is not connected.");
        }

        var requestId = Interlocked.Increment(ref _lastRequestId);
        var frame = IpcMessage.Create(
            requestId: requestId,
            messageType: IpcConstants.MessageTypeHeartbeat,
            payload: Array.Empty<byte>());

        await _ioLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await WriteFrameAsync(stream, frame, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ioLock.Release();
        }
    }

    /// <summary>
    /// 读取服务端发来的下一帧（R06 双工接收模式）：仅供独占接收线程调用
    /// （读侧唯一读者约定；推送帧 requestId 为 0，Ack/Response 由调用方按帧类型分发）。
    /// </summary>
    public async Task<IpcMessage> ReadServerFrameAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        var stream = _stream;
        if (stream is not { IsConnected: true })
        {
            throw new IOException("IPC client is not connected.");
        }

        return await ReadFrameAsync(stream, cancellationToken).ConfigureAwait(false);
    }

    private async Task<ResponseEnvelope> SendAndReceiveAsync(ushort messageType, string payloadJson, CancellationToken cancellationToken)
    {
        var responseFrame = await SendAndReceiveFrameAsync(
            messageType, payloadJson, IpcConstants.MessageTypeResponse, cancellationToken).ConfigureAwait(false);
        var response = ResponseEnvelope.Deserialize(Encoding.UTF8.GetString(responseFrame.Payload));
        return response ?? throw new IOException("server response payload is not a valid envelope.");
    }

    private async Task<IpcMessage> SendAndReceiveFrameAsync(ushort messageType, string? payloadJson,
        ushort expectedFrameType, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();

        var stream = _stream;
        if (stream is not { IsConnected: true })
        {
            throw new IOException("IPC client is not connected.");
        }

        var requestId = Interlocked.Increment(ref _lastRequestId);
        var frame = IpcMessage.Create(
            requestId: requestId,
            messageType: messageType,
            payload: payloadJson is null ? Array.Empty<byte>() : Encoding.UTF8.GetBytes(payloadJson));

        await _ioLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await WriteFrameAsync(stream, frame, cancellationToken).ConfigureAwait(false);

            var responseFrame = await ReadFrameAsync(stream, cancellationToken).ConfigureAwait(false);
            if (responseFrame.MessageType != expectedFrameType)
            {
                throw new IOException($"unexpected frame type 0x{responseFrame.MessageType:X4} from server.");
            }

            if (responseFrame.RequestId != requestId)
            {
                throw new IOException("response request id does not match the request.");
            }

            return responseFrame;
        }
        finally
        {
            _ioLock.Release();
        }
    }

    private static async Task WriteFrameAsync(NamedPipeClientStream stream, IpcMessage frame,
        CancellationToken cancellationToken)
    {
        var bytes = frame.ToBytes();
        var lengthPrefix = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(lengthPrefix, (uint)bytes.Length);
        await stream.WriteAsync(lengthPrefix, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<IpcMessage> ReadFrameAsync(NamedPipeClientStream stream, CancellationToken cancellationToken)
    {
        var lengthBuffer = new byte[4];
        await ReadExactAsync(stream, lengthBuffer, 4, cancellationToken).ConfigureAwait(false);

        var length = BinaryPrimitives.ReadUInt32LittleEndian(lengthBuffer);
        if (length == 0 || length > IpcConstants.MaxMessageLength)
        {
            throw new IOException("server frame length out of bounds.");
        }

        var body = new byte[length];
        await ReadExactAsync(stream, body, (int)length, cancellationToken).ConfigureAwait(false);
        return IpcMessage.FromBytes(body);
    }

    private static async Task ReadExactAsync(Stream stream, byte[] buffer, int count, CancellationToken cancellationToken)
    {
        var totalRead = 0;
        while (totalRead < count)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(totalRead, count - totalRead), cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                throw new IOException("connection closed by server.");
            }

            totalRead += read;
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    private bool _disposed;

    /// <summary>关闭连接并释放资源。</summary>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _stream?.Dispose();
        _stream = null;
        await Task.CompletedTask.ConfigureAwait(false);
    }
}
