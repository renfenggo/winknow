using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text;
using Microsoft.Extensions.Logging;
using Winknow.Core;
using Winknow.Core.Results;

namespace Winknow.Ipc;

/// <summary>
/// Named Pipe 客户端。
/// 用于 SessionAgent / AdminUI 连接 ControlService。
/// </summary>
public sealed class IpcClient : IAsyncDisposable
{
    private readonly string _pipeName;
    private readonly string _serverName;
    private readonly string _senderSid;
    private readonly ILogger<IpcClient>? _logger;
    private NamedPipeClientStream? _stream;
    private uint _nextRequestId = 1;
    private readonly SemaphoreSlim _sendLock = new(1, 1);

    /// <summary>接收到服务端消息时触发。</summary>
    public event Func<IpcMessage, CancellationToken, Task>? MessageReceived;

    /// <summary>
    /// 创建 IPC 客户端。
    /// </summary>
    /// <param name="pipeName">Pipe 名称。</param>
    /// <param name="senderSid">发送方 SID（用于消息身份）。</param>
    /// <param name="serverName">服务器名（默认本机）。</param>
    /// <param name="logger">可选的日志记录器。</param>
    public IpcClient(string pipeName, string senderSid, string? serverName = null, ILogger<IpcClient>? logger = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(pipeName);
        ArgumentException.ThrowIfNullOrEmpty(senderSid);

        _pipeName = pipeName;
        _senderSid = senderSid;
        _serverName = serverName ?? ".";
        _logger = logger;
    }

    /// <summary>
    /// 连接到服务端。
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

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(IpcConstants.ConnectionTimeoutMs);

            await _stream.ConnectAsync(cts.Token).ConfigureAwait(false);
            _logger?.LogInformation("Connected to IPC server {Server}/{Pipe}", _serverName, _pipeName);

            // 启动接收循环
            _ = ReceiveLoopAsync(cancellationToken);
            return Result<object>.Success(new object());
        }
        catch (OperationCanceledException)
        {
            return Result<object>.Failure(ErrorCode.IpcTimeout, "IPC connection timed out.");
        }
        catch (Exception ex)
        {
            return Result<object>.Failure(ErrorCode.IpcConnectionFailed, ex.Message);
        }
    }

    /// <summary>
    /// 发送消息。
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

            var bytes = message.ToBytes();
            var lengthPrefix = new byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(lengthPrefix, (uint)bytes.Length);

            await _stream.WriteAsync(lengthPrefix, cancellationToken).ConfigureAwait(false);
            await _stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
            await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);

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

    private async Task ReceiveLoopAsync(CancellationToken cancellationToken)
    {
        if (_stream is null)
        {
            return;
        }

        try
        {
            while (_stream.IsConnected && !cancellationToken.IsCancellationRequested)
            {
                var lengthBuffer = new byte[4];
                var bytesRead = await ReadExactAsync(_stream, lengthBuffer, 4, cancellationToken).ConfigureAwait(false);
                if (bytesRead < 4)
                {
                    break;
                }

                var messageLength = BinaryPrimitives.ReadUInt32LittleEndian(lengthBuffer);
                if (messageLength == 0 || messageLength > IpcConstants.MaxMessageLength)
                {
                    _logger?.LogWarning("Invalid message length: {Length}", messageLength);
                    break;
                }

                var messageBuffer = new byte[messageLength];
                bytesRead = await ReadExactAsync(_stream, messageBuffer, (int)messageLength, cancellationToken).ConfigureAwait(false);
                if (bytesRead < messageLength)
                {
                    break;
                }

                var message = IpcMessage.FromBytes(messageBuffer);
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
        _sendLock.Dispose();
        if (_stream is not null)
        {
            await _stream.DisposeAsync().ConfigureAwait(false);
        }
    }
}
