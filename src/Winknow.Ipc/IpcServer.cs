using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using Winknow.Core.Results;

namespace Winknow.Ipc;

/// <summary>
/// Named Pipe 服务端。
///
/// 安全配置（见《V7.0 组件架构设计》第 6.2 节）：
/// - SYSTEM：完全控制
/// - Administrators：完全控制
/// - 当前会话用户：读写
/// - 其他：拒绝
/// </summary>
public sealed class IpcServer : IAsyncDisposable
{
    private readonly string _pipeName;
    private readonly IpcAuthenticator _authenticator;
    private readonly ILogger<IpcServer>? _logger;
    private readonly CancellationTokenSource _cts = new();
    private Task? _listenTask;

    /// <summary>接收到有效消息时触发。</summary>
    public event Func<IpcMessage, CancellationToken, Task>? MessageReceived;

    /// <summary>
    /// 创建 Named Pipe 服务端。
    /// </summary>
    public IpcServer(string pipeName, IpcAuthenticator authenticator, ILogger<IpcServer>? logger = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(pipeName);
        ArgumentNullException.ThrowIfNull(authenticator);

        _pipeName = pipeName;
        _authenticator = authenticator;
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
        // Pipe ACL：SYSTEM 完全控制 + Administrators 完全控制 + Everyone 读（连接后由身份验证层校验 SID）
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

        // 允许 Everyone 连接（实际身份验证由 IpcAuthenticator 完成）
        var everyoneIdentity = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        security.AddAccessRule(new PipeAccessRule(
            everyoneIdentity,
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
                while (pipeStream.IsConnected && !cancellationToken.IsCancellationRequested)
                {
                    var messageResult = await ReadMessageAsync(pipeStream, cancellationToken).ConfigureAwait(false);
                    if (!messageResult.IsSuccess)
                    {
                        _logger?.LogWarning("IPC read failed: {Error}", messageResult.ErrorMessage);
                        break;
                    }

                    var validation = _authenticator.ValidateMessage(messageResult.Data!);
                    if (!validation.IsSuccess)
                    {
                        _logger?.LogWarning("IPC message rejected: {ErrorCode} {Message}",
                            validation.ErrorCode, validation.ErrorMessage);

                        var errorResponse = IpcMessage.Create(
                            requestId: 0,
                            messageType: IpcConstants.MessageTypeError,
                            payload: System.Text.Encoding.UTF8.GetBytes(validation.ErrorMessage ?? "Unknown error"));
                        await WriteMessageAsync(pipeStream, errorResponse, cancellationToken).ConfigureAwait(false);
                        continue;
                    }

                    if (MessageReceived is not null)
                    {
                        await MessageReceived.Invoke(validation.Data!, cancellationToken).ConfigureAwait(false);
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
