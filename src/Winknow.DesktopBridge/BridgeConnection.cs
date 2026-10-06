using System.IO.Pipes;
using Winknow.Ipc;
using Winknow.Ipc.Protocol;
using Winknow.Ipc.Session;

namespace Winknow.DesktopBridge;

/// <summary>
/// Bridge 到 ControlService 的 IPC 连接管理：懒连接 + 断线后下次调用重建
/// （连接 + 握手一次完成）。连接/握手失败映射为 UNAVAILABLE 错误信封，
/// 不抛出到行协议层。
/// </summary>
internal sealed class BridgeConnection : IAsyncDisposable
{
    private readonly string _pipeName;
    private readonly HandshakeParams _handshake;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private IpcClient? _client;
    private bool _handshakeCompleted;

    /// <summary>创建连接管理器。</summary>
    /// <param name="pipeName">目标管道名。</param>
    /// <param name="handshake">握手参数（连接时使用）。</param>
    public BridgeConnection(string pipeName, HandshakeParams handshake)
    {
        ArgumentException.ThrowIfNullOrEmpty(pipeName);
        ArgumentNullException.ThrowIfNull(handshake);
        _pipeName = pipeName;
        _handshake = handshake;
    }

    /// <summary>
    /// 调用远端方法：无可用连接时先建立连接并完成握手；
    /// 连接级失败返回 UNAVAILABLE（retryable）错误信封。
    /// </summary>
    /// <param name="request">请求信封。</param>
    /// <param name="cancellationToken">取消令牌。</param>
    public async Task<ResponseEnvelope> InvokeAsync(RequestEnvelope request, CancellationToken cancellationToken)
    {
        await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_client is not { IsConnected: true } || !_handshakeCompleted)
            {
                var connected = await TryConnectAsync(cancellationToken).ConfigureAwait(false);
                if (!connected)
                {
                    return ResponseEnvelope.FromError(ErrorEnvelope.Create(
                        IpcErrorCodes.Unavailable, "ControlService pipe is not reachable.", request.TraceId));
                }
            }

            try
            {
                return await _client!.InvokeAsync(request, cancellationToken).ConfigureAwait(false);
            }
            catch (IOException)
            {
                // 管道中断：丢弃连接，本次调用返回 UNAVAILABLE，下次调用重建
                await DisposeClientAsync().ConfigureAwait(false);
                return ResponseEnvelope.FromError(ErrorEnvelope.Create(
                    IpcErrorCodes.Unavailable, "IPC connection was lost; will reconnect on next call.",
                    request.TraceId));
            }
            catch (ObjectDisposedException)
            {
                await DisposeClientAsync().ConfigureAwait(false);
                return ResponseEnvelope.FromError(ErrorEnvelope.Create(
                    IpcErrorCodes.Unavailable, "IPC connection was closed.", request.TraceId));
            }
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task<bool> TryConnectAsync(CancellationToken cancellationToken)
    {
        await DisposeClientAsync().ConfigureAwait(false);
        var client = new IpcClient(_pipeName);
        try
        {
            await client.ConnectAsync(cancellationToken: cancellationToken).ConfigureAwait(false);
            var handshakeResponse = await client.HandshakeAsync(_handshake, cancellationToken).ConfigureAwait(false);
            if (!handshakeResponse.Ok)
            {
                // 版本不兼容/设备不匹配/身份不一致：显式拒绝，不得静默重试
                await client.DisposeAsync().ConfigureAwait(false);
                return false;
            }

            _client = client;
            _handshakeCompleted = true;
            return true;
        }
        catch (Exception ex) when (ex is IOException or TimeoutException or OperationCanceledException)
        {
            await client.DisposeAsync().ConfigureAwait(false);
            return false;
        }
    }

    private async Task DisposeClientAsync()
    {
        _handshakeCompleted = false;
        if (_client is not null)
        {
            await _client.DisposeAsync().ConfigureAwait(false);
            _client = null;
        }
    }

    /// <summary>释放连接资源。</summary>
    public async ValueTask DisposeAsync()
    {
        await DisposeClientAsync().ConfigureAwait(false);
        _lock.Dispose();
    }
}
