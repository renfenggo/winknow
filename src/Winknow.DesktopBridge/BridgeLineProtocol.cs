using System.Text.Json;
using System.Text.Json.Serialization;
using Winknow.Ipc.Protocol;

namespace Winknow.DesktopBridge;

/// <summary>
/// Flutter 侧行协议请求（每行一个 JSON 对象）：
/// {"id":&lt;任意 JSON 值&gt;,"method":"system.get_status","params":{...},"trace_id":"..."}。
/// </summary>
internal sealed class BridgeLineRequest
{
    /// <summary>调用方关联 ID（原样回显，不做解释）。</summary>
    [JsonPropertyName("id")]
    public JsonElement? Id { get; init; }

    /// <summary>目标方法名（须在 method_registry.md 白名单内）。</summary>
    [JsonPropertyName("method")]
    public string? Method { get; init; }

    /// <summary>方法参数（原样透传）。</summary>
    [JsonPropertyName("params")]
    public JsonElement? Params { get; init; }

    /// <summary>调用链追踪 ID（可选）。</summary>
    [JsonPropertyName("trace_id")]
    public string? TraceId { get; init; }
}

/// <summary>Flutter 侧行协议响应：{"id":...,"ok":true,"result":...} 或 {"id":...,"ok":false,"error":{...}}。</summary>
internal sealed class BridgeLineResponse
{
    /// <summary>回显请求 ID。</summary>
    [JsonPropertyName("id")]
    public JsonElement? Id { get; init; }

    /// <summary>是否成功。</summary>
    [JsonPropertyName("ok")]
    public bool Ok { get; init; }

    /// <summary>成功结果（ok=true 时有）。</summary>
    [JsonPropertyName("result")]
    public JsonElement? Result { get; init; }

    /// <summary>错误信封（ok=false 时有）。</summary>
    [JsonPropertyName("error")]
    public ErrorEnvelope? Error { get; init; }

    /// <summary>回显 trace_id。</summary>
    [JsonPropertyName("trace_id")]
    public string? TraceId { get; init; }

    /// <summary>序列化为行 JSON。</summary>
    public string Serialize() => JsonSerializer.Serialize(this, Json.Options);
}

/// <summary>
/// Bridge 行协议引擎（stdin/stdout，每行一个 JSON 对象）：
/// 逐行读取请求 → 组装 RequestEnvelope → 经注入的调用器发出 → 写响应行。
/// 纯 I/O 映射，不含连接管理；stdout 只输出协议行（日志走 stderr）。
/// </summary>
internal static class BridgeLineProtocol
{
    /// <summary>运行行协议直到输入 EOF 或取消。</summary>
    /// <param name="input">输入流（每行一个请求 JSON）。</param>
    /// <param name="output">输出流（每行一个响应 JSON）。</param>
    /// <param name="invoke">请求调用器（通常为 BridgeConnection.InvokeAsync）。</param>
    /// <param name="cancellationToken">取消令牌。</param>
    public static async Task RunAsync(
        TextReader input,
        TextWriter output,
        Func<RequestEnvelope, CancellationToken, Task<ResponseEnvelope>> invoke,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(invoke);

        while (!cancellationToken.IsCancellationRequested)
        {
            var line = await input.ReadLineAsync(cancellationToken).ConfigureAwait(false);
            if (line is null)
            {
                break;
            }

            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            await HandleLineAsync(line, output, invoke, cancellationToken).ConfigureAwait(false);
        }

        await output.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task HandleLineAsync(
        string line,
        TextWriter output,
        Func<RequestEnvelope, CancellationToken, Task<ResponseEnvelope>> invoke,
        CancellationToken cancellationToken)
    {
        BridgeLineRequest? request = null;
        try
        {
            request = JsonSerializer.Deserialize<BridgeLineRequest>(line, Json.Options);
        }
        catch (JsonException)
        {
            // 解析失败：请求本身非法
        }

        if (request is null || string.IsNullOrEmpty(request.Method) || !RequestEnvelope.IsValidMethodName(request.Method))
        {
            await WriteAsync(output, new BridgeLineResponse
            {
                Id = request?.Id,
                Ok = false,
                Error = ErrorEnvelope.Create(
                    IpcErrorCodes.InvalidArgument, "line must be JSON with a valid 'method' field."),
            }, cancellationToken).ConfigureAwait(false);
            return;
        }

        var envelope = new RequestEnvelope
        {
            Method = request.Method,
            Params = request.Params,
            TraceId = request.TraceId,
        };

        ResponseEnvelope response;
        try
        {
            response = await invoke(envelope, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            // 不外泄异常细节
            response = ResponseEnvelope.FromError(ErrorEnvelope.Create(
                IpcErrorCodes.InternalError, "bridge invoke failed.", envelope.TraceId));
        }

        await WriteAsync(output, new BridgeLineResponse
        {
            Id = request.Id,
            Ok = response.Ok,
            Result = response.Result,
            Error = response.Error,
            TraceId = envelope.TraceId,
        }, cancellationToken).ConfigureAwait(false);
    }

    private static async Task WriteAsync(TextWriter output, BridgeLineResponse response, CancellationToken cancellationToken)
    {
        await output.WriteLineAsync(response.Serialize().AsMemory(), cancellationToken).ConfigureAwait(false);
        await output.FlushAsync(cancellationToken).ConfigureAwait(false);
    }
}
