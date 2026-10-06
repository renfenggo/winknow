namespace Winknow.Ipc.Protocol;

/// <summary>
/// IPC payload 协议版本（contracts/ipc，独立于二进制帧 Version 与组件版本）。
/// 兼容规则（ADR-001）：主版本必须一致，且客户端次版本不得高于服务端。
/// </summary>
public readonly record struct ProtocolVersion(int Major, int Minor) : IComparable<ProtocolVersion>
{
    /// <summary>当前协议版本。</summary>
    public static ProtocolVersion Current => new(1, 0);

    /// <summary>解析 "Major.Minor" 形式版本串。</summary>
    public static bool TryParse(string? text, out ProtocolVersion version)
    {
        version = default;
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        var parts = text.Split('.');
        if (parts.Length != 2 ||
            !int.TryParse(parts[0], out var major) || major < 0 ||
            !int.TryParse(parts[1], out var minor) || minor < 0)
        {
            return false;
        }

        version = new ProtocolVersion(major, minor);
        return true;
    }

    /// <summary>服务端视角判断本客户端版本是否兼容（主版本一致且客户端次版本不更高）。</summary>
    public bool Accepts(ProtocolVersion client) => Major == client.Major && client.Minor <= Minor;

    /// <inheritdoc/>
    public int CompareTo(ProtocolVersion other) => Major != other.Major
        ? Major.CompareTo(other.Major)
        : Minor.CompareTo(other.Minor);

    /// <inheritdoc/>
    public override string ToString() => $"{Major}.{Minor}";
}
