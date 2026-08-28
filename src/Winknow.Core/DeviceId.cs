using System.Security.Cryptography;
using System.Security;
using System.Text;
using Microsoft.Win32;

namespace Winknow.Core;

/// <summary>
/// Generates a stable, non-reversible identifier from local machine attributes.
/// </summary>
public static class DeviceId
{
    /// <summary>
    /// Generates a 16-character hexadecimal device identifier.
    /// </summary>
    /// <returns>The generated device identifier.</returns>
    public static string Generate()
    {
        var parts = new List<string>();

        AddRegistryValue(parts, Registry.LocalMachine, @"SOFTWARE\Microsoft\Cryptography", "MachineGuid");
        AddRegistryValue(
            parts,
            Registry.LocalMachine,
            @"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            "ProcessorNameString");

        if (parts.Count == 0)
        {
            parts.Add(Environment.MachineName);
            parts.Add(Environment.OSVersion.VersionString);
        }

        var combined = string.Join('|', parts);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(combined));
        return Convert.ToHexString(hash)[..16];
    }

    private static void AddRegistryValue(
        ICollection<string> parts,
        RegistryKey root,
        string keyPath,
        string valueName)
    {
        try
        {
            using var key = root.OpenSubKey(keyPath);
            if (key?.GetValue(valueName) is string value && !string.IsNullOrWhiteSpace(value))
            {
                parts.Add(value.Trim());
            }
        }
        catch (Exception exception) when (exception is SecurityException or UnauthorizedAccessException or IOException)
        {
            // A missing or inaccessible hardware attribute is expected on restricted systems.
        }
    }
}
