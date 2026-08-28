namespace Winknow.Core;

/// <summary>
/// Defines product-wide constants and default values.
/// </summary>
public static class Constants
{
    /// <summary>Gets the product name.</summary>
    public const string ProductName = "Winknow";

    /// <summary>Gets the current product version.</summary>
    public const string Version = "7.0.0";

    /// <summary>Defines registry locations owned by Winknow.</summary>
    public static class Registry
    {
        /// <summary>Gets the root registry key.</summary>
        public const string BaseKey = @"HKEY_LOCAL_MACHINE\SOFTWARE\Winknow";

        /// <summary>Gets the policy registry key.</summary>
        public const string PolicyKey = BaseKey + @"\Policy";

        /// <summary>Gets the security registry key.</summary>
        public const string SecurityKey = BaseKey + @"\Security";

        /// <summary>Gets the logging registry key.</summary>
        public const string LoggingKey = BaseKey + @"\Logging";
    }

    /// <summary>Defines IPC defaults.</summary>
    public static class Ipc
    {
        /// <summary>Gets the named pipe prefix.</summary>
        public const string PipePrefix = @"\\.\pipe\Winknow_";

        /// <summary>Gets the connection timeout in milliseconds.</summary>
        public const int ConnectionTimeoutMs = 5000;

        /// <summary>Gets the request timeout in milliseconds.</summary>
        public const int RequestTimeoutMs = 30000;

        /// <summary>Gets the maximum retry count.</summary>
        public const int MaxRetryCount = 3;
    }

    /// <summary>Defines audit logging defaults.</summary>
    public static class Logging
    {
        /// <summary>Gets the default retention period in days.</summary>
        public const int DefaultRetentionDays = 30;

        /// <summary>Gets the default maximum database size.</summary>
        public const long MaxDatabaseSizeBytes = 500L * 1024 * 1024;

        /// <summary>Gets the number of records between integrity checkpoints.</summary>
        public const int CheckpointFrequency = 100;

        /// <summary>Gets the audit database file name.</summary>
        public const string DatabaseFileName = "audit.db";
    }
}
