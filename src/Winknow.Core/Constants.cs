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

    /// <summary>Defines guard daemon defaults (V7.0 week 10).</summary>
    public static class Guard
    {
        /// <summary>Gets the heartbeat write interval of the monitored service.</summary>
        public const int HeartbeatIntervalSeconds = 5;

        /// <summary>Gets the lease timeout: heartbeat older than this means the peer is dead or hung.</summary>
        public const int LeaseTimeoutSeconds = 15;

        /// <summary>Gets the sliding window for restart throttling.</summary>
        public const int ThrottleWindowMinutes = 10;

        /// <summary>Gets the maximum restarts allowed within the throttle window.</summary>
        public const int MaxRestartsPerWindow = 5;

        /// <summary>Gets the exponential backoff base delay in seconds.</summary>
        public const int BackoffBaseSeconds = 1;

        /// <summary>Gets the exponential backoff cap in seconds.</summary>
        public const int BackoffCapSeconds = 60;

        /// <summary>Gets the crash-loop test iteration count required by the plan.</summary>
        public const int CrashLoopTestIterations = 20;

        /// <summary>Gets the heartbeat lease file name (under ProgramData\Winknow).</summary>
        public const string HeartbeatFileName = "control_heartbeat.json";
    }

    /// <summary>Defines device security module defaults (V7.0 week 11).</summary>
    public static class DeviceSecurity
    {
        /// <summary>Gets the device security data directory name (under ProgramData\Winknow).</summary>
        public const string DataDirName = "device_security";

        /// <summary>Gets the verification record file name.</summary>
        public const string VerificationFileName = "verification.json";

        /// <summary>Gets the manual checklist file name.</summary>
        public const string ChecklistFileName = "checklist.json";
    }
}
