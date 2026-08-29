namespace Winknow.Core.Results;

/// <summary>
/// Represents the result of an operation that returns data.
/// </summary>
/// <typeparam name="T">The result data type.</typeparam>
public sealed class Result<T>
{
    private Result(T data)
    {
        IsSuccess = true;
        Data = data;
        ErrorCode = ErrorCode.Success;
    }

    private Result(ErrorCode errorCode, string? errorMessage)
    {
        IsSuccess = false;
        ErrorCode = errorCode;
        ErrorMessage = errorMessage;
    }

    /// <summary>Gets whether the operation succeeded.</summary>
    public bool IsSuccess { get; }

    /// <summary>Gets the returned data when the operation succeeded.</summary>
    public T? Data { get; }

    /// <summary>Gets the operation error code.</summary>
    public ErrorCode ErrorCode { get; }

    /// <summary>Gets the optional safe error message.</summary>
    public string? ErrorMessage { get; }

    /// <summary>Creates a successful result.</summary>
    /// <param name="data">The returned data.</param>
    /// <returns>A successful result.</returns>
    public static Result<T> Success(T data) => new(data);

    /// <summary>Creates a failed result.</summary>
    /// <param name="code">The failure code.</param>
    /// <param name="message">An optional safe failure message.</param>
    /// <returns>A failed result.</returns>
    public static Result<T> Failure(ErrorCode code, string? message = null)
    {
        if (code == ErrorCode.Success)
        {
            throw new ArgumentException("A failed result cannot use the success error code.", nameof(code));
        }

        return new Result<T>(code, message);
    }
}

/// <summary>
/// Represents the result of an operation that returns no data.
/// </summary>
public sealed class Result
{
    private Result()
    {
        IsSuccess = true;
        ErrorCode = ErrorCode.Success;
    }

    private Result(ErrorCode errorCode, string? errorMessage)
    {
        IsSuccess = false;
        ErrorCode = errorCode;
        ErrorMessage = errorMessage;
    }

    /// <summary>Gets whether the operation succeeded.</summary>
    public bool IsSuccess { get; }

    /// <summary>Gets the operation error code.</summary>
    public ErrorCode ErrorCode { get; }

    /// <summary>Gets the optional safe error message.</summary>
    public string? ErrorMessage { get; }

    /// <summary>Creates a successful result.</summary>
    /// <returns>A successful result.</returns>
    public static Result Success() => new();

    /// <summary>Creates a failed result.</summary>
    /// <param name="code">The failure code.</param>
    /// <param name="message">An optional safe failure message.</param>
    /// <returns>A failed result.</returns>
    public static Result Failure(ErrorCode code, string? message = null)
    {
        if (code == ErrorCode.Success)
        {
            throw new ArgumentException("A failed result cannot use the success error code.", nameof(code));
        }

        return new Result(code, message);
    }
}

/// <summary>
/// Defines stable error codes shared across Winknow components.
/// </summary>
public enum ErrorCode
{
    /// <summary>The operation succeeded.</summary>
    Success = 0,
    /// <summary>An unknown error occurred.</summary>
    Unknown = 1000,
    /// <summary>An input parameter is invalid.</summary>
    InvalidParameter = 1001,
    /// <summary>A requested path does not exist.</summary>
    PathNotFound = 1002,
    /// <summary>The caller is unauthorized.</summary>
    Unauthorized = 1003,
    /// <summary>An input argument is invalid (e.g. empty service name).</summary>
    InvalidArgument = 1004,
    /// <summary>The caller lacks the required privileges (e.g. not an administrator).</summary>
    AccessDenied = 1005,
    /// <summary>An external Win32 or system call failed.</summary>
    ExternalError = 9001,
    /// <summary>Encryption failed.</summary>
    EncryptionFailed = 2001,
    /// <summary>Decryption failed.</summary>
    DecryptionFailed = 2002,
    /// <summary>A digital signature is invalid.</summary>
    SignatureInvalid = 2003,
    /// <summary>A required key was not found.</summary>
    KeyNotFound = 2004,
    /// <summary>An IPC connection could not be established.</summary>
    IpcConnectionFailed = 3001,
    /// <summary>An IPC request timed out.</summary>
    IpcTimeout = 3002,
    /// <summary>An IPC replay was detected.</summary>
    IpcReplayDetected = 3003,
    /// <summary>The database could not be opened.</summary>
    DatabaseOpenFailed = 4001,
    /// <summary>A database write failed.</summary>
    DatabaseWriteFailed = 4002,
    /// <summary>A database read failed.</summary>
    DatabaseReadFailed = 4003,
    /// <summary>The database is corrupted.</summary>
    DatabaseCorrupted = 4004,
    /// <summary>A policy is invalid.</summary>
    PolicyInvalid = 5001,
    /// <summary>A policy version is incompatible.</summary>
    PolicyVersionMismatch = 5002,
    /// <summary>A policy signature is invalid.</summary>
    PolicySignatureInvalid = 5003,
    /// <summary>Secure Boot is disabled.</summary>
    SecureBootDisabled = 6001,
    /// <summary>A BIOS password is not configured.</summary>
    BiosPasswordNotSet = 6002,
    /// <summary>Booting from USB is enabled.</summary>
    UsbBootEnabled = 6003,
    /// <summary>A process was blocked by the software control engine.</summary>
    ProcessBlocked = 7001,
    /// <summary>A process could not be terminated.</summary>
    ProcessTerminationFailed = 7002,
}

