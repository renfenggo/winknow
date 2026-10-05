namespace Winknow.Core;

/// <summary>
/// Owns the product filesystem layout. Tests can supply an isolated root instead of ProgramData.
/// </summary>
public sealed class ProductPaths
{
    /// <summary>Creates the layout using ProgramData or an isolated test root.</summary>
    public ProductPaths(string? root = null)
    {
        Root = root ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Constants.ProductName);
    }

    /// <summary>Product data root.</summary>
    public string Root { get; }
    /// <summary>A/B deployment slot root.</summary>
    public string DeployRoot => Path.Combine(Root, "deploy");
    /// <summary>Active deployment slot.</summary>
    public string CurrentDeployment => Path.Combine(DeployRoot, "Current");
    /// <summary>Rollback deployment slot.</summary>
    public string PreviousDeployment => Path.Combine(DeployRoot, "Previous");
    /// <summary>Staged update slot.</summary>
    public string StagingDeployment => Path.Combine(DeployRoot, "Staging");
    /// <summary>Policy directory.</summary>
    public string Policies => Path.Combine(Root, "policies");
    /// <summary>Single active policy file.</summary>
    public string ActivePolicy => Path.Combine(Policies, "active_policy.json");
    /// <summary>Detached active-policy signature.</summary>
    public string ActivePolicySignature => Path.Combine(Policies, "active_policy.sig");
    /// <summary>Maintenance credential and ticket directory.</summary>
    public string Maintenance => Path.Combine(Root, "maintain");
    /// <summary>Audit-log directory.</summary>
    public string Logs => Path.Combine(Root, "logs");
    /// <summary>Device-secret directory.</summary>
    public string Keys => Path.Combine(Root, "keys");
    /// <summary>Update-signature verification public key.</summary>
    public string PublicKey => Path.Combine(DeployRoot, "publickey.pem");

    /// <summary>Creates the directories required before product services start.</summary>
    public void EnsureDirectories()
    {
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(DeployRoot);
        Directory.CreateDirectory(Policies);
        Directory.CreateDirectory(Maintenance);
        Directory.CreateDirectory(Logs);
        Directory.CreateDirectory(Keys);
    }
}
