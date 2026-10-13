namespace UserRights.Application;

/// <summary>
/// Represents the interface to the local security authority.
/// </summary>
public interface ILsaUserRights : IUserRights
{
    /// <summary>
    /// Connects to the local security authority.
    /// </summary>
    void Connect();
}