namespace Tests;

using UserRights.Application;

using Xunit.Abstractions;

/// <summary>
/// Represents the interface to the local security authority user right functions with support for serialization in xUnit.net.
/// </summary>
public interface IUserRightsSerializable : IUserRights, IXunitSerializable
{
}