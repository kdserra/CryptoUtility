namespace CryptoUtility;

/// <summary>
/// Marks a class to be wrapped with a static class that raises it's public functions and properties as static functions
/// and properties, by accessing them through a cached reference to the underlying instance. This is used to provide a
/// more convenient API for users of the library.
/// </summary>
[AttributeUsage(AttributeTargets.Class)]
public sealed class GenerateStaticApiAttribute : Attribute { }
