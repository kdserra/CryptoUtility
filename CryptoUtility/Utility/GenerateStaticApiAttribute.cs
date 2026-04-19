namespace CryptoUtility;

/// <summary>
/// Marks a class to be wrapped with a static class that raises it's public functions and properties as static functions
/// and properties, by accessing them through a cached reference to the underlying instance. This is used to provide a
/// more convenient API for users of the library.
/// </summary>
/// <remarks>
/// Usage of this attribute requires the implementation class to have the "Impl" suffix to avoid naming conflicts with
/// the generated static class. For example, if you have a class named "Aes256GcmImpl" marked with this attribute, a
/// static class named "Aes256Gcm" will be generated to provide static access to its members.
/// </remarks>
[AttributeUsage(AttributeTargets.Class)]
internal sealed class GenerateStaticApiAttribute : Attribute { }
