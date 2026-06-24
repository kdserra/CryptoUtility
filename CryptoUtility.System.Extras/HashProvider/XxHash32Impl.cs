using SystemXxHash32 = System.IO.Hashing.XxHash32;

namespace CryptoUtility.System.Extras;

/// <summary>
/// Provides a XxHash32 implementation by wrapping <see cref="System.IO.Hashing.XxHash32"/>.
/// </summary>
[GenerateStaticApi]
public sealed class XxHash32Impl : IHashProvider
{
    /// <summary>
    /// The shared static instance of <see cref="XxHash32Impl"/>.
    /// </summary>
    public static readonly XxHash32Impl Shared = new();

    public byte[] Hash(byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(message);
        return SystemXxHash32.Hash(message);
    }
}
