using SystemXxHash64 = System.IO.Hashing.XxHash64;

namespace CryptoUtility.System.Extras;

/// <summary>
/// Provides a XxHash64 implementation by wrapping <see cref="System.IO.Hashing.XxHash64"/>.
/// </summary>
[GenerateStaticApi]
public sealed class XxHash64Impl : IHashProvider
{
    /// <summary>
    /// The shared static instance of <see cref="XxHash64Impl"/>.
    /// </summary>
    public static readonly XxHash64Impl Shared = new();

    public byte[] Hash(byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(message);
        return SystemXxHash64.Hash(message);
    }
}
