using SystemXxHash128 = System.IO.Hashing.XxHash128;

namespace CryptoUtility.System.Extras;

/// <summary>
/// Provides a XxHash128 implementation by wrapping <see cref="System.IO.Hashing.XxHash128"/>.
/// </summary>
[GenerateStaticApi]
public sealed class XxHash128Impl : IHashProvider
{
    /// <summary>
    /// The shared static instance of <see cref="XxHash128Impl"/>.
    /// </summary>
    public static readonly XxHash128Impl Shared = new();

    public byte[] Hash(byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(message);
        return SystemXxHash128.Hash(message);
    }
}
