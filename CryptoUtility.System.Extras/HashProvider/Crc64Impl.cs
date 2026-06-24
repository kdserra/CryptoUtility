using SystemCrc64 = System.IO.Hashing.Crc64;

namespace CryptoUtility.System.Extras;

/// <summary>
/// Provides a CRC64 implementation by wrapping <see cref="System.IO.Hashing.Crc64"/>.
/// </summary>
[GenerateStaticApi]
public sealed class Crc64Impl : IHashProvider
{
    /// <summary>
    /// The shared static instance of <see cref="Crc64Impl"/>.
    /// </summary>
    public static readonly Crc64Impl Shared = new();

    public byte[] Hash(byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(message);
        return SystemCrc64.Hash(message);
    }
}
