using SystemCrc32 = System.IO.Hashing.Crc32;

namespace CryptoUtility.System.Extras;

[GenerateStaticApi]
public sealed class Crc32Impl : IHashProvider
{
    public static readonly Crc32Impl Shared = new();

    public byte[] Hash(byte[] message)
    {
        return SystemCrc32.Hash(message);
    }
}
