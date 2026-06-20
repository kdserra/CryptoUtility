using SystemCrc64 = System.IO.Hashing.Crc64;

namespace CryptoUtility.System.Extras;

[GenerateStaticApi]
public sealed class Crc64Impl : IHashProvider
{
    public static readonly Crc64Impl Shared = new();

    public byte[] Hash(byte[] message)
    {
        return SystemCrc64.Hash(message);
    }
}
