using SystemXxHash64 = System.IO.Hashing.XxHash64;

namespace CryptoUtility.System.Extras;

[GenerateStaticApi]
public sealed class XxHash64Impl : IHashProvider
{
    public static readonly XxHash64Impl Shared = new();

    public byte[] Hash(byte[] message)
    {
        return SystemXxHash64.Hash(message);
    }
}
