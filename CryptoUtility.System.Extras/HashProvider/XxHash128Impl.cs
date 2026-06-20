using SystemXxHash128 = System.IO.Hashing.XxHash128;

namespace CryptoUtility.System.Extras;

[GenerateStaticApi]
public sealed class XxHash128Impl : IHashProvider
{
    public static readonly XxHash128Impl Shared = new();

    public byte[] Hash(byte[] message)
    {
        return SystemXxHash128.Hash(message);
    }
}
