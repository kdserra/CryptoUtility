using SystemXxHash32 = System.IO.Hashing.XxHash32;

namespace CryptoUtility.System.Extras;

[GenerateStaticApi]
public sealed class XxHash32Impl : IHashProvider
{
    public static readonly XxHash32Impl Shared = new();

    public byte[] Hash(byte[] message)
    {
        return SystemXxHash32.Hash(message);
    }
}
