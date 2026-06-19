using System.Security.Cryptography;

namespace CryptoUtility;

[GenerateStaticApi]
public sealed class Md5Impl : IHashProvider
{
    public static readonly Md5Impl Shared = new();

    public byte[] Hash(byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(message);
        using var alg = MD5.Create();
        byte[] hash = alg.ComputeHash(message);
        return hash;
    }
}
