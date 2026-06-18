using System.Security.Cryptography;

namespace CryptoUtility;

[GenerateStaticApi]
public sealed class Sha1Impl : IHashProvider
{
    public static readonly Sha1Impl Shared = new();

    public byte[] Hash(byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(message);
        using var alg = SHA1.Create();
        byte[] hash = alg.ComputeHash(message);
        return hash;
    }
}
