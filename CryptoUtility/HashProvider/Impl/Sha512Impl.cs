using System.Security.Cryptography;

namespace CryptoUtility;

[GenerateStaticApi]
public sealed class Sha512Impl : IHashProvider
{
    public static readonly Sha512Impl Shared = new();

    public byte[] Hash(byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(message);
        using var alg = SHA512.Create();
        byte[] hash = alg.ComputeHash(message);
        return hash;
    }
}
