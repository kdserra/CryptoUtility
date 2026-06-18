using System.Security.Cryptography;

namespace CryptoUtility;

[GenerateStaticApi]
public sealed class Sha384Impl : IHashProvider
{
    public static readonly Sha384Impl Shared = new();

    public byte[] Hash(byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(message);
        using var alg = SHA384.Create();
        byte[] hash = alg.ComputeHash(message);
        return hash;
    }
}
