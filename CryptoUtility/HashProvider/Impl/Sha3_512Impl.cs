#if NET8_0_OR_GREATER
using System.Security.Cryptography;

namespace CryptoUtility;

[GenerateStaticApi]
public sealed class Sha3_512Impl : IHashProvider
{
    public static readonly Sha3_512Impl Shared = new();

    public byte[] Hash(byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(message);
        using var alg = SHA3_512.Create();
        byte[] hash = alg.ComputeHash(message);
        return hash;
    }
}
#endif
