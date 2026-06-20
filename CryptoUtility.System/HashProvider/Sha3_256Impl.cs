#if NET8_0_OR_GREATER
using System.Security.Cryptography;

namespace CryptoUtility.System;

[GenerateStaticApi]
public sealed class Sha3_256Impl : IHashProvider
{
    public static readonly Sha3_256Impl Shared = new();

    public byte[] Hash(byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(message);
        using var alg = SHA3_256.Create();
        byte[] hash = alg.ComputeHash(message);
        return hash;
    }
}
#endif
