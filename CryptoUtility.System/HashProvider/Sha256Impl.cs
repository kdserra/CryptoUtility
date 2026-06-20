using System.Security.Cryptography;

namespace CryptoUtility.System;

[GenerateStaticApi]
public sealed class Sha256Impl : IHashProvider
{
    public static readonly Sha256Impl Shared = new();

    public byte[] Hash(byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(message);
        using var alg = SHA256.Create();
        byte[] hash = alg.ComputeHash(message);
        return hash;
    }
}
