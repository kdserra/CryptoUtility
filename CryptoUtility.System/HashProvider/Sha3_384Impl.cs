#if NET8_0_OR_GREATER
using System.Security.Cryptography;

namespace CryptoUtility.System;
    /// <summary>
    /// Represents the sha3_384 implementation.
    /// </summary>

[GenerateStaticApi]
public sealed class Sha3_384Impl : IHashProvider
{
    /// <summary>
    /// Gets the shared instance.
    /// </summary>
    public static readonly Sha3_384Impl Shared = new();
    /// <summary>
    /// Computes the cryptographic hash of the specified input data.
    /// </summary>
    /// <param name="message">The input data to process.</param>
    /// <returns>A byte array containing the result.</returns>

    public byte[] Hash(byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(message);
        using var alg = SHA3_384.Create();
        byte[] hash = alg.ComputeHash(message);
        return hash;
    }
}
#endif
