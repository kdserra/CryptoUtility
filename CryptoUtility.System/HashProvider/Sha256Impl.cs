using System.Security.Cryptography;

namespace CryptoUtility.System;

/// <summary>
/// Represents the sha256 implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Sha256Impl : IHashProvider
{
    /// <summary>
    /// Gets the shared instance.
    /// </summary>
    public static readonly Sha256Impl Shared = new();

    /// <summary>
    /// Computes the cryptographic hash of the specified input data.
    /// </summary>
    /// <param name="message">The input data to process.</param>
    /// <returns>A byte array containing the result.</returns>
    public byte[] Hash(byte[] message)
    {
        LibraryHelper.ThrowIfNull(message);
        using var alg = SHA256.Create();
        byte[] hash = alg.ComputeHash(message);
        return hash;
    }
}
