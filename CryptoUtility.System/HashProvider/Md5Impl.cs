using System.Security.Cryptography;

namespace CryptoUtility.System;

/// <summary>
/// Represents the md5 implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Md5Impl : IHashProvider
{
    /// <summary>
    /// Gets the shared instance.
    /// </summary>
    public static readonly Md5Impl Shared = new();

    /// <summary>
    /// Computes the cryptographic hash of the specified input data.
    /// </summary>
    /// <param name="message">The input data to process.</param>
    /// <returns>A byte array containing the result.</returns>
    public byte[] Hash(byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(message);
        using var alg = MD5.Create();
        byte[] hash = alg.ComputeHash(message);
        return hash;
    }
}
