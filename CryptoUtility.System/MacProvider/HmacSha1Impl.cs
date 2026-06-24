using System.Security.Cryptography;

namespace CryptoUtility.System;

/// <summary>
/// Represents the hmac sha1 implementation.
/// </summary>
[GenerateStaticApi]
public sealed class HmacSha1Impl : IMacProvider
{
    /// <summary>
    /// Gets the shared instance.
    /// </summary>
    public static readonly HmacSha1Impl Shared = new();

    /// <summary>
    /// Gets the required key size in bytes, or 0 if variable-length keys are accepted.
    /// </summary>
    public int RequiredKeySizeInBytes => 0;

    /// <summary>
    /// Gets the size of the computed MAC in bytes.
    /// </summary>
    public int MacSizeInBytes => 20;

    /// <summary>
    /// Computes the Message Authentication Code (MAC) for the specified message using the provided key.
    /// </summary>
    /// <param name="key">The symmetric key.</param>
    /// <param name="message">The input data to process.</param>
    /// <returns>A byte array containing the result.</returns>
    public byte[] ComputeMac(byte[] key, byte[] message)
    {
        LibraryHelper.ThrowIfNull(key);
        LibraryHelper.ThrowIfNull(message);

        using var hmac = new HMACSHA1(key);

        return hmac.ComputeHash(message);
    }
}
