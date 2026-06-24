#if NET8_0_OR_GREATER
using System.Security.Cryptography;

namespace CryptoUtility.System;

/// <summary>
/// Represents the hmac sha3_384 implementation.
/// </summary>
[GenerateStaticApi]
public sealed class HmacSha3_384Impl : IMacProvider
{
    /// <summary>
    /// Gets the shared instance.
    /// </summary>
    public static readonly HmacSha3_384Impl Shared = new();

    /// <summary>
    /// Gets the required key size in bytes, or 0 if variable-length keys are accepted.
    /// </summary>
    public int RequiredKeySizeInBytes => 0;

    /// <summary>
    /// Gets the size of the computed MAC in bytes.
    /// </summary>
    public int MacSizeInBytes => 48;

    /// <summary>
    /// Computes the Message Authentication Code (MAC) for the specified message using the provided key.
    /// </summary>
    /// <param name="key">The symmetric key.</param>
    /// <param name="message">The input data to process.</param>
    /// <returns>A byte array containing the result.</returns>
    public byte[] ComputeMac(byte[] key, byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(key, message);

        using var hmac = new HMACSHA3_384(key);

        return hmac.ComputeHash(message);
    }
}

#endif
