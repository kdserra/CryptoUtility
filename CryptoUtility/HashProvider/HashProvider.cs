using System.Security.Cryptography;

namespace CryptoUtility;

/// <summary>
/// Provides an abstract base class for hashing related operations, allowing derived classes to implement specific
/// hashing algorithms.
/// </summary>
public abstract class HashProvider
{
    /// <summary>
    /// Provides a new instance of the desired HMAC implementation.
    /// </summary>
    /// <remarks>
    /// HMACs are not thread-safe, as such they should not share their implementation. By using a factory we ensure
    /// each instance is created upon request, used, and disposed of immediately afterwards. This prevents issues
    /// related to concurrent usage of the shared HMAC instances.
    /// </remarks>
    private readonly Func<HMAC> _hmacProvider = () =>
    {
        return new HMACSHA256();
    };

    /// <summary>
    /// Responsible for setting up, and caching the initial state before usage.
    /// </summary>
    /// <param name="hmacProvider">Optional parameter. Responisble for providing an HMAC used for signing and verifying
    /// messages. If unspecified, <see cref="HMACSHA256"/> is used.</param>
    public HashProvider(Func<HMAC>? hmacProvider = null)
    {
        if (hmacProvider != null)
        {
            _hmacProvider = hmacProvider;
        }
    }

    /// <summary>
    /// Computes the hash value for the specified input data using the algorithm implemented by the derived class.
    /// </summary>
    /// <param name="input">The byte array containing the data to hash. This parameter must not be null or empty.</param>
    /// <returns>A byte array that contains the computed hash value.</returns>
    public abstract byte[] Hash(byte[] input);

    /// <summary>
    /// Computes a Hash-based Message Authentication Code (HMAC) signature for the specified input data using the
    /// provided secret key.
    /// </summary>
    /// <remarks>The method uses the configured HMAC provider to generate a secure signature. For best
    /// security, use a strong, randomly generated key and ensure both input and key are not null. The returned
    /// signature can be used to verify the authenticity and integrity of the input data.</remarks>
    /// <param name="input">The data to be signed. This must be a non-null byte array containing the message or payload
    /// to authenticate.</param>
    /// <param name="key">The secret key used to generate the HMAC signature. This must be a non-null byte array and
    /// should be kept confidential to ensure signature integrity.</param>
    /// <returns>A byte array containing the computed HMAC signature for the input data.</returns>
    public byte[] Sign(byte[] input, byte[] key)
    {
        using HMAC hmac = _hmacProvider.Invoke();
        byte[] result = hmac.ComputeHash(input);
        return result;
    }

    /// <summary>
    /// Verifies that the specified signature is valid for the given input data using the provided key.
    /// </summary>
    /// <remarks>This method performs a fixed-time comparison to help prevent timing attacks. All parameters
    /// must be non-null and of appropriate length for the verification to succeed.</remarks>
    /// <param name="input">The input data to verify, as a byte array. Cannot be null.</param>
    /// <param name="signature">The signature to verify against the input data, as a byte array. Cannot be null.</param>
    /// <param name="key">The key used to verify the signature, as a byte array. Cannot be null.</param>
    /// <returns>true if the signature is valid for the input and key; otherwise, false.</returns>
    public bool Verify(byte[] input, byte[] signature, byte[] key)
    {
        byte[] computed = Sign(input, key);
        bool result = CryptoHelper.FixedTimeEquals(computed, signature);
        return result;
    }
}
