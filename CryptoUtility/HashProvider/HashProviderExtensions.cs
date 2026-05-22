using System.Security.Cryptography;

namespace CryptoUtility;

public static class HashProviderExtensions
{
    private static Func<HMAC> DefaultHmacProvider => () => new HMACSHA256();

    /// <summary>
    /// Computes the hash value for the specified input data using the algorithm implemented by the derived class.
    /// </summary>
    /// <param name="hashProvider">The hash provider instance.</param>
    /// <param name="message">The UTF8 string containing the data to hash.  This parameter must not be null or empty.</param>
    /// <returns>A base64 string that contains the computed hash value.</returns>
    public static string HashBase64(this IHashProvider hashProvider, string message)
    {
        if (!LibraryHelper.NotNull(hashProvider, message))
        {
            return string.Empty;
        }

        byte[] messageBytes = System.Text.Encoding.UTF8.GetBytes(message);
        byte[] hashBytes = hashProvider.Hash(messageBytes);
        string hashBase64 = Convert.ToBase64String(hashBytes);

        return hashBase64;
    }

    /// <summary>
    /// Computes a Hash-based Message Authentication Code (HMAC) signature for the specified input data using the
    /// provided secret key.
    /// </summary>
    /// <remarks>The method uses the configured HMAC provider to generate a secure signature. For best
    /// security, use a strong, randomly generated key and ensure both input and key are not null. The returned
    /// signature can be used to verify the authenticity and integrity of the input data.</remarks>
    /// <param name="hashProvider">The hash provider instance.</param>
    /// <param name="message">The data to be signed. This must be a non-null byte array containing the message or payload
    /// to authenticate.</param>
    /// <param name="key">The secret key used to generate the HMAC signature. This must be a non-null byte array and
    /// should be kept confidential to ensure signature integrity.</param>
    /// <param name="hmacProvider">Optional parameter that is responsible for providing a new instance of an HMAC that
    /// will be used to compute the signature, if unspecified it uses <see cref="HMACSHA256"/>.</param>
    /// <returns>A byte array containing the computed HMAC signature for the input data.</returns>
    public static byte[] Sign(
        this IHashProvider hashProvider,
        byte[] message,
        byte[] key,
        Func<HMAC>? hmacProvider = null
    )
    {
        if (!LibraryHelper.NotNull(hashProvider, message, key))
        {
            return Array.Empty<byte>();
        }

        hmacProvider ??= DefaultHmacProvider;
        using HMAC hmac = hmacProvider.Invoke();
        hmac.Key = key;
        byte[] result = hmac.ComputeHash(message);

        return result;
    }

    /// <summary>
    /// Computes a Base64-encoded Hash-based Message Authentication Code (HMAC) signature for the specified string input
    /// using the provided secret key.
    /// </summary>
    /// <remarks>
    /// The input message and key are encoded using UTF-8 before computing the signature. The resulting HMAC is returned
    /// as a Base64-encoded string for convenient storage or transmission. For best security, use a strong, randomly
    /// generated key and ensure both inputs are not null.
    /// </remarks>
    /// <param name="hashProvider">The hash provider instance.</param>
    /// <param name="message">The string data to be signed. Cannot be null.</param>
    /// <param name="key">The secret key used to generate the HMAC signature. Cannot be null and should be kept confidential.</param>
    /// <param name="hmacProvider">
    /// Optional parameter that provides a new instance of an HMAC algorithm. If not specified, <see cref="HMACSHA256"/> is used.
    /// </param>
    /// <returns>A Base64-encoded string representing the computed HMAC signature.</returns>
    public static string SignBase64(
        this IHashProvider hashProvider,
        string message,
        string key,
        Func<HMAC>? hmacProvider = null
    )
    {
        if (!LibraryHelper.NotNull(hashProvider, message, key))
        {
            return string.Empty;
        }

        byte[] messageBytes = System.Text.Encoding.UTF8.GetBytes(message);
        byte[] keyBytes = System.Text.Encoding.UTF8.GetBytes(key);
        byte[] signatureBytes = hashProvider.Sign(messageBytes, keyBytes, hmacProvider);
        string signatureBase64 = Convert.ToBase64String(signatureBytes);
        return signatureBase64;
    }

    /// <summary>
    /// Verifies that the specified signature is valid for the given input data using the provided key.
    /// </summary>
    /// <remarks>This method performs a fixed-time comparison to help prevent timing attacks. All parameters
    /// must be non-null and of appropriate length for the verification to succeed.</remarks>
    /// <param name="hashProvider">The hash provider instance.</param>
    /// <param name="message">The input data to verify, as a byte array. Cannot be null.</param>
    /// <param name="signature">The signature to verify against the input data, as a byte array. Cannot be null.</param>
    /// <param name="key">The key used to verify the signature, as a byte array. Cannot be null.</param>
    /// <param name="hmacProvider">Optional parameter that is responsible for providing a new instance of an HMAC that
    /// will be used to compute the signature, if unspecified it uses <see cref="HMACSHA256"/>.</param>
    /// <returns>true if the signature is valid for the input and key; otherwise, false.</returns>
    public static bool Verify(
        this IHashProvider hashProvider,
        byte[] message,
        byte[] signature,
        byte[] key,
        Func<HMAC>? hmacProvider = null
    )
    {
        if (!LibraryHelper.NotNull(hashProvider, message, signature, key))
        {
            return false;
        }

        byte[] computedSignature = hashProvider.Sign(message, key, hmacProvider);
        bool result = CryptoHelper.FixedTimeEquals(computedSignature, signature);
        return result;
    }

    /// <summary>
    /// Verifies that the specified Base64-encoded signature is valid for the given string input and key.
    /// </summary>
    /// <remarks>
    /// The input message and key are encoded using UTF-8, and the provided signature is decoded from Base64 before
    /// verification. This method performs a fixed-time comparison to help prevent timing attacks. All inputs must be
    /// non-null and properly formatted for verification to succeed.
    /// </remarks>
    /// <param name="hashProvider">The hash provider instance.</param>
    /// <param name="message">The string data to verify. Cannot be null.</param>
    /// <param name="signature">The Base64-encoded signature to verify against the message. Cannot be null.</param>
    /// <param name="key">The secret key used to verify the signature. Cannot be null.</param>
    /// <param name="hmacProvider">
    /// Optional parameter that provides a new instance of an HMAC algorithm. If not specified, <see cref="HMACSHA256"/> is used.
    /// </param>
    /// <returns><c>true</c> if the signature is valid for the given message and key; otherwise, <c>false</c>.</returns>
    public static bool VerifyBase64(
        this IHashProvider hashProvider,
        string message,
        string signature,
        string key,
        Func<HMAC>? hmacProvider = null
    )
    {
        if (!LibraryHelper.NotNull(hashProvider, message, signature, key))
        {
            return false;
        }

        byte[] messageBytes = System.Text.Encoding.UTF8.GetBytes(message);
        byte[] keyBytes = System.Text.Encoding.UTF8.GetBytes(key);
        byte[] signatureBytes = Convert.FromBase64String(signature);
        bool isValid = hashProvider.Verify(messageBytes, signatureBytes, keyBytes, hmacProvider);

        return isValid;
    }
}
