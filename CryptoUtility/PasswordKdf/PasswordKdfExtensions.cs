namespace CryptoUtility;

/// <summary>
/// Provides extension methods for Password-based Key Derivation Functions (Such as PBKDF2).
/// </summary>
public static class PasswordKdfExtensions
{
    /// <summary>
    /// Derives a key from a password and salt, returning the result as a Base64-encoded string.
    /// </summary>
    /// <param name="kdf">The password KDF instance.</param>
    /// <param name="password">The password string.</param>
    /// <param name="salt">The salt bytes. Cannot be null.</param>
    /// <param name="iterations">The number of iterations to perform.</param>
    /// <param name="outputLength">The desired length of the derived key in bytes.</param>
    /// <returns>A Base64-encoded string representing the derived key, or an empty string if derivation fails.</returns>
    public static string DeriveKeyBase64(
        this IPasswordKdf kdf,
        string password,
        int iterations,
        int outputLength,
        byte[] salt
    )
    {
        try
        {
            if (!LibraryHelper.NotNullOrEmpty(kdf, password, salt))
            {
                return string.Empty;
            }

            byte[] keyBytes = kdf.DeriveKey(password, salt, iterations, outputLength);
            string keyBase64 = Convert.ToBase64String(keyBytes);
            return keyBase64;
        }
        catch
        {
            return string.Empty;
        }
    }
}
