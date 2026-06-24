namespace CryptoUtility;

/// <summary>
/// Defines a contract for Password Key Derivation Functions (KDFs).
/// </summary>
public interface IPasswordKdf
{
    /// <summary>
    /// Derives a key of the specified length from the password and salt.
    /// </summary>
    /// <param name="passwordUtf8">The UTF-8 password string.</param>
    /// <param name="salt">The salt value.</param>
    /// <param name="outputLength">The desired length of the derived key in bytes.</param>
    /// <returns>A byte array containing the derived key.</returns>
    public byte[] DeriveKey(string passwordUtf8, byte[] salt, int outputLength);
}
