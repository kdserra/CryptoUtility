using System.Text;

namespace CryptoUtility;

internal abstract class SymmetricCipher
{
    /// <summary>
    /// The cipher identifier used for tracking the cipher used for encrypting a given ciphertext.
    /// </summary>
    public abstract CipherID CipherID { get; }

    /// <summary>
    /// Gets the size, in bytes, of the cryptographic key used for encryption and decryption operations.
    /// </summary>
    public abstract int KeySizeBytes { get; }

    /// <summary>
    /// Gets the size, in bytes, of the cryptographic nonce used for encryption and decryption operations.
    /// </summary>
    public abstract int NonceSizeBytes { get; }

    /// <summary>
    /// Encrypts the specified plaintext using the provided cryptographic key.
    /// </summary>
    /// <param name="key">The cryptographic key used to perform the encryption.</param>
    /// <param name="plaintext">The data to be encrypted.</param>
    /// <returns>
    /// A tuple containing:
    /// <list type="bullet">
    /// <item>
    /// <description><c>success</c>: Indicates whether the encryption operation was successful.</description>
    /// </item>
    /// <item>
    /// <description><c>encrypted</c>: The resulting encrypted byte array if successful; otherwise, an empty byte array.</description>
    /// </item>
    /// </list>
    /// </returns>
    public abstract (bool success, byte[] encrypted) Encrypt(byte[] key, byte[] plaintext);

    /// <summary>
    /// Decrypts the specified encrypted data using the provided cryptographic key.
    /// </summary>
    /// <param name="key">The cryptographic key used to perform the decryption.</param>
    /// <param name="encrypted">The encrypted data to decrypt.</param>
    /// <returns>
    /// A tuple containing:
    /// <list type="bullet">
    /// <item>
    /// <description><c>success</c>: Indicates whether the decryption operation was successful.</description>
    /// </item>
    /// <item>
    /// <description><c>plaintext</c>: The resulting decrypted byte array if successful; otherwise, an empty byte array.</description>
    /// </item>
    /// </list>
    /// </returns>
    public abstract (bool success, byte[] plaintext) Decrypt(byte[] key, byte[] encrypted);

    /// <summary>
    /// Encrypts the specified plaintext UTF8 string using the provided Base64 key and returns a Base64-encoded result.
    /// </summary>
    /// <param name="key">The string representation of the cryptographic key in Base64.</param>
    /// <param name="plaintext">The plaintext UTF8 string to encrypt.</param>
    /// <returns>
    /// A tuple containing:
    /// <list type="bullet">
    /// <item>
    /// <description><c>success</c>: Indicates whether the encryption operation was successful.</description>
    /// </item>
    /// <item>
    /// <description><c>encrypted</c>: The Base64-encoded encrypted string if successful; otherwise, an empty string.</description>
    /// </item>
    /// </list>
    /// </returns>
    public (bool success, string encrypted) EncryptBase64(string key, string plaintext)
    {
        byte[] keyBytes = Convert.FromBase64String(key);
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        (bool success, byte[] encrypted) encryptedResult = Encrypt(keyBytes, plaintextBytes);

        if (!encryptedResult.success)
        {
            return (false, string.Empty);
        }

        string encrypted = Convert.ToBase64String(encryptedResult.encrypted);

        return (true, encrypted);
    }

    /// <summary>
    /// Decrypts the specified Base64-encoded encrypted string using the provided Base64 key and returns the decrypted plaintext as a Base64 string.
    /// </summary>
    /// <param name="key">The cryptographic key in Base64 format.</param>
    /// <param name="encrypted">The encrypted data to decrypt in Base64 format.</param>
    /// <returns>
    /// A tuple containing:
    /// <list type="bullet">
    /// <item>
    /// <description><c>success</c>: Indicates whether the decryption operation was successful.</description>
    /// </item>
    /// <item>
    /// <description><c>plaintext</c>: The plaintext UTF8 string if successful; otherwise, an empty string.</description>
    /// </item>
    /// </list>
    /// </returns>
    public (bool success, string plaintext) DecryptBase64(string key, string encrypted)
    {
        byte[] keyBytes = Convert.FromBase64String(key);
        byte[] encryptedBytes = Convert.FromBase64String(encrypted);
        (bool success, byte[] plaintext) decryptedResult = Decrypt(keyBytes, encryptedBytes);

        if (!decryptedResult.success)
        {
            return (false, string.Empty);
        }

        string plaintext = Encoding.UTF8.GetString(decryptedResult.plaintext);

        return (true, plaintext);
    }

    /// <summary>
    /// Generates a new cryptographic key for use in encryption or decryption operations.
    /// </summary>
    /// <returns>A byte array containing the generated cryptographic key.</returns>
    public virtual byte[] GenerateKey()
    {
        return CryptoHelper.GetBytes(KeySizeBytes);
    }

    /// <summary>
    /// Generates a new cryptographic key and returns it as a Base64 encoded string.
    /// </summary>
    /// <returns>The generated key as a Base64 string.</returns>
    public string GenerateKeyBase64()
    {
        byte[] key = GenerateKey();
        string result = Convert.ToBase64String(key);
        return result;
    }

    /// <summary>
    /// Verifies the Cipher has all the required parameters for decryption.
    /// </summary>
    /// <param name="envelope">The cipher envelope to verify.</param>
    /// <returns>True when the envelope passed verification, false when it fails; missing required paramters.</returns>
    protected virtual bool Verify(SymmetricCipherEnvelope envelope)
    {
        return envelope.Cipher == CipherID
            && !envelope.Ciphertext.IsNullOrEmpty()
            && !envelope.Nonce.IsNullOrEmpty()
            && envelope.Nonce.Length == NonceSizeBytes;
    }
}
