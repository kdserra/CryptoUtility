using System.Text;

namespace CryptoUtility;

internal abstract class SymmetricCipher
{
    /// <summary>
    /// Gets the size, in bytes, of the cryptographic key used for encryption and decryption operations.
    /// </summary>
    public abstract int KeySizeBytes { get; }

    /// <summary>
    /// Gets the size, in bytes, of the nonce. A nonce is a unique value used for each encryption so that encrypting the
    /// same data more than once produces different ciphertext. This helps prevent attackers from detecting patterns or
    /// learning information about the original data.
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
    public virtual (bool success, byte[] encrypted) Encrypt(byte[] key, byte[] plaintext) =>
        Encrypt(key, plaintext, nonce: GenerateNonce());

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
    /// Encrypts the specified plaintext using the provided cryptographic key.
    /// </summary>
    /// <param name="key">The cryptographic key used to perform the encryption.</param>
    /// <param name="plaintext">The data to be encrypted.</param>
    /// <param name="nonce">A unique value used for this encryption operation that prevents reuse of ciphertext for the
    /// same key, ensuring identical plaintexts encrypt differently each time.</param>
    ///
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
    public abstract (bool success, byte[] encrypted) Encrypt(
        byte[] key,
        byte[] plaintext,
        byte[] nonce
    );

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
    /// Decrypts the specified Base64-encoded encrypted string using the provided Base64 key and returns the decrypted
    /// plaintext as a Base64 string.
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
    /// Encrypts the specified plaintext using the provided Base64 key and returns the encrypted base64 data.
    /// </summary>
    /// <param name="key">The string representation of the cryptographic key in Base64.</param>
    /// <param name="plaintext">The data to be encrypted.</param>
    /// <returns>
    /// A tuple containing:
    /// <list type="bullet">
    /// <item>
    /// <description><c>success</c>: Indicates whether the encryption operation was successful.</description>
    /// </item>
    /// <item>
    /// <description><c>encrypted</c>: The encrypted bytes if successful; otherwise, an empty byte array.</description>
    /// </item>
    /// </list>
    /// </returns>
    public (bool success, byte[] encrypted) EncryptBase64(string key, byte[] plaintext)
    {
        byte[] keyBytes = Convert.FromBase64String(key);
        (bool success, byte[] encrypted) encryptedResult = Encrypt(keyBytes, plaintext);
        return encryptedResult;
    }

    /// <summary>
    /// Decrypts the specified encrypted data using the provided Base64 cryptographic key and returns the decrypted
    /// plaintext.
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
    public (bool success, byte[] plaintext) DecryptBase64(string key, byte[] encrypted)
    {
        byte[] keyBytes = Convert.FromBase64String(key);
        (bool success, byte[] plaintext) decryptedResult = Decrypt(keyBytes, encrypted);
        return decryptedResult;
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
    /// Generates a new cryptographic nonce for use in encryption or decryption operations.
    /// </summary>
    /// <returns>A byte array containing the generated cryptographic nonce.</returns>
    public virtual byte[] GenerateNonce()
    {
        return CryptoHelper.GetBytes(NonceSizeBytes);
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
    /// Verifies the Cipher has all the required parameters for encryption.
    /// </summary>
    /// <param name="key">The key to verify.</param>
    /// <param name="plaintext">The plaintext to verify.</param>
    /// <param name="nonce">The nonce to verify.</param>
    /// <returns>True when the parameters passed verification, false when it fails; missing required parameters.</returns>
    protected virtual bool VerifyEncryptionParameters(byte[] key, byte[] plaintext, byte[] nonce)
    {
        return CryptoHelper.NotNull(key, plaintext, nonce)
            && key.Length == KeySizeBytes
            && plaintext.Length > 0
            && nonce.Length == NonceSizeBytes;
    }

    /// <summary>
    /// Verifies the Cipher has all the required parameters for decryption.
    /// </summary>
    /// <param name="envelope">The cipher envelope to verify.</param>
    /// <returns>True when the parameters passed verification, false when it fails; missing required parameters.</returns>
    protected virtual bool VerifyDecryptionParameters(byte[] key, SymmetricCipherEnvelope envelope)
    {
        return CryptoHelper.NotNull(key, envelope)
            && key.Length == KeySizeBytes
            && envelope.Ciphertext.Length > 0
            && envelope.Nonce.Length == NonceSizeBytes;
    }
}
