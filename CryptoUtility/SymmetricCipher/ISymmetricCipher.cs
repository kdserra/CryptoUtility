namespace CryptoUtility;

public interface ISymmetricCipher
{
    /// <summary>
    /// Gets the identifier for the symmetric cipher algorithm associated with this instance.
    /// </summary>
    public SymmetricCipherID CipherID { get; }

    /// <summary>
    /// Gets the size, in bytes, of the cryptographic key used for encryption and decryption operations.
    /// </summary>
    public int KeySizeBytes { get; }

    /// <summary>
    /// Gets the size, in bytes, of the nonce.
    ///
    /// A nonce is a unique value used for each encryption so that encrypting the
    /// same data more than once produces different ciphertext. This helps prevent attackers from detecting patterns or
    /// learning information about the original data.
    /// </summary>
    public int NonceSizeBytes { get; }

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
    public (bool success, byte[] encrypted) Encrypt(byte[] key, byte[] plaintext, byte[] nonce);

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
    public (bool success, byte[] plaintext) Decrypt(byte[] key, byte[] encrypted);
}
