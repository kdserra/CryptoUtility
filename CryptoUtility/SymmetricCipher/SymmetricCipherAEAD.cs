namespace CryptoUtility;

/// <summary>
/// Symmetric Authenticated Encryption, with Associated Data (AEAD) ciphers additionally compute an authentication tag
/// during encryption that is verified upon decryption, ensuring both confidentiality and integrity of the ciphertext
///and any associated (non-encrypted) data.
/// </summary>
internal abstract class SymmetricCipherAEAD : SymmetricCipher
{
    /// <inheritdoc cref="SymmetricCipher.Encrypt" />
    public override (bool success, byte[] encrypted) Encrypt(byte[] key, byte[] plaintext) =>
        Encrypt(key, plaintext, nonce: GenerateNonce(), aad: []);

    /// <inheritdoc cref="SymmetricCipher.Encrypt(byte[], byte[], byte[])" />
    public override (bool success, byte[] encrypted) Encrypt(
        byte[] key,
        byte[] plaintext,
        byte[] nonce
    ) => Encrypt(key, plaintext, nonce, aad: []);

    /// <summary>
    /// Encrypts the specified plaintext using the provided cryptographic key.
    /// </summary>
    /// <param name="key">The cryptographic key used to perform the encryption.</param>
    /// <param name="plaintext">The data to be encrypted.</param>
    /// <param name="nonce">A unique value used for this encryption operation that prevents reuse of ciphertext for the
    /// same key, ensuring identical plaintexts encrypt differently each time.</param>
    /// <param name="aad">Additional authenticated data (AAD) to be included in the authentication tag but not encrypted.  This data is authenticated alongside the ciphertext to ensure integrity, but remains in plaintext form.</param>
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
        byte[] nonce,
        byte[] aad
    );

    protected override bool Verify(SymmetricCipherEnvelope envelope)
    {
        return !envelope.Ciphertext.IsNullOrEmpty()
            && !envelope.Nonce.IsNullOrEmpty()
            && envelope.Nonce.Length == NonceSizeBytes
            && !envelope.Tag.IsNullOrEmpty();

        // AAD not required, optional parameter.
    }
}
