namespace CryptoUtility;

/// <summary>
/// Symmetric Authenticated Encryption Ciphers additionally compute a tag upon encryption, that is verified upon
/// decryption.
/// </summary>
internal abstract class SymmetricCipherAE : SymmetricCipher
{
    /// <summary>
    /// Gets the size, in bytes, of the authentication tag. This tag is used to verify that the encrypted data (and any
    /// additional data) has not been changed or tampered with.
    /// </summary>
    public abstract int AuthTagSizeBytes { get; }

    /// <inheritdoc cref="SymmetricCipher.VerifyDecryptionParameters(byte[], SymmetricCipherEnvelope)"/>
    protected override bool VerifyDecryptionParameters(byte[] key, SymmetricCipherEnvelope envelope)
    {
        return key.Length == KeySizeBytes
            && envelope.Ciphertext.Length > 0
            && envelope.Nonce.Length == NonceSizeBytes
            && envelope.Tag.Length == AuthTagSizeBytes;
    }
}
