namespace CryptoUtility;

/// <summary>
/// Symmetric Authenticated Encryption Ciphers additionally compute a tag upon encryption, that is verified upon
/// decryption.
/// </summary>
internal abstract class SymmetricCipherAE : SymmetricCipher
{
    protected override bool Verify(SymmetricCipherEnvelope envelope)
    {
        return envelope.Cipher == CipherID
            && !envelope.Ciphertext.IsNullOrEmpty()
            && !envelope.Nonce.IsNullOrEmpty()
            && envelope.Nonce.Length == NonceSizeBytes
            && !envelope.Tag.IsNullOrEmpty();
    }
}
