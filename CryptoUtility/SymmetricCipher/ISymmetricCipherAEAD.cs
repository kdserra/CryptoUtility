namespace CryptoUtility;

/// <summary>
/// Defines a contract for Authenticated Encryption with Associated Data (AEAD) symmetric ciphers.
/// </summary>
public interface ISymmetricCipherAEAD : ISymmetricCipherAE
{
    /// <summary>
    /// Encrypts the plaintext using the key, nonce, and additional authenticated data (AAD).
    /// </summary>
    public byte[] Encrypt(byte[] key, byte[] plaintext, byte[] nonce, byte[] aad);

    /// <summary>
    /// Decrypts the ciphertext using the key and additional authenticated data (AAD).
    /// </summary>
    public byte[] Decrypt(byte[] key, byte[] encrypted, byte[] aad);
}
