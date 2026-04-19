namespace CryptoUtility;

/// <summary>
/// Symmetric Authenticated Encryption, with Associated Data (AEAD) ciphers additionally compute an authentication tag
/// during encryption that is verified upon decryption, ensuring both confidentiality and integrity of the ciphertext
///and any associated (non-encrypted) data.
/// </summary>
internal abstract class SymmetricCipherAEAD : SymmetricCipher
{
    public override (bool success, byte[] encrypted) Encrypt(byte[] key, byte[] plaintext) =>
        Encrypt(key, plaintext, nonce: GenerateNonce(), aad: []);

    public override (bool success, byte[] encrypted) Encrypt(
        byte[] key,
        byte[] plaintext,
        byte[] nonce
    ) => Encrypt(key, plaintext, nonce, aad: []);

    public abstract (bool success, byte[] encrypted) Encrypt(
        byte[] key,
        byte[] plaintext,
        byte[] nonce,
        byte[] aad
    );
}
