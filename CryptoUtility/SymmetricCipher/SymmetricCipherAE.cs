namespace CryptoUtility;

internal abstract class SymmetricCipherAE : SymmetricCipher
{
    public override (bool success, byte[] encrypted) Encrypt(byte[] key, byte[] plaintext) =>
        Encrypt(key, plaintext, nonce: CryptoHelper.GetBytes(NonceSizeBytes));

    public abstract (bool success, byte[] encrypted) Encrypt(
        byte[] key,
        byte[] plaintext,
        byte[] nonce
    );

    protected override bool Verify(SymmetricCipherEnvelope envelope)
    {
        return envelope.Cipher == CipherID
            && !envelope.Ciphertext.IsNullOrEmpty()
            && !envelope.Nonce.IsNullOrEmpty()
            && envelope.Nonce.Length == NonceSizeBytes
            && !envelope.Tag.IsNullOrEmpty();
    }
}
