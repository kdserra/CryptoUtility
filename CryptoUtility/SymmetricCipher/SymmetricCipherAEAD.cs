namespace CryptoUtility;

internal abstract class SymmetricCipherAEAD : SymmetricCipherAE
{
    public override (bool success, byte[] encrypted) Encrypt(byte[] key, byte[] plaintext) =>
        Encrypt(key, plaintext, nonce: CryptoHelper.GetBytes(KeySizeBytes), aad: []);

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
