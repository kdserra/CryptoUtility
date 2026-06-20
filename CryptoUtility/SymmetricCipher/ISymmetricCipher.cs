namespace CryptoUtility;

public interface ISymmetricCipher
{
    public int KeySizeBytes { get; }

    public int NonceSizeBytes { get; }

    public (bool success, byte[] encrypted) Encrypt(byte[] key, byte[] plaintext, byte[] nonce);

    public (bool success, byte[] plaintext) Decrypt(byte[] key, byte[] encrypted);
}
