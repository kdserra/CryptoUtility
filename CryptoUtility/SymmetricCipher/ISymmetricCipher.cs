namespace CryptoUtility;

public interface ISymmetricCipher
{
    public int KeySizeBytes { get; }

    public int NonceSizeBytes { get; }

    public byte[] Encrypt(byte[] key, byte[] plaintext, byte[] nonce);

    public byte[] Decrypt(byte[] key, byte[] encrypted);
}
