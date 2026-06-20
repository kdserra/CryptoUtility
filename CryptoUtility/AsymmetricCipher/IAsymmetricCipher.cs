namespace CryptoUtility;

public interface IAsymmetricCipher
{
    public int KeySizeBytes { get; }

    public int SaltSizeBytes { get; }

    public byte[] Encrypt(byte[] publicKey, byte[] plaintext);

    public byte[] Decrypt(byte[] secretKey, byte[] encrypted);

    public (byte[] publicKey, byte[] secretKey) GenerateKeyPair();
}
