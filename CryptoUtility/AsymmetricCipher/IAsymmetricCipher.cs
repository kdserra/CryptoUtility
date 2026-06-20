namespace CryptoUtility;

public interface IAsymmetricCipher
{
    public int KeySizeBytes { get; }

    public int SaltSizeBytes { get; }

    public (bool success, byte[] encrypted) Encrypt(byte[] publicKey, byte[] plaintext);

    public (bool success, byte[] plaintext) Decrypt(byte[] secretKey, byte[] encrypted);

    public (byte[] PublicKey, byte[] SecretKey) GenerateKeyPair();
}
