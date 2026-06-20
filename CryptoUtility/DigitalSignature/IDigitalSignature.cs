namespace CryptoUtility;

public interface IDigitalSignature
{
    public (bool success, byte[] signature) Sign(byte[] message, byte[] secretKey);

    public bool Verify(byte[] message, byte[] signature, byte[] publicKey);

    public (byte[] PublicKey, byte[] SecretKey) GenerateKeyPair();
}
