namespace CryptoUtility;

public interface IDigitalSignature
{
    public byte[] Sign(byte[] message, byte[] secretKey);

    public bool Verify(byte[] message, byte[] signature, byte[] publicKey);

    public (byte[] PublicKey, byte[] SecretKey) GenerateKeyPair();
}
