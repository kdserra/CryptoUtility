namespace CryptoUtility;

public interface IKeyAgreement
{
    public byte[] DeriveSharedSecret(byte[] secretKey, byte[] peerPublicKey);
    public (byte[] PublicKey, byte[] SecretKey) GenerateKeyPair();
}
