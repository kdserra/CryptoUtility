namespace CryptoUtility;

public interface IKeyAgreement
{
    public byte[] DeriveSharedSecret(byte[] secretKey, byte[] peerPublicKey);
    public (byte[] publicKey, byte[] secretKey) GenerateKeyPair();
}
