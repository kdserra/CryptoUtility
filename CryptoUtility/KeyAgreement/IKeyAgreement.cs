namespace CryptoUtility;

public interface IKeyAgreement
{
    public (bool success, byte[] sharedSecret) DeriveSharedSecret(
        byte[] secretKey,
        byte[] peerPublicKey
    );

    public (byte[] PublicKey, byte[] SecretKey) GenerateKeyPair();
}
