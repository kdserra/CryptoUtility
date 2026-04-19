namespace CryptoUtility;

internal abstract class KeyAgreement
{
    public abstract (bool success, byte[] sharedSecret) DeriveSharedSecret(
        byte[] privateKey,
        byte[] peerPublicKey
    );

    public (bool success, string sharedSecret) DeriveSharedSecret(
        string privateKey,
        string peerPublicKey
    )
    {
        byte[] privateKeyBytes = Convert.FromBase64String(privateKey);
        byte[] peerPublicKeyBytes = Convert.FromBase64String(peerPublicKey);

        (bool success, byte[] sharedSecret) derivationResult = DeriveSharedSecret(
            privateKeyBytes,
            peerPublicKeyBytes
        );

        if (!derivationResult.success)
        {
            return (false, string.Empty);
        }

        string derivedSharedSecret = Convert.ToBase64String(derivationResult.sharedSecret);

        return (true, derivedSharedSecret);
    }
}
