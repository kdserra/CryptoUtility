namespace CryptoUtility;

internal abstract class DigitalSignature
{
    public abstract (bool success, byte[] signature) Sign(byte[] message, byte[] secretKey);

    public abstract bool Verify(byte[] message, byte[] signature, byte[] publicKey);
}
