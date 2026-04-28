namespace CryptoUtility;

public interface IKdf
{
    public byte[] DeriveKey(byte[] inputKeyMaterial, byte[] salt, int iterations, int outputLength);
}
