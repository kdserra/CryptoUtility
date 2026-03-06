namespace CryptoUtility;

public interface IHashProvider
{
    public byte[] Hash(byte[] input);

    public byte[] Sign(byte[] input, byte[] key);
    public bool VerifySignature(byte[] input, byte[] signature, byte[] key);
}
