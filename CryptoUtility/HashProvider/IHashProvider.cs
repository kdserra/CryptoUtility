namespace CryptoUtility;

public interface IHashProvider
{
    public byte[] Hash(byte[] message);
}
