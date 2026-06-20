namespace CryptoUtility;

public interface IMacProvider
{
    public int RequiredKeySizeInBytes { get; }

    public int MacSizeInBytes { get; }

    public byte[] ComputeMac(byte[] key, byte[] message);
}
