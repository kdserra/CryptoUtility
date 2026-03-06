namespace CryptoUtility;

public sealed class Crc64HashProvider : CrcHashProvider
{
    public Crc64HashProvider()
        : base(CrcVariant.Crc64) { }
}
