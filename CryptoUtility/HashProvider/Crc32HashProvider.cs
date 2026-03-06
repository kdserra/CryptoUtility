namespace CryptoUtility;

public sealed class Crc32HashProvider : CrcHashProvider
{
    public Crc32HashProvider()
        : base(CrcVariant.Crc32) { }
}
