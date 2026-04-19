namespace CryptoUtility.Extras;

public sealed class Crc64 : Crc
{
    public static readonly Crc64 Shared = new();

    public Crc64()
        : base(CrcVariant.Crc64) { }
}
