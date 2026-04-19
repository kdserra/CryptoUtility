namespace CryptoUtility.Extras;

public sealed class Crc64 : CrcBase
{
    public static readonly Crc64 Shared = new();

    public Crc64()
        : base(CrcVariant.Crc64) { }
}
