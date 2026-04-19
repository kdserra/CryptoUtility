namespace CryptoUtility.Extras;

public sealed class Crc32 : Crc
{
    public static readonly Crc32 Shared = new();

    public Crc32()
        : base(CrcVariant.Crc32) { }
}
