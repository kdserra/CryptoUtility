#if NET8_0_OR_GREATER
namespace CryptoUtility;

public sealed class Sha3_256 : ShaHashProvider
{
    public static readonly Sha3_256 Shared = new();

    public Sha3_256()
        : base(ShaVariant.Sha3_256) { }
}
#endif
