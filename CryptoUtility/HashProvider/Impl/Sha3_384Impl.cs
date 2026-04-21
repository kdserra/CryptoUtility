#if NET8_0_OR_GREATER
namespace CryptoUtility;

[GenerateStaticApi]
internal sealed class Sha3_384Impl : ShaBase
{
    internal static readonly Sha3_384Impl Shared = new();

    public Sha3_384Impl()
        : base(ShaVariant.Sha3_384) { }
}
#endif
