#if NET8_0_OR_GREATER
using CryptoUtility;

namespace CryptoUtility.Tests;

public sealed class HkdfTests : KeyExpansionKdfTests
{
    internal override IKeyExpansionKdf Kdf => HkdfImpl.Shared;
}
#endif
