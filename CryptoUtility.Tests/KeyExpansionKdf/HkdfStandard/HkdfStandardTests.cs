using CryptoUtility.HkdfStandard;

namespace CryptoUtility.Tests;

public sealed class HkdfStandardTests : KeyExpansionKdfTests
{
    internal override IKeyExpansionKdf Kdf => HkdfImpl.Shared;
}
