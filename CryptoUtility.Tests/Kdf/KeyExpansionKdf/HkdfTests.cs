namespace CryptoUtility.Tests;

public sealed class HkdfTests : KeyExpansionKdfTests
{
    internal override IKeyExpansionKdf Kdf => HkdfImpl.Shared;
}
