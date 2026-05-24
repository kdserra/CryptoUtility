namespace CryptoUtility.Tests;

public sealed class HkdfDotNetTests : KeyExpansionKdfTests
{
    internal override IKeyExpansionKdf Kdf => HkdfDotNetImpl.Shared;
}
