using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyHkdfTests : KeyExpansionKdfTests
{
    internal override IKeyExpansionKdf Kdf => HkdfImpl.Shared;
}
