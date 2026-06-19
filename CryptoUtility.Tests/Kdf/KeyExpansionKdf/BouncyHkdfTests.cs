using BouncyHkdfImpl = CryptoUtility.BouncyCastle.HkdfImpl;

namespace CryptoUtility.Tests;

public sealed class BouncyHkdfTests : KeyExpansionKdfTests
{
    internal override IKeyExpansionKdf Kdf => BouncyHkdfImpl.Shared;
}
