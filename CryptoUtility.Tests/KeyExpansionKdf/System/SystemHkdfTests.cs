using CryptoUtility.System;

namespace CryptoUtility.Tests;

public sealed class SystemHkdfTests : KeyExpansionKdfTests
{
    internal override IKeyExpansionKdf Kdf => HkdfImpl.Shared;
}
