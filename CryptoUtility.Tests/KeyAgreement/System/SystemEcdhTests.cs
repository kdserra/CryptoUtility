using CryptoUtility.System;

namespace CryptoUtility.Tests;

public sealed class SystemEcdhTests : KeyAgreementTests
{
    internal override IKeyAgreement KeyAgreement => EcdhImpl.Shared;

    internal override IKeyAgreement CreateNew()
    {
        return new EcdhImpl();
    }
}
