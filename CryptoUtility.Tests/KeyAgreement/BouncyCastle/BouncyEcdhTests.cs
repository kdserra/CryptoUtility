using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyEcdhTests : KeyAgreementTests
{
    internal override IKeyAgreement KeyAgreement => EcdhImpl.Shared;

    internal override IKeyAgreement CreateNew()
    {
        return new EcdhImpl();
    }
}
