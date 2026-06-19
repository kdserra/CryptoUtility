using BouncyEcdhImpl = CryptoUtility.BouncyCastle.EcdhImpl;

namespace CryptoUtility.Tests;

public sealed class BouncyEcdhTests : KeyAgreementTests
{
    internal override IKeyAgreement KeyAgreement => new BouncyEcdhImpl();

    internal override IKeyAgreement CreateNew()
    {
        return new EcdhImpl();
    }
}
