namespace CryptoUtility.Tests;

public sealed class EcdhTests : KeyAgreementTests
{
    internal override IKeyAgreement KeyAgreement => new EcdhImpl();

    internal override IKeyAgreement CreateNew()
    {
        return new EcdhImpl();
    }
}
