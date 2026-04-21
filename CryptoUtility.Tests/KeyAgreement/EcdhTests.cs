namespace CryptoUtility.Tests;

public sealed class EcdhTests : KeyAgreementTests
{
    internal override KeyAgreement KeyAgreement => new EcdhImpl();

    internal override KeyAgreement CreateNew()
    {
        return new EcdhImpl();
    }
}
