namespace CryptoUtility.Tests;

public class EcdsaTests : DigitalSignatureTests
{
    internal override IDigitalSignature Signer { get; } = EcdsaImpl.Shared;
}
