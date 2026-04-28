namespace CryptoUtility.Tests;

public class EcdsaTests : DigitalSignatureTests
{
    internal override IDigitalSignature Cipher { get; } = EcdsaImpl.Shared;
}
