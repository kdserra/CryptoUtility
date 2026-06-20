using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public class BouncyEcdsaTests : DigitalSignatureTests
{
    internal override IDigitalSignature Signer { get; } = EcdsaImpl.Shared;
}
