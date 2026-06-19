using BouncyEcdsaImpl = CryptoUtility.BouncyCastle.EcdsaImpl;

namespace CryptoUtility.Tests;

public class BouncyEcdsaTests : DigitalSignatureTests
{
    internal override IDigitalSignature Signer { get; } = BouncyEcdsaImpl.Shared;
}
