using CryptoUtility.System;

namespace CryptoUtility.Tests;

public class SystemEcdsaTests : DigitalSignatureTests
{
    internal override IDigitalSignature Signer { get; } = EcdsaImpl.Shared;
}
