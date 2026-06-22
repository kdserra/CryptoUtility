using System.Text;
using CryptoUtility.System;

namespace CryptoUtility.Tests;

public class SystemEcdsaTests : DigitalSignatureTests
{
    internal override IDigitalSignature Signer { get; } = EcdsaImpl.Shared;

    public override void Verify_AlgorithmSpecification()
    {
        var (pub, sec) = GenerateKeyPair();
        var message = Encoding.UTF8.GetBytes("test");
        var signature = Signer.Sign(message, sec);
        Assert.True(Signer.Verify(message, signature, pub));
    }
}
