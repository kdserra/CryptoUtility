using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleEcdhTests : KeyAgreementTests
{
    internal override IKeyAgreement KeyAgreement => EcdhImpl.Shared;

    internal override IKeyAgreement CreateNew()
    {
        return new EcdhImpl();
    }

    public override void Verify_AlgorithmSpecification()
    {
        var a = KeyAgreement;
        var b = CreateNew();
        var (aPub, aSec) = a.GenerateKeyPair();
        var (bPub, bSec) = b.GenerateKeyPair();
        var secretA = a.DeriveSharedSecret(aSec, bPub);
        var secretB = b.DeriveSharedSecret(bSec, aPub);
        Assert.Equal(32, secretA.Length);
        Assert.Equal(secretA, secretB);
    }
}
