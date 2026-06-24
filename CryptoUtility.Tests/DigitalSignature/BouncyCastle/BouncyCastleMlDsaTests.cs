using System.Text;
using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public class BouncyCastleMlDsa44Tests : DigitalSignatureTests
{
    internal override IDigitalSignature Signer => MlDsa44Impl.Shared;

    public override void Verify_AlgorithmSpecification()
    {
        var (pub, sec) = GenerateKeyPair();
        var message = Encoding.UTF8.GetBytes("ml-dsa-44 test");
        var signature = Signer.Sign(message, sec);
        Assert.True(Signer.Verify(message, signature, pub));
    }
}

public class BouncyCastleMlDsa65Tests : DigitalSignatureTests
{
    internal override IDigitalSignature Signer => MlDsa65Impl.Shared;

    public override void Verify_AlgorithmSpecification()
    {
        var (pub, sec) = GenerateKeyPair();
        var message = Encoding.UTF8.GetBytes("ml-dsa-65 test");
        var signature = Signer.Sign(message, sec);
        Assert.True(Signer.Verify(message, signature, pub));
    }
}

public class BouncyCastleMlDsa87Tests : DigitalSignatureTests
{
    internal override IDigitalSignature Signer => MlDsa87Impl.Shared;

    public override void Verify_AlgorithmSpecification()
    {
        var (pub, sec) = GenerateKeyPair();
        var message = Encoding.UTF8.GetBytes("ml-dsa-87 test");
        var signature = Signer.Sign(message, sec);
        Assert.True(Signer.Verify(message, signature, pub));
    }
}
