using System.Text;
using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public class BouncyCastleFalcon512Tests : DigitalSignatureTests
{
    internal override IDigitalSignature Signer => Falcon512Impl.Shared;

    public override void Verify_AlgorithmSpecification()
    {
        var (pub, sec) = GenerateKeyPair();
        var message = Encoding.UTF8.GetBytes("falcon-512 test");
        var signature = Signer.Sign(message, sec);
        Assert.True(Signer.Verify(message, signature, pub));
    }
}

public class BouncyCastleFalcon1024Tests : DigitalSignatureTests
{
    internal override IDigitalSignature Signer => Falcon1024Impl.Shared;

    public override void Verify_AlgorithmSpecification()
    {
        var (pub, sec) = GenerateKeyPair();
        var message = Encoding.UTF8.GetBytes("falcon-1024 test");
        var signature = Signer.Sign(message, sec);
        Assert.True(Signer.Verify(message, signature, pub));
    }
}
