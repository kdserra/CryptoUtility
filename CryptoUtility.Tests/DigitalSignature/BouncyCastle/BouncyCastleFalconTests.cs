using System.Text;
using CryptoUtility.BouncyCastle;
using Org.BouncyCastle.Pqc.Crypto.Falcon;

namespace CryptoUtility.Tests;

public class BouncyCastleFalcon512Tests : DigitalSignatureTests
{
    internal override IDigitalSignature Signer => FalconImpl.Shared;

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
    internal override IDigitalSignature Signer { get; } = new FalconImpl(FalconParameters.falcon_1024);

    public override void Verify_AlgorithmSpecification()
    {
        var (pub, sec) = GenerateKeyPair();
        var message = Encoding.UTF8.GetBytes("falcon-1024 test");
        var signature = Signer.Sign(message, sec);
        Assert.True(Signer.Verify(message, signature, pub));
    }
}
