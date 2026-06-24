using System.Text;
using CryptoUtility.BouncyCastle;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoUtility.Tests;

public class BouncyCastleMlDsa44Tests : DigitalSignatureTests
{
    internal override IDigitalSignature Signer { get; } = new MlDsaImpl(MLDsaParameters.ml_dsa_44);

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
    internal override IDigitalSignature Signer => MlDsaImpl.Shared;

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
    internal override IDigitalSignature Signer { get; } = new MlDsaImpl(MLDsaParameters.ml_dsa_87);

    public override void Verify_AlgorithmSpecification()
    {
        var (pub, sec) = GenerateKeyPair();
        var message = Encoding.UTF8.GetBytes("ml-dsa-87 test");
        var signature = Signer.Sign(message, sec);
        Assert.True(Signer.Verify(message, signature, pub));
    }
}
