using System.Text;
using CryptoUtility.BouncyCastle;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoUtility.Tests;

public class BouncyCastleSlhDsa128sTests : DigitalSignatureTests
{
    internal override IDigitalSignature Signer => SlhDsaImpl.Shared;

    public override void Verify_AlgorithmSpecification()
    {
        var (pub, sec) = GenerateKeyPair();
        var message = Encoding.UTF8.GetBytes("slh-dsa-128s test");
        var signature = Signer.Sign(message, sec);
        Assert.True(Signer.Verify(message, signature, pub));
    }
}

public class BouncyCastleSlhDsa128fTests : DigitalSignatureTests
{
    internal override IDigitalSignature Signer { get; } = new SlhDsaImpl(SlhDsaParameters.slh_dsa_sha2_128f);

    public override void Verify_AlgorithmSpecification()
    {
        var (pub, sec) = GenerateKeyPair();
        var message = Encoding.UTF8.GetBytes("slh-dsa-128f test");
        var signature = Signer.Sign(message, sec);
        Assert.True(Signer.Verify(message, signature, pub));
    }
}
