using System.Text;
using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public class BouncyCastleSlhDsa128sTests : DigitalSignatureTests
{
    internal override IDigitalSignature Signer => SlhDsa128sImpl.Shared;

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
    internal override IDigitalSignature Signer => SlhDsa128fImpl.Shared;

    public override void Verify_AlgorithmSpecification()
    {
        var (pub, sec) = GenerateKeyPair();
        var message = Encoding.UTF8.GetBytes("slh-dsa-128f test");
        var signature = Signer.Sign(message, sec);
        Assert.True(Signer.Verify(message, signature, pub));
    }
}

public class BouncyCastleSlhDsa192sTests : DigitalSignatureTests
{
    internal override IDigitalSignature Signer => SlhDsa192sImpl.Shared;

    public override void Verify_AlgorithmSpecification()
    {
        var (pub, sec) = GenerateKeyPair();
        var message = Encoding.UTF8.GetBytes("slh-dsa-192s test");
        var signature = Signer.Sign(message, sec);
        Assert.True(Signer.Verify(message, signature, pub));
    }
}

public class BouncyCastleSlhDsa192fTests : DigitalSignatureTests
{
    internal override IDigitalSignature Signer => SlhDsa192fImpl.Shared;

    public override void Verify_AlgorithmSpecification()
    {
        var (pub, sec) = GenerateKeyPair();
        var message = Encoding.UTF8.GetBytes("slh-dsa-192f test");
        var signature = Signer.Sign(message, sec);
        Assert.True(Signer.Verify(message, signature, pub));
    }
}

public class BouncyCastleSlhDsa256sTests : DigitalSignatureTests
{
    internal override IDigitalSignature Signer => SlhDsa256sImpl.Shared;

    public override void Verify_AlgorithmSpecification()
    {
        var (pub, sec) = GenerateKeyPair();
        var message = Encoding.UTF8.GetBytes("slh-dsa-256s test");
        var signature = Signer.Sign(message, sec);
        Assert.True(Signer.Verify(message, signature, pub));
    }
}

public class BouncyCastleSlhDsa256fTests : DigitalSignatureTests
{
    internal override IDigitalSignature Signer => SlhDsa256fImpl.Shared;

    public override void Verify_AlgorithmSpecification()
    {
        var (pub, sec) = GenerateKeyPair();
        var message = Encoding.UTF8.GetBytes("slh-dsa-256f test");
        var signature = Signer.Sign(message, sec);
        Assert.True(Signer.Verify(message, signature, pub));
    }
}
