using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyRsa1024Tests : AsymmetricCipherTests
{
    public override IAsymmetricCipher Cipher => Rsa1024Impl.Shared;

    public override void Verify_AlgorithmSpecification()
    {
        Assert.Equal(1024 / 8, Cipher.KeySizeBytes);
    }
}
