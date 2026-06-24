using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleRsa3072Tests : AsymmetricCipherTests
{
    public override IAsymmetricCipher Cipher => Rsa3072Impl.Shared;

    public override void Verify_AlgorithmSpecification()
    {
        Assert.Equal(3072 / 8, Cipher.KeySizeBytes);
    }
}
