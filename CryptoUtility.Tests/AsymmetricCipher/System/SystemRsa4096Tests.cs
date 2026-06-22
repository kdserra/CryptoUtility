using CryptoUtility.System;

namespace CryptoUtility.Tests;

public sealed class SystemRsa4096Tests : AsymmetricCipherTests
{
    public override IAsymmetricCipher Cipher => Rsa4096Impl.Shared;

    public override void Verify_AlgorithmSpecification()
    {
        Assert.Equal(4096 / 8, Cipher.KeySizeBytes);
    }
}
