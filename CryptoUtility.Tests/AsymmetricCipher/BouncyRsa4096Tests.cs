using BouncyRsa4096Impl = CryptoUtility.BouncyCastle.Rsa4096Impl;

namespace CryptoUtility.Tests;

public sealed class BouncyRsa4096Tests : AsymmetricCipherTests
{
    public override IAsymmetricCipher Cipher => new BouncyRsa4096Impl();
}
