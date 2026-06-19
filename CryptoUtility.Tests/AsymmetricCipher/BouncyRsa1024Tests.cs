using BouncyRsa1024Impl = CryptoUtility.BouncyCastle.Rsa1024Impl;

namespace CryptoUtility.Tests;

public sealed class BouncyRsa1024Tests : AsymmetricCipherTests
{
    public override IAsymmetricCipher Cipher => new BouncyRsa1024Impl();
}
