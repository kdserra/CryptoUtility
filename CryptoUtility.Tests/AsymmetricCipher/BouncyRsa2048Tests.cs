using BouncyRsa2048Impl = CryptoUtility.BouncyCastle.Rsa2048Impl;

namespace CryptoUtility.Tests;

public sealed class BouncyRsa2048Tests : AsymmetricCipherTests
{
    public override IAsymmetricCipher Cipher => new BouncyRsa2048Impl();
}
