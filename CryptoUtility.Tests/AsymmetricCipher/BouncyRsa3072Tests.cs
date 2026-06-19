using BouncyRsa3072Impl = CryptoUtility.BouncyCastle.Rsa3072Impl;

namespace CryptoUtility.Tests;

public sealed class BouncyRsa3072Tests : AsymmetricCipherTests
{
    public override IAsymmetricCipher Cipher => new BouncyRsa3072Impl();
}
