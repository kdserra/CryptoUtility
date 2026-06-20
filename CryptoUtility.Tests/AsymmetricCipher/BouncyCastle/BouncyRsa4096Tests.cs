using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyRsa4096Tests : AsymmetricCipherTests
{
    public override IAsymmetricCipher Cipher => Rsa4096Impl.Shared;
}
