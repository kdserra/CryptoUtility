using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyRsa2048Tests : AsymmetricCipherTests
{
    public override IAsymmetricCipher Cipher => Rsa2048Impl.Shared;
}
