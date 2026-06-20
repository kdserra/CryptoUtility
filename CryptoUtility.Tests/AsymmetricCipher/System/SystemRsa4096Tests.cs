using CryptoUtility.System;

namespace CryptoUtility.Tests;

public sealed class SystemRsa4096Tests : AsymmetricCipherTests
{
    public override IAsymmetricCipher Cipher => Rsa4096Impl.Shared;
}
