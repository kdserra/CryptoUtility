using CryptoUtility.System;

namespace CryptoUtility.Tests;

public sealed class SystemRsa2048Tests : AsymmetricCipherTests
{
    public override IAsymmetricCipher Cipher => Rsa2048Impl.Shared;
}
