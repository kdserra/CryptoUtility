using CryptoUtility.System;

namespace CryptoUtility.Tests;

public sealed class Aes256GcmTests : SymmetricCipherAEADTests
{
    internal override ISymmetricCipher Cipher => Aes256GcmImpl.Shared;
}
