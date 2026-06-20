using CryptoUtility.System;

namespace CryptoUtility.Tests;

public sealed class Aes128GcmTests : SymmetricCipherAEADTests
{
    internal override ISymmetricCipher Cipher => Aes128GcmImpl.Shared;
}
