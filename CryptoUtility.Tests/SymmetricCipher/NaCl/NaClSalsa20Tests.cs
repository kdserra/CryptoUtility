using CryptoUtility.NaCl;

namespace CryptoUtility.Tests;

public sealed class NaClSalsa20Tests : SymmetricCipherTests
{
    internal override ISymmetricCipher Cipher => Salsa20Impl.Shared;
}
