using CryptoUtility.NaCl;

namespace CryptoUtility.Tests;

public sealed class NaClXChaCha20Tests : SymmetricCipherTests
{
    internal override ISymmetricCipher Cipher => XChaCha20Impl.Shared;
}
