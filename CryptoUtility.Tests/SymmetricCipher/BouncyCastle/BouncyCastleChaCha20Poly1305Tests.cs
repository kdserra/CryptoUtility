using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleChaCha20Poly1305Tests : SymmetricCipherAEADTests
{
    internal override ISymmetricCipher Cipher => ChaCha20Poly1305Impl.Shared;
}
