namespace CryptoUtility;

internal enum SymmetricCipherID
{
    None = 0,

    // Reserved: 100-1000 for built-in custom cipher implementations.
    XorCipher = 100,

    // Reserved: 1001-2000 for official .NET cipher implementations.
    SystemAesGcm128 = 1001,
    SystemAesGcm192 = 1002,
    SystemAesGcm256 = 1003,
    SystemChaCha20Poly1305 = 1050,

    // Reserved: 2001-3000 for BouncyCastle cipher implementations.
    BouncyCastleAesGcm128 = 2001,
    BouncyCastleAesGcm192 = 2002,
    BouncyCastleAesGcm256 = 2003,
    BouncyCastleChaCha20Poly1305 = 2050,
    BouncyCastleXChaCha20Poly1305 = 2051,

    // Reserved: 3001-4000 for NaCL cipher implementations.
    NaClSalsa20,
    NaClChaCha20,
    NaClXChaCha20,
    NaClChaCha20Poly1305,
    NaClXChaCha20Poly1305,
}
