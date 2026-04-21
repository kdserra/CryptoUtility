namespace CryptoUtility;

public enum SymmetricCipherID
{
    None = 0,

    // Reserved: 100-1000 for built-in custom cipher implementations.
    XorCipher = 100,

    // Reserved: 1001-2000 for official .NET cipher implementations.
    SystemAesGcm128 = 1001,
    SystemAesGcm192 = 1002,
    SystemAesGcm256 = 1003,
    SystemChaCha20Poly1305 = 1050,
}
