namespace CryptoUtility;

public enum SymmetricCipherID
{
    None = 0,

    // 1000-1999 : System Ciphers
    Aes128GcmSystem = 1000,
    Aes192GcmSystem = 1001,
    Aes256GcmSystem = 1002,
    ChaCha20Poly1305System = 1050,

    // 2000-2999 : Standard Built-In Ciphers
    XorCipherStandard = 2000,

    // 3000+ : Third Party Ciphers
}
