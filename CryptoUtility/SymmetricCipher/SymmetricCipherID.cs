namespace CryptoUtility;

public enum SymmetricCipherID
{
    None = 0,

    Aes128GcmSystem = 1000,
    Aes192GcmSystem = 1001,
    Aes256GcmSystem = 1002,
#if NET8_0_OR_GREATER
    ChaCha20Poly1305System = 1050,
#endif

    XorCipherStandard = 2000,

}
