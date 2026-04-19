namespace CryptoUtility;

public enum CipherID
{
    None = 0,

    // AES Family
    AES_128_GCM = 1,
    AES_256_GCM = 2,
    AES_512_GCM = 3,
    AES_128_CBC = 4,
    AES_256_CBC = 5,
    AES_512_CBC = 6,
    AES_128_ECB = 7,
    AES_256_ECB = 8,
    AES_512_ECB = 9,
    AES_128_CTR = 10,
    AES_256_CTR = 11,
    AES_512_CTR = 12,

    // ChaCha Family
    Salsa20 = 13,
    ChaCha20 = 14,
    ChaCha20Poly1305 = 15,
    XChaCha20 = 16,
    XChaCha20Poly1305 = 17,

    // Stateless Ciphers
    Xor = 100,
}
