#if NET8_0_OR_GREATER
using System.Security.Cryptography;

namespace CryptoUtility;

public sealed class Aes256GcmCryptoProvider : ISymmetricCryptor
{
    public static Aes256GcmCryptoProvider Shared { get; } = new();

    private const int NonceSize = 12;
    private const int TagSize = 16;

    public int KeySize { get; } = 32;

    public byte[] Encrypt(byte[] key, byte[] value, IKeyNormalizer? keyNormalizer)
    {
        keyNormalizer ??= this.GetDefaultKeyNormalizer();

        if (value == null || value.Length == 0)
            return Array.Empty<byte>();

        byte[] normalizedKey = keyNormalizer.Normalize(key, KeySize);

        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] ciphertext = new byte[value.Length];
        byte[] tag = new byte[TagSize];

        using var aes = new AesGcm(normalizedKey, TagSize);
        aes.Encrypt(nonce, value, ciphertext, tag);

        byte[] result = new byte[NonceSize + TagSize + ciphertext.Length];

        Buffer.BlockCopy(nonce, 0, result, 0, NonceSize);
        Buffer.BlockCopy(tag, 0, result, NonceSize, TagSize);
        Buffer.BlockCopy(ciphertext, 0, result, NonceSize + TagSize, ciphertext.Length);

        return result;
    }

    public byte[] Decrypt(byte[] key, byte[] encryptedValue, IKeyNormalizer? keyNormalizer)
    {
        keyNormalizer ??= this.GetDefaultKeyNormalizer();

        if (encryptedValue == null || encryptedValue.Length < NonceSize + TagSize)
            throw new ArgumentException("Invalid encrypted data.");

        byte[] normalizedKey = keyNormalizer.Normalize(key, KeySize);

        byte[] nonce = new byte[NonceSize];
        byte[] tag = new byte[TagSize];
        int cipherLength = encryptedValue.Length - NonceSize - TagSize;

        byte[] ciphertext = new byte[cipherLength];
        byte[] plaintext = new byte[cipherLength];

        Buffer.BlockCopy(encryptedValue, 0, nonce, 0, NonceSize);
        Buffer.BlockCopy(encryptedValue, NonceSize, tag, 0, TagSize);
        Buffer.BlockCopy(encryptedValue, NonceSize + TagSize, ciphertext, 0, cipherLength);

        using var aes = new AesGcm(normalizedKey, TagSize);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);

        return plaintext;
    }
}
#endif
