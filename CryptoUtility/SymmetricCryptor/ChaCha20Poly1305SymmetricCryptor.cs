#if NET8_0_OR_GREATER
using System.Security.Cryptography;

namespace CryptoUtility;

public sealed class ChaCha20Poly1305SymmetricCryptor : ISymmetricCryptor
{
    private const int NonceSize = 12;
    private const int TagSize = 16;

    public int KeySize => 32;

    public byte[] Encrypt(byte[] key, byte[] value, IKeyNormalizer? keyNormalizer = null)
    {
        keyNormalizer ??= this.GetDefaultKeyNormalizer();
        var normalizedKey = keyNormalizer.Normalize(key, KeySize);

        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] ciphertext = new byte[value.Length];
        byte[] tag = new byte[TagSize];

        using var cipher = new ChaCha20Poly1305(normalizedKey);
        cipher.Encrypt(nonce, value, ciphertext, tag);

        byte[] result = new byte[NonceSize + ciphertext.Length + TagSize];

        Buffer.BlockCopy(nonce, 0, result, 0, NonceSize);
        Buffer.BlockCopy(ciphertext, 0, result, NonceSize, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, NonceSize + ciphertext.Length, TagSize);

        return result;
    }

    public byte[] Decrypt(byte[] key, byte[] encryptedValue, IKeyNormalizer? keyNormalizer = null)
    {
        keyNormalizer ??= this.GetDefaultKeyNormalizer();
        var normalizedKey = keyNormalizer.Normalize(key, KeySize);

        byte[] nonce = new byte[NonceSize];
        Buffer.BlockCopy(encryptedValue, 0, nonce, 0, NonceSize);

        int cipherLength = encryptedValue.Length - NonceSize - TagSize;

        byte[] ciphertext = new byte[cipherLength];
        byte[] tag = new byte[TagSize];

        Buffer.BlockCopy(encryptedValue, NonceSize, ciphertext, 0, cipherLength);
        Buffer.BlockCopy(encryptedValue, NonceSize + cipherLength, tag, 0, TagSize);

        byte[] plaintext = new byte[cipherLength];

        using var cipher = new ChaCha20Poly1305(normalizedKey);
        cipher.Decrypt(nonce, ciphertext, tag, plaintext);

        return plaintext;
    }
}
#endif
