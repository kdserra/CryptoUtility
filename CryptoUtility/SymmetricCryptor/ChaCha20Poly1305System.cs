#if NET8_0_OR_GREATER
using System.Security.Cryptography;

namespace CryptoUtility;

public sealed class ChaCha20Poly1305SymmetricCryptor : SymmetricCryptor
{
    private const int NonceSizeBytes = 12;
    private const int TagSizeBytes = 16;

    public override int KeySizeBytes => 32;

    public override byte[] Encrypt(byte[] key, byte[] value, IKeyNormalizer? keyNormalizer = null)
    {
        keyNormalizer ??= CryptoHelper.DefaultKeyNormalizer;
        var normalizedKey = keyNormalizer.Normalize(key, KeySizeBytes);

        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
        byte[] ciphertext = new byte[value.Length];
        byte[] tag = new byte[TagSizeBytes];

        using var cipher = new ChaCha20Poly1305(normalizedKey);
        cipher.Encrypt(nonce, value, ciphertext, tag);

        byte[] result = new byte[NonceSizeBytes + ciphertext.Length + TagSizeBytes];

        Buffer.BlockCopy(nonce, 0, result, 0, NonceSizeBytes);
        Buffer.BlockCopy(ciphertext, 0, result, NonceSizeBytes, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, NonceSizeBytes + ciphertext.Length, TagSizeBytes);

        return result;
    }

    public override byte[] Decrypt(
        byte[] key,
        byte[] encryptedValue,
        IKeyNormalizer? keyNormalizer = null
    )
    {
        keyNormalizer ??= CryptoHelper.DefaultKeyNormalizer;
        var normalizedKey = keyNormalizer.Normalize(key, KeySizeBytes);

        byte[] nonce = new byte[NonceSizeBytes];
        Buffer.BlockCopy(encryptedValue, 0, nonce, 0, NonceSizeBytes);

        int cipherLength = encryptedValue.Length - NonceSizeBytes - TagSizeBytes;

        byte[] ciphertext = new byte[cipherLength];
        byte[] tag = new byte[TagSizeBytes];

        Buffer.BlockCopy(encryptedValue, NonceSizeBytes, ciphertext, 0, cipherLength);
        Buffer.BlockCopy(encryptedValue, NonceSizeBytes + cipherLength, tag, 0, TagSizeBytes);

        byte[] plaintext = new byte[cipherLength];

        using var cipher = new ChaCha20Poly1305(normalizedKey);
        cipher.Decrypt(nonce, ciphertext, tag, plaintext);

        return plaintext;
    }
}
#endif
