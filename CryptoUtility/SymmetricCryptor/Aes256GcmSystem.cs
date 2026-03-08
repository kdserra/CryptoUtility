#if NET8_0_OR_GREATER
using System.Security.Cryptography;

namespace CryptoUtility;

/// <summary>
/// Official .NET AES-256 GCM using buffering.
/// </summary>
/// <remarks>
/// <inheritdoc cref="SymmetricCryptor"/>
/// </remarks>
public sealed class Aes256GcmSystem : SymmetricCryptor
{
    /// <summary>
    /// Shared instance
    /// </summary>
    public static readonly Aes256GcmSystem Shared = new();

    public const int NonceSizeBytes = 12;
    public const int TagSizeBytes = 16;

    public override int KeySizeBytes => 32;

    public override byte[] Encrypt(byte[] key, byte[] value, IKeyNormalizer? keyNormalizer = null)
    {
        keyNormalizer ??= CryptoHelper.DefaultKeyNormalizer;

        if (value == null || value.Length == 0)
            return [];

        byte[] normalizedKey = keyNormalizer.Normalize(key, KeySizeBytes);

        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
        byte[] ciphertext = new byte[value.Length];
        byte[] tag = new byte[TagSizeBytes];

        using AesGcm aes = new AesGcm(normalizedKey, TagSizeBytes);
        aes.Encrypt(nonce, value, ciphertext, tag);

        byte[] result = new byte[NonceSizeBytes + TagSizeBytes + ciphertext.Length];

        Buffer.BlockCopy(nonce, 0, result, 0, NonceSizeBytes);
        Buffer.BlockCopy(tag, 0, result, NonceSizeBytes, TagSizeBytes);
        Buffer.BlockCopy(ciphertext, 0, result, NonceSizeBytes + TagSizeBytes, ciphertext.Length);

        return result;
    }

    public override byte[] Decrypt(
        byte[] key,
        byte[] encryptedValue,
        IKeyNormalizer? keyNormalizer = null
    )
    {
        keyNormalizer ??= CryptoHelper.DefaultKeyNormalizer;

        if (encryptedValue == null || encryptedValue.Length < NonceSizeBytes + TagSizeBytes)
            throw new ArgumentException("Invalid encrypted data.");

        byte[] normalizedKey = keyNormalizer.Normalize(key, KeySizeBytes);

        byte[] nonce = new byte[NonceSizeBytes];
        byte[] tag = new byte[TagSizeBytes];
        int cipherLength = encryptedValue.Length - NonceSizeBytes - TagSizeBytes;

        byte[] ciphertext = new byte[cipherLength];
        byte[] plaintext = new byte[cipherLength];

        Buffer.BlockCopy(encryptedValue, 0, nonce, 0, NonceSizeBytes);
        Buffer.BlockCopy(encryptedValue, NonceSizeBytes, tag, 0, TagSizeBytes);
        Buffer.BlockCopy(
            encryptedValue,
            NonceSizeBytes + TagSizeBytes,
            ciphertext,
            0,
            cipherLength
        );

        using AesGcm aes = new AesGcm(normalizedKey, TagSizeBytes);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);

        return plaintext;
    }
}
#endif
