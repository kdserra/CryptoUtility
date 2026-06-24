using System.Security.Cryptography;

namespace CryptoUtility.System;

/// <summary>
/// Base class for System AES-GCM implementations.
/// </summary>
public abstract class AesGcmBase : ISymmetricCipherAEAD
{
    /// <inheritdoc />
    public abstract int KeySizeBytes { get; }

    /// <inheritdoc />
    public abstract int NonceSizeBytes { get; }

    /// <inheritdoc />
    public abstract int AuthTagSizeBytes { get; }

    /// <inheritdoc />
    public byte[] Encrypt(byte[] key, byte[] plaintext, byte[] nonce) =>
        Encrypt(key, plaintext, nonce: nonce, aad: []);

    /// <inheritdoc />
    public byte[] Encrypt(byte[] key, byte[] plaintext, byte[] nonce, byte[] aad)
    {
        LibraryHelper.ThrowIfNull(key);
        LibraryHelper.ThrowIfNull(plaintext);
        LibraryHelper.ThrowIfNull(nonce);
        LibraryHelper.ThrowIfNull(aad);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[AuthTagSizeBytes];

#if NET8_0_OR_GREATER
        using var aes = new AesGcm(key, AuthTagSizeBytes);
#else
        using var aes = new AesGcm(key);
#endif
        aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        byte[] result = new byte[nonce.Length + ciphertext.Length + tag.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
        Buffer.BlockCopy(ciphertext, 0, result, nonce.Length, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, nonce.Length + ciphertext.Length, tag.Length);

        return result;
    }

    /// <inheritdoc />
    public byte[] Decrypt(byte[] key, byte[] encrypted) => Decrypt(key, encrypted, aad: []);

    /// <inheritdoc />
    public byte[] Decrypt(byte[] key, byte[] encrypted, byte[] aad)
    {
        LibraryHelper.ThrowIfNull(key);
        LibraryHelper.ThrowIfNull(encrypted);
        LibraryHelper.ThrowIfNull(aad);
        int nonceLen = NonceSizeBytes;
        int tagLen = AuthTagSizeBytes;

        if (encrypted.Length < nonceLen + tagLen)
        {
            throw new ArgumentException("Encrypted payload is too short.");
        }

        byte[] nonce = new byte[nonceLen];
        byte[] tag = new byte[tagLen];
        int ciphertextLen = encrypted.Length - nonceLen - tagLen;
        byte[] ciphertext = new byte[ciphertextLen];

        Buffer.BlockCopy(encrypted, 0, nonce, 0, nonceLen);
        Buffer.BlockCopy(encrypted, nonceLen, ciphertext, 0, ciphertextLen);
        Buffer.BlockCopy(encrypted, nonceLen + ciphertextLen, tag, 0, tagLen);

        byte[] plaintext = new byte[ciphertextLen];

#if NET8_0_OR_GREATER
        using var aes = new AesGcm(key, AuthTagSizeBytes);
#else
        using var aes = new AesGcm(key);
#endif
        aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);

        return plaintext;
    }
}
