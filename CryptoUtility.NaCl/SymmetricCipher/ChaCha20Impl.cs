using System.Security.Cryptography;

namespace CryptoUtility.NaCl;

/// <summary>
/// NaCl ChaCha20 Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class ChaCha20Impl : ISymmetricCipher
{
    /// <summary>
    /// Shared static instance of <see cref="ChaCha20Impl"/>.
    /// </summary>
    public static readonly ChaCha20Impl Shared = new();

    private ChaCha20Impl() { }

    /// <inheritdoc />
    public int KeySizeBytes => 32;

    /// <inheritdoc />
    public int NonceSizeBytes => 12;

    /// <inheritdoc />
    public byte[] Encrypt(byte[] key, byte[] plaintext, byte[] nonce)
    {
        LibraryHelper.ThrowIfAnyNull(key, plaintext, nonce);
        byte[] ciphertext = new byte[plaintext.Length];
        using var chacha = new global::NaCl.Core.ChaCha20(key, initialCounter: 0);
        chacha.Encrypt(plaintext, nonce, ciphertext);

        byte[] result = new byte[nonce.Length + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
        Buffer.BlockCopy(ciphertext, 0, result, nonce.Length, ciphertext.Length);

        return result;
    }

    /// <inheritdoc />
    public byte[] Decrypt(byte[] key, byte[] encrypted)
    {
        LibraryHelper.ThrowIfAnyNull(key, encrypted);
        int nonceLen = NonceSizeBytes;
        if (encrypted.Length < nonceLen)
        {
            throw new ArgumentException("Encrypted payload is too short.");
        }

        byte[] nonce = new byte[nonceLen];
        int ciphertextLen = encrypted.Length - nonceLen;
        byte[] ciphertext = new byte[ciphertextLen];

        Buffer.BlockCopy(encrypted, 0, nonce, 0, nonceLen);
        Buffer.BlockCopy(encrypted, nonceLen, ciphertext, 0, ciphertextLen);

        byte[] plaintext = new byte[ciphertextLen];
        using var chacha = new global::NaCl.Core.ChaCha20(key, initialCounter: 0);
        chacha.Decrypt(ciphertext, nonce, plaintext);

        return plaintext;
    }
}
