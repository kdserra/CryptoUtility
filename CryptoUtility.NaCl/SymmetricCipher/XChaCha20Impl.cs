using System.Security.Cryptography;

namespace CryptoUtility.NaCl;

/// <summary>
/// NaCl XChaCha20 Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class XChaCha20Impl : ISymmetricCipher
{
    /// <summary>
    /// Shared static instance of <see cref="XChaCha20Impl"/>.
    /// </summary>
    public static readonly XChaCha20Impl Shared = new();

    private XChaCha20Impl() { }

    /// <inheritdoc />
    public int KeySizeBytes => 32;

    /// <inheritdoc />
    public int NonceSizeBytes => 24;

    /// <inheritdoc />
    public byte[] Encrypt(byte[] key, byte[] plaintext, byte[] nonce)
    {
        LibraryHelper.ThrowIfNull(key);
        LibraryHelper.ThrowIfNull(plaintext);
        LibraryHelper.ThrowIfNull(nonce);
        byte[] ciphertext = new byte[plaintext.Length];
        using var xchacha = new global::NaCl.Core.XChaCha20(key, initialCounter: 0);
        xchacha.Encrypt(plaintext, nonce, ciphertext);

        byte[] result = new byte[nonce.Length + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
        Buffer.BlockCopy(ciphertext, 0, result, nonce.Length, ciphertext.Length);

        return result;
    }

    /// <inheritdoc />
    public byte[] Decrypt(byte[] key, byte[] encrypted)
    {
        LibraryHelper.ThrowIfNull(key);
        LibraryHelper.ThrowIfNull(encrypted);
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
        using var xchacha = new global::NaCl.Core.XChaCha20(key, initialCounter: 0);
        xchacha.Decrypt(ciphertext, nonce, plaintext);

        return plaintext;
    }
}
