using System.Security.Cryptography;

namespace CryptoUtility.NaCl;

/// <summary>
/// NaCl ChaCha20-Poly1305 Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class ChaCha20Poly1305Impl : ISymmetricCipherAEAD
{
    /// <summary>
    /// Shared static instance of <see cref="ChaCha20Poly1305Impl"/>.
    /// </summary>
    public static readonly ChaCha20Poly1305Impl Shared = new();

    private ChaCha20Poly1305Impl() { }

    /// <inheritdoc />
    public int KeySizeBytes => 32;

    /// <inheritdoc />
    public int NonceSizeBytes => 12;

    /// <inheritdoc />
    public int AuthTagSizeBytes => 16;

    /// <inheritdoc />
    public byte[] Encrypt(byte[] key, byte[] plaintext, byte[] nonce) =>
        Encrypt(key, plaintext, nonce, aad: []);

    /// <inheritdoc />
    public byte[] Encrypt(
        byte[] key,
        byte[] plaintext,
        byte[] nonce,
        byte[] aad
    )
    {
        LibraryHelper.ThrowIfAnyNull(key, plaintext, nonce, aad);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[AuthTagSizeBytes];

        using var aead = new global::NaCl.Core.ChaCha20Poly1305(key);
        aead.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        byte[] result = new byte[nonce.Length + ciphertext.Length + tag.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
        Buffer.BlockCopy(ciphertext, 0, result, nonce.Length, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, nonce.Length + ciphertext.Length, tag.Length);

        return result;
    }

    /// <inheritdoc />
    public byte[] Decrypt(byte[] key, byte[] encrypted) =>
        Decrypt(key, encrypted, aad: []);

    /// <inheritdoc />
    public byte[] Decrypt(byte[] key, byte[] encrypted, byte[] aad)
    {
        LibraryHelper.ThrowIfAnyNull(key, encrypted, aad);
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
        using var aead = new global::NaCl.Core.ChaCha20Poly1305(key);
        aead.Decrypt(nonce, ciphertext, tag, plaintext, aad);

        return plaintext;
    }
}
