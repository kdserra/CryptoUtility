using System.Security.Cryptography;

namespace CryptoUtility.NaCl;

[GenerateStaticApi]
public sealed class XChaCha20Impl : ISymmetricCipher
{
    public static readonly XChaCha20Impl Shared = new();

    /// <inheritdoc cref="ISymmetricCipher.KeySizeBytes" />
    public int KeySizeBytes => 32;

    /// <inheritdoc cref="ISymmetricCipher.NonceSizeBytes" />
    public int NonceSizeBytes => 24;

    /// <inheritdoc cref="ISymmetricCipher.Encrypt(byte[], byte[], byte[])" />
    public byte[] Encrypt(byte[] key, byte[] plaintext, byte[] nonce)
    {
        byte[] ciphertext = new byte[plaintext.Length];
        using var xchacha = new global::NaCl.Core.XChaCha20(key, initialCounter: 0);
        xchacha.Encrypt(plaintext, nonce, ciphertext);

        var envelope = new SymmetricCipherEnvelope(
            version: SymmetricCipherEnvelope.LatestVersion,
            nonce: nonce,
            tag: [],
            aad: [],
            ciphertext: ciphertext
        );

        return envelope.ToBytes();
    }

    /// <inheritdoc cref="ISymmetricCipher.Decrypt(byte[], byte[])" />
    public byte[] Decrypt(byte[] key, byte[] encrypted)
    {
        SymmetricCipherEnvelope? envelope = SymmetricCipherEnvelope.FromBytes(encrypted);
        if (envelope == null)
        {
            throw new ArgumentException("Invalid envelope format");
        }

        byte[] plaintext = new byte[envelope.Ciphertext.Length];
        using var xchacha = new global::NaCl.Core.XChaCha20(key, initialCounter: 0);
        xchacha.Decrypt(envelope.Ciphertext, envelope.Nonce, plaintext);

        return plaintext;
    }
}
