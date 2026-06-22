using System.Security.Cryptography;

namespace CryptoUtility.NaCl;

[GenerateStaticApi]
public sealed class Salsa20Impl : ISymmetricCipher
{
    public static readonly Salsa20Impl Shared = new();

    /// <inheritdoc cref="ISymmetricCipher.KeySizeBytes" />
    public int KeySizeBytes => 32;

    /// <inheritdoc cref="ISymmetricCipher.NonceSizeBytes" />
    public int NonceSizeBytes => 8;

    /// <inheritdoc cref="ISymmetricCipher.Encrypt(byte[], byte[], byte[])" />
    public byte[] Encrypt(byte[] key, byte[] plaintext, byte[] nonce)
    {
        byte[] ciphertext = new byte[plaintext.Length];
        using var salsa = new global::NaCl.Core.Salsa20(key, initialCounter: 0);
        salsa.Encrypt(plaintext, nonce, ciphertext);

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
        using var salsa = new global::NaCl.Core.Salsa20(key, initialCounter: 0);
        salsa.Decrypt(envelope.Ciphertext, envelope.Nonce, plaintext);

        return plaintext;
    }
}
