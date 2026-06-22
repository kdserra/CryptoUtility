#if NET8_0_OR_GREATER
using System.Security.Cryptography;
using SystemChaCha20Poly1305 = System.Security.Cryptography.ChaCha20Poly1305;

namespace CryptoUtility.System;

/// <summary>
/// Official .NET ChaCha20-Poly1305 Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class ChaCha20Poly1305Impl : ISymmetricCipherAEAD
{
    public static readonly ChaCha20Poly1305Impl Shared = new();

    /// <inheritdoc cref="ISymmetricCipher.KeySizeBytes" />
    public int KeySizeBytes => 32;

    /// <inheritdoc cref="ISymmetricCipher.NonceSizeBytes" />
    public int NonceSizeBytes => 12;

    /// <inheritdoc cref="ISymmetricCipherAE.AuthTagSizeBytes" />
    public int AuthTagSizeBytes => 16;

    /// <inheritdoc cref="ISymmetricCipherAEAD.Encrypt" />
    public byte[] Encrypt(byte[] key, byte[] plaintext, byte[] nonce) =>
        Encrypt(key, plaintext, nonce, aad: []);

    /// <inheritdoc cref="ISymmetricCipherAEAD.Encrypt" />
    public byte[] Encrypt(
        byte[] key,
        byte[] plaintext,
        byte[] nonce,
        byte[] aad
    )
    {
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[AuthTagSizeBytes];

        using var chacha = new SystemChaCha20Poly1305(key);

        chacha.Encrypt(
            nonce: nonce,
            plaintext: plaintext,
            ciphertext: ciphertext,
            tag: tag,
            associatedData: aad
        );

        var envelope = new SymmetricCipherEnvelope(
            version: 1,
            nonce: nonce,
            tag: tag,
            aad: aad,
            ciphertext: ciphertext
        );

        return envelope.ToBytes();
    }

    public byte[] Decrypt(byte[] key, byte[] encrypted)
    {
        SymmetricCipherEnvelope? envelope = SymmetricCipherEnvelope.FromBytes(encrypted);
        if (envelope == null)
        {
            throw new ArgumentException("Invalid envelope format");
        }

        byte[] plaintext = new byte[envelope.Ciphertext.Length];

        using var chacha = new SystemChaCha20Poly1305(key);

        chacha.Decrypt(
            nonce: envelope.Nonce,
            ciphertext: envelope.Ciphertext,
            tag: envelope.Tag,
            plaintext: plaintext,
            associatedData: envelope.Aad
        );

        return plaintext;
    }
}
#endif
