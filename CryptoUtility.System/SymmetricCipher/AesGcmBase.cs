using System.Security.Cryptography;

namespace CryptoUtility.System;

public abstract class AesGcmBase : ISymmetricCipherAEAD
{
    public abstract int KeySizeBytes { get; }
    public abstract int NonceSizeBytes { get; }
    public abstract int AuthTagSizeBytes { get; }

    /// <inheritdoc cref="ISymmetricCipher.Encrypt" />
    public byte[] Encrypt(byte[] key, byte[] plaintext, byte[] nonce) =>
        Encrypt(key, plaintext, nonce: nonce, aad: []);

    /// <inheritdoc cref="ISymmetricCipher.Encrypt" />
    public byte[] Encrypt(
        byte[] key,
        byte[] plaintext,
        byte[] nonce,
        byte[] aad
    )
    {
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[this.AuthTagSizeBytes];

#if NET8_0_OR_GREATER
        using var aes = new AesGcm(key, AuthTagSizeBytes);
#else
        using var aes = new AesGcm(key);
#endif
        aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        var envelope = new SymmetricCipherEnvelope(
            version: 1,
            nonce: nonce,
            tag: tag,
            aad: aad,
            ciphertext: ciphertext
        );

        return envelope.ToBytes();
    }

    /// <inheritdoc cref="ISymmetricCipher.Decrypt" />
    public byte[] Decrypt(byte[] key, byte[] encrypted)
    {
        SymmetricCipherEnvelope? envelope = SymmetricCipherEnvelope.FromBytes(encrypted);
        if (envelope == null)
        {
            throw new ArgumentException("Invalid envelope format");
        }

        byte[] plaintext = new byte[envelope.Ciphertext.Length];

#if NET8_0_OR_GREATER
        using var aes = new AesGcm(key, AuthTagSizeBytes);
#else
        using var aes = new AesGcm(key);
#endif
        aes.Decrypt(envelope.Nonce, envelope.Ciphertext, envelope.Tag, plaintext, envelope.Aad);

        return plaintext;
    }
}
