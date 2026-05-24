using System.Security.Cryptography;

namespace CryptoUtility.NaCl;

[GenerateStaticApi]
public sealed class XChaCha20Poly1305Impl : ISymmetricCipherAEAD
{
    public static readonly XChaCha20Poly1305Impl Shared = new();

    /// <inheritdoc cref="ISymmetricCipher.KeySizeBytes" />
    public int KeySizeBytes => 32;

    /// <inheritdoc cref="ISymmetricCipher.NonceSizeBytes" />
    public int NonceSizeBytes => 24;

    /// <inheritdoc cref="ISymmetricCipherAE.AuthTagSizeBytes" />
    public int AuthTagSizeBytes => 16;

    /// <inheritdoc cref="ISymmetricCipher.Encrypt(byte[], byte[], byte[])" />
    public (bool success, byte[] encrypted) Encrypt(byte[] key, byte[] plaintext, byte[] nonce) =>
        Encrypt(key, plaintext, nonce, aad: []);

    /// <inheritdoc cref="ISymmetricCipherAEAD.Encrypt(byte[], byte[], byte[], byte[])" />
    public (bool success, byte[] encrypted) Encrypt(
        byte[] key,
        byte[] plaintext,
        byte[] nonce,
        byte[] aad
    )
    {
        if (!this.VerifyEncryptionParameters(key, plaintext, nonce))
        {
            return (false, []);
        }

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[AuthTagSizeBytes];

        try
        {
            using var aead = new global::NaCl.Core.XChaCha20Poly1305(key);
            aead.Encrypt(nonce, plaintext, ciphertext, tag, aad);

            var envelope = new SymmetricCipherEnvelope(
                version: SymmetricCipherEnvelope.LatestVersion,
                nonce: nonce,
                tag: tag,
                aad: aad,
                ciphertext: ciphertext
            );

            return (true, envelope.ToBytes());
        }
        catch
        {
            return (false, []);
        }
    }

    /// <inheritdoc cref="ISymmetricCipher.Decrypt(byte[], byte[])" />
    public (bool success, byte[] plaintext) Decrypt(byte[] key, byte[] encrypted)
    {
        SymmetricCipherEnvelope? envelope = SymmetricCipherEnvelope.FromBytes(encrypted);
        if (envelope == null)
        {
            return (false, []);
        }

        if (!this.VerifyDecryptionParametersAEAD(key, envelope))
        {
            return (false, []);
        }

        byte[] plaintext = new byte[envelope.Ciphertext.Length];

        try
        {
            using var aead = new global::NaCl.Core.XChaCha20Poly1305(key);
            aead.Decrypt(envelope.Nonce, envelope.Ciphertext, envelope.Tag, plaintext, envelope.Aad);

            return (true, plaintext);
        }
        catch
        {
            return (false, []);
        }
    }
}
