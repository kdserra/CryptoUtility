using System.Security.Cryptography;

namespace CryptoUtility.NaCl;

[GenerateStaticApi]
public sealed class ChaCha20Impl : ISymmetricCipher
{
    public static readonly ChaCha20Impl Shared = new();

    /// <inheritdoc cref="ISymmetricCipher.KeySizeBytes" />
    public int KeySizeBytes => 32;

    /// <inheritdoc cref="ISymmetricCipher.NonceSizeBytes" />
    public int NonceSizeBytes => 12;

    /// <inheritdoc cref="ISymmetricCipher.Encrypt(byte[], byte[], byte[])" />
    public (bool success, byte[] encrypted) Encrypt(byte[] key, byte[] plaintext, byte[] nonce)
    {
        if (!this.VerifyEncryptionParameters(key, plaintext, nonce))
        {
            return (false, []);
        }

        try
        {
            byte[] ciphertext = new byte[plaintext.Length];
            using var chacha = new global::NaCl.Core.ChaCha20(key, initialCounter: 0);
            chacha.Encrypt(plaintext, nonce, ciphertext);

            var envelope = new SymmetricCipherEnvelope(
                version: SymmetricCipherEnvelope.LatestVersion,
                nonce: nonce,
                tag: [],
                aad: [],
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

        if (!this.VerifyDecryptionParametersBase(key, envelope))
        {
            return (false, []);
        }

        try
        {
            byte[] plaintext = new byte[envelope.Ciphertext.Length];
            using var chacha = new global::NaCl.Core.ChaCha20(key, initialCounter: 0);
            chacha.Decrypt(envelope.Ciphertext, envelope.Nonce, plaintext);

            return (true, plaintext);
        }
        catch
        {
            return (false, []);
        }
    }
}
