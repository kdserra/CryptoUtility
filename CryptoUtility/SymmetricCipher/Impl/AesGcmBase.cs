using System.Security.Cryptography;

namespace CryptoUtility;

internal abstract class AesGcmBase : ISymmetricCipherAEAD
{
    public abstract SymmetricCipherID CipherID { get; }
    public abstract int KeySizeBytes { get; }
    public abstract int NonceSizeBytes { get; }
    public abstract int AuthTagSizeBytes { get; }

    /// <inheritdoc cref="ISymmetricCipher.Encrypt" />
    public (bool success, byte[] encrypted) Encrypt(byte[] key, byte[] plaintext, byte[] nonce) =>
        Encrypt(key, plaintext, nonce: this.GenerateNonce(), aad: []);

    /// <inheritdoc cref="ISymmetricCipher.Encrypt" />
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
        byte[] tag = new byte[this.AuthTagSizeBytes];

        try
        {
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

            return (true, envelope.ToBytes());
        }
        catch
        {
            return (false, []);
        }
    }

    /// <inheritdoc cref="ISymmetricCipher.Decrypt" />
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
#if NET8_0_OR_GREATER
            using var aes = new AesGcm(key, AuthTagSizeBytes);
#else
            using var aes = new AesGcm(key);
#endif
            aes.Decrypt(envelope.Nonce, envelope.Ciphertext, envelope.Tag, plaintext, envelope.Aad);

            return (true, plaintext);
        }
        catch
        {
            return (false, []);
        }
    }
}
