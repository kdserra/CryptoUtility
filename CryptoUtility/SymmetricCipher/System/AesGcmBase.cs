using System.Security.Cryptography;

namespace CryptoUtility;

internal abstract class AesGcmBase : SymmetricCipherAEAD
{
    /// <inheritdoc cref="SymmetricCipher.Encrypt" />
    public override (bool success, byte[] encrypted) Encrypt(
        byte[] key,
        byte[] plaintext,
        byte[] nonce,
        byte[] aad
    )
    {
        if (!VerifyEncryptionParameters(key, plaintext, nonce))
        {
            return (false, []);
        }

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[AuthTagSizeBytes];

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

    /// <inheritdoc cref="SymmetricCipher.Decrypt" />
    public override (bool success, byte[] plaintext) Decrypt(byte[] key, byte[] encrypted)
    {
        SymmetricCipherEnvelope? envelope = SymmetricCipherEnvelope.FromBytes(encrypted);
        if (envelope == null)
        {
            return (false, []);
        }

        if (!VerifyDecryptionParameters(key, envelope))
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
