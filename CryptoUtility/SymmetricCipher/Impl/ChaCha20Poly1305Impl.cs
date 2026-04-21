#if NET8_0_OR_GREATER
using System.Security.Cryptography;
using ChaCha20Poly1305System = System.Security.Cryptography.ChaCha20Poly1305;

namespace CryptoUtility;

/// <summary>
/// Official .NET ChaCha20-Poly1305 Implementation.
/// </summary>
[GenerateStaticApi]
internal sealed class ChaCha20Poly1305Impl : SymmetricCipherAEAD
{
    public override int KeySizeBytes => 32; // 256-bit
    public override int NonceSizeBytes => 12; // 96-bit

    public override int AuthTagSizeBytes => 16; // 128-bit

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
            using var chacha = new ChaCha20Poly1305System(key);

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

            return (true, envelope.ToBytes());
        }
        catch
        {
            return (false, []);
        }
    }

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
            using var chacha = new ChaCha20Poly1305System(key);

            chacha.Decrypt(
                nonce: envelope.Nonce,
                ciphertext: envelope.Ciphertext,
                tag: envelope.Tag,
                plaintext: plaintext,
                associatedData: envelope.Aad
            );

            return (true, plaintext);
        }
        catch
        {
            return (false, []);
        }
    }
}
#endif
