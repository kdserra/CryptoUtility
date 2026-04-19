using System.Security.Cryptography;

namespace CryptoUtility;

/// <summary>
/// Official .NET AES-256 GCM
/// </summary>
[GenerateStaticApi(nameof(Aes256Gcm))]
internal sealed class Aes256GcmImpl : SymmetricCipherAEAD
{
    public override CipherID CipherID => CipherID.AES_256_GCM;

    public override int KeySizeBytes => 32; // 256-bit

    public override int NonceSizeBytes => 12; // 96-bit

    private const int AuthTagSize = 16; // 128-bit

    public override (bool success, byte[] encrypted) Encrypt(
        byte[] key,
        byte[] plaintext,
        byte[] nonce,
        byte[] aad
    )
    {
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[AuthTagSize];

        try
        {
#if NET8_0_OR_GREATER
            using var aes = new AesGcm(key, AuthTagSize);
#else
            using var aes = new AesGcm(key);
#endif
            aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);

            var envelope = new SymmetricCipherEnvelope(
                version: 1,
                cipher: CipherID,
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

        bool success = Verify(envelope);
        if (!success)
        {
            return (false, []);
        }

        byte[] plaintext = new byte[envelope.Ciphertext.Length];

        try
        {
#if NET8_0_OR_GREATER
            using var aes = new AesGcm(key, AuthTagSize);
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
