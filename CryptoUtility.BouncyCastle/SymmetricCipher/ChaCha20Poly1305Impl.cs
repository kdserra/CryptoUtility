using Org.BouncyCastle.Crypto.Parameters;
using BouncyChaCha20Poly1305 = Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle ChaCha20-Poly1305 Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class ChaCha20Poly1305Impl : ISymmetricCipherAEAD
{
    public static readonly ChaCha20Poly1305Impl Shared = new();

    public int KeySizeBytes => 32;

    public int NonceSizeBytes => 12;

    public int AuthTagSizeBytes => 16;

    public byte[] Encrypt(byte[] key, byte[] plaintext, byte[] nonce) =>
        Encrypt(key, plaintext, nonce, aad: []);

    public byte[] Encrypt(
        byte[] key,
        byte[] plaintext,
        byte[] nonce,
        byte[] aad
    )
    {
        var cipher = new BouncyChaCha20Poly1305();
        var parameters = new AeadParameters(
            new KeyParameter(key),
            AuthTagSizeBytes * 8, // Mac size in bits
            nonce,
            aad
        );

        cipher.Init(true, parameters);

        byte[] outBuffer = new byte[cipher.GetOutputSize(plaintext.Length)];
        int len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, outBuffer, 0);
        cipher.DoFinal(outBuffer, len);

        // BouncyCastle appends the tag directly to the end of the ciphertext outBuffer
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[AuthTagSizeBytes];

        Buffer.BlockCopy(outBuffer, 0, ciphertext, 0, ciphertext.Length);
        Buffer.BlockCopy(outBuffer, ciphertext.Length, tag, 0, tag.Length);

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

        var cipher = new BouncyChaCha20Poly1305();
        var parameters = new AeadParameters(
            new KeyParameter(key),
            envelope.Tag.Length * 8,
            envelope.Nonce,
            envelope.Aad
        );

        cipher.Init(false, parameters);

        // BouncyCastle expects the ciphertext and tag concatenated together for processing
        byte[] inputBuffer = new byte[envelope.Ciphertext.Length + envelope.Tag.Length];
        Buffer.BlockCopy(envelope.Ciphertext, 0, inputBuffer, 0, envelope.Ciphertext.Length);
        Buffer.BlockCopy(
            envelope.Tag,
            0,
            inputBuffer,
            envelope.Ciphertext.Length,
            envelope.Tag.Length
        );

        byte[] plaintext = new byte[cipher.GetOutputSize(inputBuffer.Length)];
        int len = cipher.ProcessBytes(inputBuffer, 0, inputBuffer.Length, plaintext, 0);
        cipher.DoFinal(plaintext, len);

        return plaintext;
    }
}
