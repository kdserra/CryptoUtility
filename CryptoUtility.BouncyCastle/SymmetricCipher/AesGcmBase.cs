using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoUtility.BouncyCastle;

public abstract class AesGcmBase : ISymmetricCipherAEAD
{
    public abstract int KeySizeBytes { get; }
    public abstract int NonceSizeBytes { get; }
    public abstract int AuthTagSizeBytes { get; }

    /// <inheritdoc cref="ISymmetricCipher.Encrypt" />
    public (bool success, byte[] encrypted) Encrypt(byte[] key, byte[] plaintext, byte[] nonce) =>
        Encrypt(key, plaintext, nonce: nonce, aad: []);

    /// <inheritdoc cref="ISymmetricCipherAEAD.Encrypt(byte[], byte[], byte[], byte[])" />
    public (bool success, byte[] encrypted) Encrypt(
        byte[] key,
        byte[] plaintext,
        byte[] nonce,
        byte[] aad
    )
    {
        if (aad is null || !this.VerifyEncryptionParameters(key, plaintext, nonce))
        {
            return (false, []);
        }

        try
        {
            var cipher = CreateCipher(forEncryption: true, key, nonce, aad);
            byte[] output = new byte[cipher.GetOutputSize(plaintext.Length)];

            int outputLength = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
            outputLength += cipher.DoFinal(output, outputLength);

            if (outputLength != plaintext.Length + AuthTagSizeBytes)
            {
                return (false, []);
            }

            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[AuthTagSizeBytes];

            Buffer.BlockCopy(output, 0, ciphertext, 0, ciphertext.Length);
            Buffer.BlockCopy(output, ciphertext.Length, tag, 0, tag.Length);

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

        try
        {
            byte[] input = new byte[envelope.Ciphertext.Length + envelope.Tag.Length];
            Buffer.BlockCopy(envelope.Ciphertext, 0, input, 0, envelope.Ciphertext.Length);
            Buffer.BlockCopy(
                envelope.Tag,
                0,
                input,
                envelope.Ciphertext.Length,
                envelope.Tag.Length
            );

            var cipher = CreateCipher(
                forEncryption: false,
                key,
                envelope.Nonce,
                envelope.Aad
            );
            byte[] plaintext = new byte[cipher.GetOutputSize(input.Length)];

            int outputLength = cipher.ProcessBytes(input, 0, input.Length, plaintext, 0);
            outputLength += cipher.DoFinal(plaintext, outputLength);

            if (outputLength != plaintext.Length)
            {
                return (false, []);
            }

            return (true, plaintext);
        }
        catch
        {
            return (false, []);
        }
    }

    private GcmBlockCipher CreateCipher(
        bool forEncryption,
        byte[] key,
        byte[] nonce,
        byte[] aad
    )
    {
        var cipher = new GcmBlockCipher(new AesEngine());
        var parameters = new AeadParameters(
            new KeyParameter(key),
            AuthTagSizeBytes * 8,
            nonce,
            aad
        );

        cipher.Init(forEncryption, parameters);
        return cipher;
    }
}
