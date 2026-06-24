using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Base class for Bouncy Castle GCM-based symmetric cipher implementations.
/// </summary>
public abstract class GcmCipherBase : ISymmetricCipherAEAD
{
    /// <inheritdoc />
    public abstract int KeySizeBytes { get; }

    /// <inheritdoc />
    public abstract int NonceSizeBytes { get; }

    /// <inheritdoc />
    public abstract int AuthTagSizeBytes { get; }

    /// <summary>
    /// Creates the block cipher engine.
    /// </summary>
    protected abstract IBlockCipher CreateEngine();

    /// <inheritdoc />
    public byte[] Encrypt(byte[] key, byte[] plaintext, byte[] nonce) =>
        Encrypt(key, plaintext, nonce: nonce, aad: []);

    /// <inheritdoc />
    public byte[] Encrypt(
        byte[] key,
        byte[] plaintext,
        byte[] nonce,
        byte[] aad
    )
    {
        LibraryHelper.ThrowIfAnyNull(key, plaintext, nonce, aad);
        var cipher = CreateCipher(forEncryption: true, key, nonce, aad);
        byte[] output = new byte[cipher.GetOutputSize(plaintext.Length)];

        int outputLength = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
        outputLength += cipher.DoFinal(output, outputLength);

        if (outputLength != plaintext.Length + AuthTagSizeBytes)
        {
            throw new CryptographicException("Encryption failed: output length mismatch");
        }

        byte[] result = new byte[nonce.Length + outputLength];
        Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
        Buffer.BlockCopy(output, 0, result, nonce.Length, outputLength);

        return result;
    }

    /// <inheritdoc />
    public byte[] Decrypt(byte[] key, byte[] encrypted) =>
        Decrypt(key, encrypted, aad: []);

    /// <inheritdoc />
    public byte[] Decrypt(byte[] key, byte[] encrypted, byte[] aad)
    {
        LibraryHelper.ThrowIfAnyNull(key, encrypted, aad);
        int nonceLen = NonceSizeBytes;
        int tagLen = AuthTagSizeBytes;

        if (encrypted.Length < nonceLen + tagLen)
        {
            throw new ArgumentException("Encrypted payload is too short.");
        }

        byte[] nonce = new byte[nonceLen];
        Buffer.BlockCopy(encrypted, 0, nonce, 0, nonceLen);

        int inputLen = encrypted.Length - nonceLen;
        byte[] input = new byte[inputLen];
        Buffer.BlockCopy(encrypted, nonceLen, input, 0, inputLen);

        var cipher = CreateCipher(
            forEncryption: false,
            key,
            nonce,
            aad
        );
        byte[] plaintext = new byte[cipher.GetOutputSize(input.Length)];

        int outputLength = cipher.ProcessBytes(input, 0, input.Length, plaintext, 0);
        outputLength += cipher.DoFinal(plaintext, outputLength);

        if (plaintext.Length != outputLength)
        {
            byte[] actualPlaintext = new byte[outputLength];
            Buffer.BlockCopy(plaintext, 0, actualPlaintext, 0, outputLength);
            return actualPlaintext;
        }

        return plaintext;
    }

    private GcmBlockCipher CreateCipher(
        bool forEncryption,
        byte[] key,
        byte[] nonce,
        byte[] aad
    )
    {
        var cipher = new GcmBlockCipher(CreateEngine());
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
