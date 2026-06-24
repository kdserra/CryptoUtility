using Org.BouncyCastle.Crypto.Parameters;
using BouncyChaCha20Poly1305 = Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle ChaCha20-Poly1305 Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class ChaCha20Poly1305Impl : ISymmetricCipherAEAD
{
    /// <summary>
    /// Shared static instance of <see cref="ChaCha20Poly1305Impl"/>.
    /// </summary>
    public static readonly ChaCha20Poly1305Impl Shared = new();

    private ChaCha20Poly1305Impl() { }

    /// <inheritdoc />
    public int KeySizeBytes => 32;

    /// <inheritdoc />
    public int NonceSizeBytes => 12;

    /// <inheritdoc />
    public int AuthTagSizeBytes => 16;

    /// <inheritdoc />
    public byte[] Encrypt(byte[] key, byte[] plaintext, byte[] nonce) =>
        Encrypt(key, plaintext, nonce, aad: []);

    /// <inheritdoc />
    public byte[] Encrypt(byte[] key, byte[] plaintext, byte[] nonce, byte[] aad)
    {
        LibraryHelper.ThrowIfNull(key);
        LibraryHelper.ThrowIfNull(plaintext);
        LibraryHelper.ThrowIfNull(nonce);
        LibraryHelper.ThrowIfNull(aad);
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

        byte[] result = new byte[nonce.Length + outBuffer.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
        Buffer.BlockCopy(outBuffer, 0, result, nonce.Length, outBuffer.Length);

        return result;
    }

    /// <inheritdoc />
    public byte[] Decrypt(byte[] key, byte[] encrypted) => Decrypt(key, encrypted, aad: []);

    /// <inheritdoc />
    public byte[] Decrypt(byte[] key, byte[] encrypted, byte[] aad)
    {
        LibraryHelper.ThrowIfNull(key);
        LibraryHelper.ThrowIfNull(encrypted);
        LibraryHelper.ThrowIfNull(aad);
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

        var cipher = new BouncyChaCha20Poly1305();
        var parameters = new AeadParameters(new KeyParameter(key), tagLen * 8, nonce, aad);

        cipher.Init(false, parameters);

        byte[] plaintext = new byte[cipher.GetOutputSize(input.Length)];
        int len = cipher.ProcessBytes(input, 0, input.Length, plaintext, 0);
        cipher.DoFinal(plaintext, len);

        return plaintext;
    }
}
