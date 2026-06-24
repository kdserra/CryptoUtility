using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using BouncyPoly1305 = Org.BouncyCastle.Crypto.Macs.Poly1305;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle Poly1305 MAC Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Poly1305Impl : IMacProvider
{
    /// <summary>
    /// Shared static instance of <see cref="Poly1305Impl"/>.
    /// </summary>
    public static readonly Poly1305Impl Shared = new();

    private Poly1305Impl() { }

    /// <inheritdoc />
    public int RequiredKeySizeInBytes => 32;

    /// <inheritdoc />
    public int MacSizeInBytes => 16;

    /// <summary>
    /// Gets the Poly1305 nonce size in bytes.
    /// </summary>
    public int NonceSizeBytes => 16;

    /// <inheritdoc />
    public byte[] ComputeMac(byte[] key, byte[] message)
    {
        byte[] nonce = CryptoHelper.GetBytes(NonceSizeBytes);
        try
        {
            return ComputeMac(key, message, nonce);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
        }
    }

    /// <summary>
    /// Computes the Poly1305 tag with a specified nonce.
    /// Returns [Nonce] || [Tag].
    /// </summary>
    /// <param name="key">The secret key.</param>
    /// <param name="message">The message to authenticate.</param>
    /// <param name="nonce">The nonce to use.</param>
    /// <returns>A byte array containing the concatenated nonce and MAC tag.</returns>
    public byte[] ComputeMac(byte[] key, byte[] message, byte[] nonce)
    {
        LibraryHelper.ThrowIfNull(key);
        LibraryHelper.ThrowIfNull(message);
        LibraryHelper.ThrowIfNull(nonce);
        if (key.Length != RequiredKeySizeInBytes)
        {
            throw new ArgumentException(
                $"Key must be exactly {RequiredKeySizeInBytes} bytes.",
                nameof(key)
            );
        }
        if (nonce.Length != NonceSizeBytes)
        {
            throw new ArgumentException(
                $"Nonce must be exactly {NonceSizeBytes} bytes.",
                nameof(nonce)
            );
        }

        var mac = new BouncyPoly1305(new Org.BouncyCastle.Crypto.Engines.AesEngine());
        mac.Init(new ParametersWithIV(new KeyParameter(key), nonce));
        mac.BlockUpdate(message, 0, message.Length);

        byte[] tag = new byte[MacSizeInBytes];
        mac.DoFinal(tag, 0);

        byte[] result = new byte[NonceSizeBytes + MacSizeInBytes];
        Buffer.BlockCopy(nonce, 0, result, 0, NonceSizeBytes);
        Buffer.BlockCopy(tag, 0, result, NonceSizeBytes, MacSizeInBytes);

        return result;
    }

    /// <inheritdoc />
    public bool VerifyMac(byte[] key, byte[] message, byte[] mac)
    {
        LibraryHelper.ThrowIfNull(key);
        LibraryHelper.ThrowIfNull(message);
        LibraryHelper.ThrowIfNull(mac);
        if (mac.Length < NonceSizeBytes + MacSizeInBytes)
        {
            return false;
        }

        byte[] nonce = new byte[NonceSizeBytes];
        Buffer.BlockCopy(mac, 0, nonce, 0, NonceSizeBytes);

        byte[] expectedTag = new byte[MacSizeInBytes];
        Buffer.BlockCopy(mac, NonceSizeBytes, expectedTag, 0, MacSizeInBytes);

        var macEngine = new BouncyPoly1305(new Org.BouncyCastle.Crypto.Engines.AesEngine());
        macEngine.Init(new ParametersWithIV(new KeyParameter(key), nonce));
        macEngine.BlockUpdate(message, 0, message.Length);

        byte[] computedTag = new byte[MacSizeInBytes];
        macEngine.DoFinal(computedTag, 0);

        try
        {
            return CryptographicOperations.FixedTimeEquals(computedTag, expectedTag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(computedTag);
        }
    }
}
