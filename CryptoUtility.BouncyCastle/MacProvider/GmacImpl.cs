using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle GMAC (AES-GCM MAC) Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class GmacImpl : IMacProvider
{
    /// <summary>
    /// Shared static instance of <see cref="GmacImpl"/>.
    /// </summary>
    public static readonly GmacImpl Shared = new();

    private GmacImpl() { }

    /// <inheritdoc />
    public int RequiredKeySizeInBytes => 0;

    /// <inheritdoc />
    public int MacSizeInBytes => 16;

    /// <summary>
    /// Gets the standard GMAC nonce size in bytes.
    /// </summary>
    public int NonceSizeBytes => 12;

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
    /// Computes the GMAC tag using a specified nonce.
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
        if (nonce.Length != NonceSizeBytes)
        {
            throw new ArgumentException(
                $"Nonce must be exactly {NonceSizeBytes} bytes.",
                nameof(nonce)
            );
        }

        var gmac = new GMac(new GcmBlockCipher(new AesEngine()));
        gmac.Init(new ParametersWithIV(new KeyParameter(key), nonce));
        gmac.BlockUpdate(message, 0, message.Length);

        byte[] tag = new byte[MacSizeInBytes];
        gmac.DoFinal(tag, 0);

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
        byte[] expectedTag = new byte[MacSizeInBytes];

        Buffer.BlockCopy(mac, 0, nonce, 0, NonceSizeBytes);
        Buffer.BlockCopy(mac, NonceSizeBytes, expectedTag, 0, MacSizeInBytes);

        var gmac = new GMac(new GcmBlockCipher(new AesEngine()));
        gmac.Init(new ParametersWithIV(new KeyParameter(key), nonce));
        gmac.BlockUpdate(message, 0, message.Length);

        byte[] computedTag = new byte[MacSizeInBytes];
        gmac.DoFinal(computedTag, 0);

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
