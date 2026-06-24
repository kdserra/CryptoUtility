using System.Security.Cryptography;

namespace CryptoUtility.Extras;

/// <summary>
/// A simple XOR cipher implementation for testing and demonstration.
/// Layout: [Nonce] || [Ciphertext]
/// </summary>
[GenerateStaticApi]
public sealed class XorCipherImpl : ISymmetricCipher
{
    /// <summary>
    /// Shared static instance of <see cref="XorCipherImpl"/>.
    /// </summary>
    public static readonly XorCipherImpl Shared = new();

    private XorCipherImpl() { }

    /// <inheritdoc />
    public int KeySizeBytes => 32;

    /// <inheritdoc />
    public int NonceSizeBytes => 32;

    /// <inheritdoc />
    public byte[] Encrypt(byte[] key, byte[] plaintext, byte[] nonce)
    {
        LibraryHelper.ThrowIfAnyNull(key, plaintext, nonce);
        if (key.Length == 0)
            throw new ArgumentException("Key cannot be empty.", nameof(key));
        if (nonce.Length != NonceSizeBytes)
            throw new ArgumentException($"Nonce must be exactly {NonceSizeBytes} bytes.", nameof(nonce));

        byte[] keyStreamKey = new byte[key.Length];
        for (int i = 0; i < key.Length; i++)
        {
            keyStreamKey[i] = (byte)(key[i] ^ nonce[i % nonce.Length]);
        }

        byte[] ciphertext = Xor(plaintext, keyStreamKey);

        byte[] result = new byte[nonce.Length + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
        Buffer.BlockCopy(ciphertext, 0, result, nonce.Length, ciphertext.Length);

        CryptographicOperations.ZeroMemory(keyStreamKey);

        return result;
    }

    /// <inheritdoc />
    public byte[] Decrypt(byte[] key, byte[] encrypted)
    {
        LibraryHelper.ThrowIfAnyNull(key, encrypted);
        int nonceLen = NonceSizeBytes;
        if (encrypted.Length < nonceLen)
        {
            throw new ArgumentException("Encrypted payload is too short.");
        }

        byte[] nonce = new byte[nonceLen];
        int ciphertextLen = encrypted.Length - nonceLen;
        byte[] ciphertext = new byte[ciphertextLen];

        Buffer.BlockCopy(encrypted, 0, nonce, 0, nonceLen);
        Buffer.BlockCopy(encrypted, nonceLen, ciphertext, 0, ciphertextLen);

        byte[] keyStreamKey = new byte[key.Length];
        for (int i = 0; i < key.Length; i++)
        {
            keyStreamKey[i] = (byte)(key[i] ^ nonce[i % nonce.Length]);
        }

        byte[] plaintext = Xor(ciphertext, keyStreamKey);

        CryptographicOperations.ZeroMemory(keyStreamKey);

        return plaintext;
    }

    private static byte[] Xor(byte[] input, byte[] key)
    {
        byte[] output = new byte[input.Length];
        for (int i = 0; i < input.Length; i++)
        {
            output[i] = (byte)(input[i] ^ key[i % key.Length]);
        }
        return output;
    }
}
