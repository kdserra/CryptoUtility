using System.Security.Cryptography;

namespace CryptoUtility.Extras;

[GenerateStaticApi]
public sealed class XorCipherImpl : ISymmetricCipher
{
    public static readonly XorCipherImpl Shared = new();

    /// <inheritdoc cref="ISymmetricCipher.KeySizeBytes" />
    public int KeySizeBytes => 32;

    /// <inheritdoc cref="ISymmetricCipher.NonceSizeBytes" />
    public int NonceSizeBytes => 32;

    /// <inheritdoc cref="ISymmetricCipher.Encrypt(byte[], byte[], byte[])" />
    public byte[] Encrypt(byte[] key, byte[] plaintext, byte[] nonce)
    {
        if (key == null || key.Length == 0)
            throw new CryptographicException("Key cannot be null or empty");
        if (nonce == null || nonce.Length == 0)
            throw new CryptographicException("Nonce cannot be null or empty");
        if (plaintext == null)
            throw new CryptographicException("Plaintext cannot be null");

        byte[] input = new byte[nonce.Length + plaintext.Length];
        Buffer.BlockCopy(nonce, 0, input, 0, nonce.Length);
        Buffer.BlockCopy(plaintext, 0, input, nonce.Length, plaintext.Length);

        byte[] ciphertext = Xor(input, key);

        SymmetricCipherEnvelope envelope = new(
            version: SymmetricCipherEnvelope.LatestVersion,
            nonce: nonce,
            tag: [],
            aad: [],
            ciphertext: ciphertext
        );

        CryptographicOperations.ZeroMemory(input);

        return envelope.ToBytes();
    }

    /// <inheritdoc cref="ISymmetricCipher.Decrypt(byte[], byte[])" />
    public byte[] Decrypt(byte[] key, byte[] encrypted)
    {
        SymmetricCipherEnvelope? envelope = SymmetricCipherEnvelope.FromBytes(encrypted);
        if (envelope == null)
        {
            throw new ArgumentException("Invalid envelope format");
        }

        byte[] decrypted = Xor(envelope.Ciphertext, key);
        if (decrypted.Length < NonceSizeBytes)
        {
            throw new ArgumentException("Decrypted ciphertext too short");
        }

        byte[] plaintext = new byte[decrypted.Length - NonceSizeBytes];
        Buffer.BlockCopy(decrypted, NonceSizeBytes, plaintext, 0, plaintext.Length);

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
