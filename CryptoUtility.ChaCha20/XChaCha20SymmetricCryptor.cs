using NaCl.Core;

namespace CryptoUtility.ChaCha20;

public sealed class XChaCha20SymmetricCryptor : ISymmetricCryptor
{
    private const int NonceSize = 24;
    public int KeySize => 32;

    public byte[] Encrypt(byte[] key, byte[] value, IKeyNormalizer? keyNormalizer)
    {
        keyNormalizer ??= this.GetDefaultKeyNormalizer();
        byte[] normalized = keyNormalizer.Normalize(key, KeySize);

        byte[] nonce = new byte[NonceSize];
        CryptoHelper.Fill(nonce);

        byte[] ciphertext = new byte[value.Length];
        var cipher = new XChaCha20(normalized, 0); // initialCounter = 0
        cipher.Encrypt(value, nonce, ciphertext);

        byte[] result = new byte[NonceSize + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, NonceSize);
        Buffer.BlockCopy(ciphertext, 0, result, NonceSize, ciphertext.Length);

        return result;
    }

    public byte[] Decrypt(byte[] key, byte[] encryptedValue, IKeyNormalizer? keyNormalizer)
    {
        keyNormalizer ??= this.GetDefaultKeyNormalizer();
        byte[] normalized = keyNormalizer.Normalize(key, KeySize);

        if (encryptedValue.Length < NonceSize)
            throw new ArgumentException("Invalid ciphertext.", nameof(encryptedValue));

        byte[] nonce = new byte[NonceSize];
        Buffer.BlockCopy(encryptedValue, 0, nonce, 0, NonceSize);

        int cipherLength = encryptedValue.Length - NonceSize;
        byte[] ciphertext = new byte[cipherLength];
        Buffer.BlockCopy(encryptedValue, NonceSize, ciphertext, 0, cipherLength);

        byte[] plaintext = new byte[cipherLength];
        var cipher = new XChaCha20(normalized, 0); // initialCounter = 0
        cipher.Decrypt(ciphertext, nonce, plaintext);

        return plaintext;
    }
}
