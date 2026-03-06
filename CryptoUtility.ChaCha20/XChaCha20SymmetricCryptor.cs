using System;
using System.Security.Cryptography;
using NaCl.Core;

namespace CryptoUtility.ChaCha20;

public sealed class XChaCha20SymmetricCryptor : ISymmetricCryptor
{
    private const int KEY_SIZE = 32;
    private const int NONCE_SIZE = 24;

    public int KeySize => KEY_SIZE;

    public byte[] Encrypt(byte[] key, byte[] value, IKeyNormalizer? keyNormalizer)
    {
        keyNormalizer ??= this.GetDefaultKeyNormalizer();
        byte[] normalized = keyNormalizer.Normalize(key, KEY_SIZE);

        byte[] nonce = new byte[NONCE_SIZE];
        CryptoHelper.Fill(nonce);

        byte[] ciphertext = new byte[value.Length];
        var cipher = new XChaCha20(normalized, 0); // initialCounter = 0
        cipher.Encrypt(value, nonce, ciphertext);

        byte[] result = new byte[NONCE_SIZE + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, NONCE_SIZE);
        Buffer.BlockCopy(ciphertext, 0, result, NONCE_SIZE, ciphertext.Length);

        return result;
    }

    public byte[] Decrypt(byte[] key, byte[] encryptedValue, IKeyNormalizer? keyNormalizer)
    {
        keyNormalizer ??= this.GetDefaultKeyNormalizer();
        byte[] normalized = keyNormalizer.Normalize(key, KEY_SIZE);

        if (encryptedValue.Length < NONCE_SIZE)
            throw new ArgumentException("Invalid ciphertext.", nameof(encryptedValue));

        byte[] nonce = new byte[NONCE_SIZE];
        Buffer.BlockCopy(encryptedValue, 0, nonce, 0, NONCE_SIZE);

        int cipherLength = encryptedValue.Length - NONCE_SIZE;
        byte[] ciphertext = new byte[cipherLength];
        Buffer.BlockCopy(encryptedValue, NONCE_SIZE, ciphertext, 0, cipherLength);

        byte[] plaintext = new byte[cipherLength];
        var cipher = new XChaCha20(normalized, 0); // initialCounter = 0
        cipher.Decrypt(ciphertext, nonce, plaintext);

        return plaintext;
    }
}
