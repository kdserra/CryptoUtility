namespace CryptoUtility.ChaCha20;

public sealed class ChaCha20Poly1305SymmetricCryptor2 : ISymmetricCryptor
{
    public int KeySize => throw new NotImplementedException();

    public byte[] Decrypt(byte[] key, byte[] encryptedValue, IKeyNormalizer? keyNormalizer)
    {
        keyNormalizer ??= this.GetDefaultKeyNormalizer();
        byte[] normalized = keyNormalizer.Normalize(key, KeySize);
        throw new NotImplementedException();
    }

    public byte[] Encrypt(byte[] key, byte[] value, IKeyNormalizer? keyNormalizer)
    {
        keyNormalizer ??= this.GetDefaultKeyNormalizer();
        byte[] normalized = keyNormalizer.Normalize(key, KeySize);
        throw new NotImplementedException();
    }
}
