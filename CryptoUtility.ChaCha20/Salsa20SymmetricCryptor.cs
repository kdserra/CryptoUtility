namespace CryptoUtility.ChaCha20;

public sealed class Salsa20SymmetricCryptor : ISymmetricCryptor
{
    public int KeySize => throw new NotImplementedException();

    public byte[] Decrypt(byte[] key, byte[] encryptedValue, IKeyNormalizer? keyNormalizer = null)
    {
        keyNormalizer ??= this.GetDefaultKeyNormalizer();
        byte[] normalized = keyNormalizer.Normalize(key, KeySize);
        throw new NotImplementedException();
    }

    public byte[] Encrypt(byte[] key, byte[] value, IKeyNormalizer? keyNormalizer = null)
    {
        keyNormalizer ??= this.GetDefaultKeyNormalizer();
        byte[] normalized = keyNormalizer.Normalize(key, KeySize);
        throw new NotImplementedException();
    }
}
