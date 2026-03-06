namespace CryptoUtility;

public class TruncateAndPadKeyNormalizer : IKeyNormalizer
{
    public byte[] Normalize(byte[] key, int keySize)
    {
        if (key == null)
            throw new ArgumentNullException(nameof(key));

        if (key.Length == keySize)
            return key;

        byte[] normalized = new byte[keySize];

        if (key.Length > keySize)
            Buffer.BlockCopy(key, 0, normalized, 0, keySize);
        else
            Buffer.BlockCopy(key, 0, normalized, 0, key.Length);

        return normalized;
    }
}
