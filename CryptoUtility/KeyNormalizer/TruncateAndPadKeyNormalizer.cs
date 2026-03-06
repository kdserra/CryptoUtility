namespace CryptoUtility;

/// <summary>
/// A simple key normalizer that adjusts the input key to the required size by truncating or padding with zeros.
/// </summary>
public sealed class TruncateAndPadKeyNormalizer : IKeyNormalizer
{
    /// <summary>
    /// Normalizes the input key to the specified size.
    /// If the key is longer than <paramref name="keySize"/>, it is truncated.
    /// If the key is shorter, it is padded with zeros.
    /// </summary>
    /// <param name="key">The input key as a byte array.</param>
    /// <param name="keySize">The desired key size in bytes.</param>
    /// <returns>A byte array of length <paramref name="keySize"/> containing the normalized key.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="key"/> is null.</exception>
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
