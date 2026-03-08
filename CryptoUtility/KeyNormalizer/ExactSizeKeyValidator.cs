namespace CryptoUtility;

/// <summary>
/// A key normalizer that performs no transformation on the key.
/// Validates that the key is exactly the expected size.
/// </summary>
public sealed class ExactSizeKeyValidator : IKeyNormalizer
{
    /// <summary>
    /// Returns the original key if it matches the expected size.
    /// Throws an exception if the key is null or the wrong length.
    /// </summary>
    /// <param name="key">The input key as a byte array.</param>
    /// <param name="keySizeBytes">The expected key size in bytes.</param>
    /// <returns>The original key unchanged.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="key"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="key"/> length does not equal <paramref name="keySizeBytes"/>.</exception>
    public byte[] Normalize(byte[] key, int keySizeBytes)
    {
        if (key == null)
            throw new ArgumentNullException(nameof(key));

        if (key.Length != keySizeBytes)
            throw new ArgumentException($"Key must be {keySizeBytes} bytes.", nameof(key));

        return key;
    }
}
