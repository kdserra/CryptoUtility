using System.Security.Cryptography;

namespace CryptoUtility;

/// <summary>
/// Defines methods for performing symmetric encryption and decryption operations, as well as cryptographic key
/// management.
/// </summary>
public interface ISymmetricCryptor
{
    /// <summary>
    /// Gets the size, in bits, of the cryptographic key used for encryption and decryption operations.
    /// </summary>
    public int KeySize { get; }

    /// <summary>
    /// Encrypts the specified value using the provided key and returns the encrypted data.
    /// </summary>
    /// <param name="key">The cryptographic key used for encryption.</param>
    /// <param name="value">The value to encrypt.</param>
    /// <param name="keyNormalizer">Optional key normalizer. If not provided, a default will be used.</param>
    /// <returns>The encrypted data.</returns>
    public byte[] Encrypt(byte[] key, byte[] value, IKeyNormalizer? keyNormalizer);

    /// <summary>
    /// Decrypts the specified encrypted value using the provided key and returns the decrypted data.
    /// </summary>
    /// <param name="cryptor">The symmetric cryptor instance.</param>
    /// <param name="key">The cryptographic key used for decryption.</param>
    /// <param name="encryptedValue">The encrypted value to decrypt.</param>
    /// <param name="keyNormalizer">Optional key normalizer. If not provided, a default will be used.</param>
    /// <returns>The decrypted data.</returns>
    public byte[] Decrypt(byte[] key, byte[] encryptedValue, IKeyNormalizer? keyNormalizer);
}
