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
    /// Encrypts the specified value using the provided key and returns the encrypted data as a byte array.
    /// </summary>
    /// <remarks>
    /// Encryption pads the key if it's too short.
    /// </remarks>
    public byte[] Encrypt(byte[] key, byte[] value, IKeyNormalizer? keyNormalizer);

    /// <summary>
    ///
    /// </summary>
    /// <remarks>
    /// Decryption pads the key for the key if it's too short.
    /// </remarks>
    public byte[] Decrypt(byte[] key, byte[] encryptedValue, IKeyNormalizer? keyNormalizer);
}
