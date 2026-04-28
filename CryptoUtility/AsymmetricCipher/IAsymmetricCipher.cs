using System.Text;

namespace CryptoUtility;

/// <summary>
/// Defines an asymmetric cipher that performs public key cryptography.
/// </summary>
public interface IAsymmetricCipher
{
    /// <summary>
    /// Gets the identifier for the asymmetric cipher algorithm associated with this instance.
    /// </summary>
    public AsymmetricCipherID CipherID { get; }

    /// <summary>
    /// Gets the size, in bytes, of the cryptographic key used for encryption and decryption operations.
    /// </summary>
    public int KeySizeBytes { get; }

    /// <summary>
    /// Gets the size, in bytes, of the cryptographic salt used for encryption and decryption operations.
    /// </summary>
    public int SaltSizeBytes { get; }

    /// <summary>
    /// Encrypts the specified plaintext using the provided public key.
    /// </summary>
    /// <param name="publicKey">A byte array containing the public key to use for encryption. Must be a valid, non-null public key compatible
    /// with the encryption algorithm.</param>
    /// <param name="plaintext">A byte array containing the plaintext data to encrypt. Must not be null.</param>
    /// <returns>A tuple containing a Boolean value that indicates whether the encryption was successful, and a byte array with
    /// the encrypted data. The byte array is empty if the encryption fails.</returns>
    public (bool success, byte[] encrypted) Encrypt(byte[] publicKey, byte[] plaintext);

    /// <summary>
    /// Decrypts the specified encrypted data using the provided secret key.
    /// </summary>
    /// <param name="secretKey">The secret key to use for decryption. This key must be valid for the encryption algorithm and cannot be null.</param>
    /// <param name="encrypted">The encrypted data to decrypt. This parameter must be a non-null byte array containing the ciphertext.</param>
    /// <returns>A tuple containing a value indicating whether decryption was successful and a byte array with the decrypted
    /// plaintext. If decryption fails, the plaintext array is empty and the success value is <see langword="false"/>.</returns>
    public (bool success, byte[] plaintext) Decrypt(byte[] secretKey, byte[] encrypted);

    /// <summary>
    /// Generates a new cryptographic key for use in encryption or decryption operations.
    /// </summary>
    /// <returns>A byte array containing the generated cryptographic key.</returns>
    public (byte[] PublicKey, byte[] SecretKey) GenerateKeyPair();
}
