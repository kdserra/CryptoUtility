namespace CryptoUtility;

/// <summary>
/// Defines the contract for asymmetric key encryption and decryption.
/// </summary>
public interface IAsymmetricCipher
{
    /// <summary>
    /// Gets the key size in bytes.
    /// </summary>
    public int KeySizeBytes { get; }

    /// <summary>
    /// Gets the salt size in bytes.
    /// </summary>
    public int SaltSizeBytes { get; }

    /// <summary>
    /// Encrypts the specified plaintext data.
    /// </summary>
    /// <param name="publicKey">The public key.</param>
    /// <param name="plaintext">The plaintext bytes to encrypt.</param>
    /// <returns>A byte array containing the result.</returns>
    public byte[] Encrypt(byte[] publicKey, byte[] plaintext);

    /// <summary>
    /// Decrypts the specified ciphertext data.
    /// </summary>
    /// <param name="secretKey">The private (secret) key.</param>
    /// <param name="encrypted">The encrypted ciphertext bytes.</param>
    /// <returns>A byte array containing the result.</returns>
    public byte[] Decrypt(byte[] secretKey, byte[] encrypted);

    /// <summary>
    /// Generates a new public/private key pair.
    /// </summary>
    /// <returns>A tuple containing the resulting values.</returns>
    public (byte[] publicKey, byte[] secretKey) GenerateKeyPair();
}
