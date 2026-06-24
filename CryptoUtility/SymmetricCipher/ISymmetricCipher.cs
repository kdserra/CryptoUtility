namespace CryptoUtility;
    /// <summary>
    /// Defines the contract for symmetric key encryption and decryption.
    /// </summary>

public interface ISymmetricCipher
{
    /// <summary>
    /// Gets the key size in bytes.
    /// </summary>
    public int KeySizeBytes { get; }
    /// <summary>
    /// Gets the nonce (initialization vector) size in bytes.
    /// </summary>

    public int NonceSizeBytes { get; }
    /// <summary>
    /// Encrypts the specified plaintext data.
    /// </summary>
    /// <param name="key">The symmetric key.</param>
    /// <param name="plaintext">The plaintext bytes to encrypt.</param>
    /// <param name="nonce">The initialization vector (nonce).</param>
    /// <returns>A byte array containing the result.</returns>

    public byte[] Encrypt(byte[] key, byte[] plaintext, byte[] nonce);
    /// <summary>
    /// Decrypts the specified ciphertext data.
    /// </summary>
    /// <param name="key">The symmetric key.</param>
    /// <param name="encrypted">The encrypted ciphertext bytes.</param>
    /// <returns>A byte array containing the result.</returns>

    public byte[] Decrypt(byte[] key, byte[] encrypted);
}
