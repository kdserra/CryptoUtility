namespace CryptoUtility;

/// <summary>
/// Defines the post-quantum Key Encapsulation Mechanism (KEM) contract.
/// </summary>
public interface IKeyEncapsulationMechanism
{
    /// <summary>
    /// Gets the size of the public key in bytes.
    /// </summary>
    public int PublicKeySizeBytes { get; }

    /// <summary>
    /// Gets the size of the secret (private) key in bytes.
    /// </summary>
    public int SecretKeySizeBytes { get; }

    /// <summary>
    /// Gets the size of the KEM ciphertext in bytes.
    /// </summary>
    public int CiphertextSizeBytes { get; }

    /// <summary>
    /// Gets the size of the derived shared secret in bytes.
    /// </summary>
    public int SharedSecretSizeBytes { get; }

    /// <summary>
    /// Generates a new key pair for the KEM.
    /// </summary>
    /// <returns>A tuple containing the public key and secret (private) key.</returns>
    public (byte[] publicKey, byte[] secretKey) GenerateKeyPair();

    /// <summary>
    /// Encapsulates a shared secret using the peer's public key.
    /// </summary>
    /// <param name="peerPublicKey">The peer's public key bytes.</param>
    /// <returns>A tuple containing the derived shared secret and the encapsulated ciphertext.</returns>
    public (byte[] sharedSecret, byte[] ciphertext) Encapsulate(byte[] peerPublicKey);

    /// <summary>
    /// Decapsulates the ciphertext using the secret key to recover the shared secret.
    /// </summary>
    /// <param name="secretKey">The secret (private) key bytes.</param>
    /// <param name="ciphertext">The encapsulated ciphertext bytes.</param>
    /// <returns>The recovered shared secret bytes.</returns>
    public byte[] Decapsulate(byte[] secretKey, byte[] ciphertext);
}
