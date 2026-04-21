using MemoryPack;

namespace CryptoUtility;

/// <summary>
/// Defines a version-tolerant envelope format for storing data encrypted with a asymmetric cipher.
/// Encapsulates all required parameters for decryption.
/// </summary>
[MemoryPackable(GenerateType.VersionTolerant)]
public partial class AsymmetricCipherEnvelope
{
    [MemoryPackIgnore]
    public readonly int LatestVersion = 1;

    /// <summary>
    /// Protocol version used to interpret this encrypted payload.
    /// </summary>
    [MemoryPackOrder(0)]
    public readonly int Version;

    /// <summary>
    /// Identifier for the asymmetric cipher algorithm used for encryption.
    /// </summary>
    [MemoryPackOrder(1)]
    public readonly AsymmetricCipherID CipherID;

    /// <summary>
    /// Gets the encrypted data as a byte array.
    /// </summary>
    [MemoryPackOrder(2)]
    public readonly byte[] Ciphertext;

    public AsymmetricCipherEnvelope(int version, AsymmetricCipherID cipherID, byte[] ciphertext)
    {
        Version = version;
        CipherID = cipherID;
        Ciphertext = ciphertext;
    }
}
