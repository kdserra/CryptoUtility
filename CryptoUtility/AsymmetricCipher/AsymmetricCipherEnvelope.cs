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
    public const int LatestVersion = 1;

    /// <summary>
    /// Protocol version used to interpret this encrypted payload.
    /// </summary>
    [MemoryPackOrder(0)]
    public readonly int Version;

    /// <summary>
    /// Gets the identifier of the asymmetric cipher used for cryptographic operations.
    /// </summary>
    [MemoryPackOrder(1)]
    public readonly AsymmetricCipherID CipherID;

    /// <summary>
    /// The encrypted data produced by the cipher.
    /// </summary>
    /// <remarks>
    /// This field is used in all asymmetric ciphers.
    /// It may be an empty byte array if the payload is invalid, but it will never be null.
    /// </remarks>
    [MemoryPackOrder(2)]
    public readonly byte[] Ciphertext;

    [MemoryPackConstructor]
    public AsymmetricCipherEnvelope(int version, AsymmetricCipherID cipherID, byte[] ciphertext)
    {
        Version = version;
        cipherID = CipherID;
        Ciphertext = ciphertext;
        LibraryHelper.ThrowIfAnyNull(version, cipherID, ciphertext);
    }

    /// <summary>
    /// Converts the current instance to its serialized byte array representation.
    /// </summary>
    /// <returns>A byte array containing the serialized data of the current instance.</returns>
    public byte[] ToBytes()
    {
        byte[] bytes = ToBytes(this);
        return bytes;
    }

    /// <summary>
    /// Converts the current instance to its Base64 string representation.
    /// </summary>
    /// <returns>A Base64-encoded string that represents the current instance.</returns>
    public string ToBase64()
    {
        string base64 = ToBase64(this);
        return base64;
    }

    /// <summary>
    /// Converts the specified HybridCipherEnvelope to its Base64 string representation.
    /// </summary>
    /// <param name="envelope">The HybridCipherEnvelope instance to convert. This parameter must not be null.</param>
    /// <returns>A Base64-encoded string that represents the serialized form of the envelope.</returns>
    public static string ToBase64(AsymmetricCipherEnvelope envelope)
    {
        byte[] envelopeBytes = ToBytes(envelope);
        string envelopeBase64 = Convert.ToBase64String(envelopeBytes);
        return envelopeBase64;
    }

    /// <summary>
    /// Creates a new instance of the HybridCipherEnvelope class from a Base64-encoded string representation.
    /// </summary>
    /// <param name="envelopeBase64">The Base64-encoded string that represents a serialized HybridCipherEnvelope. This value must be a valid Base64
    /// string.</param>
    /// <returns>A HybridCipherEnvelope object if the input string is valid and conversion succeeds; otherwise, null.</returns>
    public static AsymmetricCipherEnvelope? FromBase64(string envelopeBase64)
    {
        byte[] envelopeBytes = Convert.FromBase64String(envelopeBase64);
        AsymmetricCipherEnvelope? envelope = FromBytes(envelopeBytes);
        return envelope;
    }

    /// <summary>
    /// Serializes the specified HybridCipherEnvelope instance to a byte array.
    /// </summary>
    /// <param name="envelope">The HybridCipherEnvelope to serialize. This parameter must not be null.</param>
    /// <returns>A byte array containing the serialized representation of the envelope.</returns>
    public static byte[] ToBytes(AsymmetricCipherEnvelope envelope)
    {
        byte[] result = MemoryPackSerializer.Serialize(envelope);
        return result;
    }

    /// <summary>
    /// Deserializes a byte array into a new instance of the HybridCipherEnvelope class.
    /// </summary>
    /// <param name="envelopeBytes">The byte array containing the serialized HybridCipherEnvelope data. This parameter must not be null.</param>
    /// <returns>A HybridCipherEnvelope instance if deserialization is successful; otherwise, null.</returns>
    public static AsymmetricCipherEnvelope? FromBytes(byte[] envelopeBytes)
    {
        try
        {
            AsymmetricCipherEnvelope? result =
                MemoryPackSerializer.Deserialize<AsymmetricCipherEnvelope>(envelopeBytes);

            return result;
        }
        catch
        {
            return null;
        }
    }
}
