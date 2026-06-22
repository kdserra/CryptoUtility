using System.Security.Cryptography;
using CryptoUtility;
using MemoryPack;

/// <summary>
/// Defines a version-tolerant envelope format for storing data encrypted with mixed ciphers.
/// Encapsulates all required parameters for decryption.
/// </summary>
[MemoryPackable(GenerateType.VersionTolerant)]
public partial class HybridCipherEnvelope
{
    [MemoryPackIgnore]
    public const int LatestVersion = 1;

    /// <summary>
    /// Protocol version used to interpret this encrypted payload.
    /// </summary>
    [MemoryPackOrder(0)]
    public readonly int Version;

    /// <summary>
    /// The encrypted data produced by the asymmetric cipher, containing the ciphertext.
    /// </summary>
    /// <remarks>
    /// This is the bytes of the <see cref="AsymmetricCipherEnvelope"/>, which itself contains the asymmetric ciphertext.
    /// It may be an empty byte array if the payload is invalid, but it will never be null.
    /// </remarks>
    [MemoryPackOrder(1)]
    public readonly byte[] AsymmetricEncrypted;

    /// <summary>
    /// The encrypted data produced by the symmetric cipher, containing the ciphertext.
    /// </summary>
    /// <remarks>
    /// This is the bytes of the <see cref="SymmetricCipherEnvelope"/>, which itself contains the symmetric ciphertext.
    /// It may be an empty byte array if the payload is invalid, but it will never be null.
    /// </remarks>
    [MemoryPackOrder(2)]
    public readonly byte[] SymmetricEncrypted;

    [MemoryPackConstructor]
    public HybridCipherEnvelope(int version, byte[] asymmetricEncrypted, byte[] symmetricEncrypted)
    {
        Version = version;
        AsymmetricEncrypted = asymmetricEncrypted;
        SymmetricEncrypted = symmetricEncrypted;

        LibraryHelper.ThrowIfAnyNull(version, asymmetricEncrypted, symmetricEncrypted);
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
    public static string ToBase64(HybridCipherEnvelope envelope)
    {
        byte[] envelopeBytes = ToBytes(envelope);
        string envelopeBase64 = Convert.ToBase64String(envelopeBytes);

        CryptographicOperations.ZeroMemory(envelopeBytes);

        return envelopeBase64;
    }

    /// <summary>
    /// Creates a new instance of the HybridCipherEnvelope class from a Base64-encoded string representation.
    /// </summary>
    /// <param name="envelopeBase64">The Base64-encoded string that represents a serialized HybridCipherEnvelope. This value must be a valid Base64
    /// string.</param>
    /// <returns>A HybridCipherEnvelope object if the input string is valid and conversion succeeds; otherwise, null.</returns>
    public static HybridCipherEnvelope? FromBase64(string envelopeBase64)
    {
        byte[] envelopeBytes = Convert.FromBase64String(envelopeBase64);

        HybridCipherEnvelope? envelope = FromBytes(envelopeBytes);

        CryptographicOperations.ZeroMemory(envelopeBytes);

        return envelope;
    }

    /// <summary>
    /// Serializes the specified HybridCipherEnvelope instance to a byte array.
    /// </summary>
    /// <param name="envelope">The HybridCipherEnvelope to serialize. This parameter must not be null.</param>
    /// <returns>A byte array containing the serialized representation of the envelope.</returns>
    public static byte[] ToBytes(HybridCipherEnvelope envelope)
    {
        byte[] result = MemoryPackSerializer.Serialize(envelope);
        return result;
    }

    /// <summary>
    /// Deserializes a byte array into a new instance of the HybridCipherEnvelope class.
    /// </summary>
    /// <param name="envelopeBytes">The byte array containing the serialized HybridCipherEnvelope data. This parameter must not be null.</param>
    /// <returns>A HybridCipherEnvelope instance if deserialization is successful; otherwise, null.</returns>
    public static HybridCipherEnvelope? FromBytes(byte[] envelopeBytes)
    {
        try
        {
            HybridCipherEnvelope? result = MemoryPackSerializer.Deserialize<HybridCipherEnvelope>(
                envelopeBytes
            );

            return result;
        }
        catch
        {
            return null;
        }
    }
}
