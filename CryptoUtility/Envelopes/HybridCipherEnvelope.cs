using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CryptoUtility;

/// <summary>
/// Defines an envelope format for storing data encrypted with hybrid ciphers.
/// Encapsulates all required parameters for decryption in a raw binary format.
/// </summary>
public class HybridCipherEnvelope
{
    /// <summary>
    /// Gets the encrypted data produced by the asymmetric cipher.
    /// </summary>
    public byte[] AsymmetricEncrypted { get; }

    /// <summary>
    /// Gets the encrypted data produced by the symmetric cipher.
    /// </summary>
    public byte[] SymmetricEncrypted { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="HybridCipherEnvelope"/> class.
    /// </summary>
    /// <param name="asymmetricEncrypted">The encrypted asymmetric payload.</param>
    /// <param name="symmetricEncrypted">The encrypted symmetric payload.</param>
    public HybridCipherEnvelope(byte[] asymmetricEncrypted, byte[] symmetricEncrypted)
    {
        AsymmetricEncrypted = asymmetricEncrypted ?? throw new ArgumentNullException(nameof(asymmetricEncrypted));
        SymmetricEncrypted = symmetricEncrypted ?? throw new ArgumentNullException(nameof(symmetricEncrypted));
    }

    /// <summary>
    /// Converts the current instance to its serialized byte array representation.
    /// </summary>
    /// <returns>A byte array containing the serialized data of the current instance.</returns>
    public byte[] ToBytes()
    {
        return ToBytes(this);
    }

    /// <summary>
    /// Converts the current instance to its Base64 string representation.
    /// </summary>
    /// <returns>A Base64-encoded string that represents the current instance.</returns>
    public string ToBase64()
    {
        return ToBase64(this);
    }

    /// <summary>
    /// Converts the specified HybridCipherEnvelope to its Base64 string representation.
    /// </summary>
    /// <param name="envelope">The HybridCipherEnvelope instance to convert. This parameter must not be null.</param>
    /// <returns>A Base64-encoded string that represents the serialized form of the envelope.</returns>
    public static string ToBase64(HybridCipherEnvelope envelope)
    {
        LibraryHelper.ThrowIfAnyNull(envelope);
        byte[] envelopeBytes = Array.Empty<byte>();
        string envelopeBase64 = string.Empty;

        try
        {
            envelopeBytes = ToBytes(envelope);
            envelopeBase64 = Convert.ToBase64String(envelopeBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(envelopeBytes);
        }

        return envelopeBase64;
    }

    /// <summary>
    /// Creates a new instance of the HybridCipherEnvelope class from a Base64-encoded string representation.
    /// </summary>
    /// <param name="envelopeBase64">The Base64-encoded string that represents a serialized HybridCipherEnvelope. This value must be a valid Base64 string.</param>
    /// <returns>A HybridCipherEnvelope object if the input string is valid and conversion succeeds; otherwise, null.</returns>
    public static HybridCipherEnvelope? FromBase64(string envelopeBase64)
    {
        if (string.IsNullOrEmpty(envelopeBase64))
        {
            return null;
        }

        byte[] envelopeBytes = Array.Empty<byte>();
        HybridCipherEnvelope? envelope = null;

        try
        {
            envelopeBytes = Convert.FromBase64String(envelopeBase64);
            envelope = FromBytes(envelopeBytes);
        }
        catch
        {
            return null;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(envelopeBytes);
        }

        return envelope;
    }

    /// <summary>
    /// Serializes the specified HybridCipherEnvelope instance to a byte array.
    /// Layout: [4-byte AsymEncrypted Length][AsymEncrypted Payload][SymEncrypted Payload]
    /// </summary>
    /// <param name="envelope">The HybridCipherEnvelope to serialize. This parameter must not be null.</param>
    /// <returns>A byte array containing the serialized representation of the envelope.</returns>
    public static byte[] ToBytes(HybridCipherEnvelope envelope)
    {
        LibraryHelper.ThrowIfAnyNull(envelope);

        int length = 4 + envelope.AsymmetricEncrypted.Length + envelope.SymmetricEncrypted.Length;
        byte[] result = new byte[length];

        BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(0, 4), envelope.AsymmetricEncrypted.Length);

        envelope.AsymmetricEncrypted.CopyTo(result, 4);
        envelope.SymmetricEncrypted.CopyTo(result, 4 + envelope.AsymmetricEncrypted.Length);

        return result;
    }

    /// <summary>
    /// Deserializes a byte array into a new instance of the HybridCipherEnvelope class.
    /// </summary>
    /// <param name="envelopeBytes">The byte array containing the serialized HybridCipherEnvelope data. This parameter must not be null.</param>
    /// <returns>A HybridCipherEnvelope instance if deserialization is successful; otherwise, null.</returns>
    public static HybridCipherEnvelope? FromBytes(byte[] envelopeBytes)
    {
        if (envelopeBytes == null || envelopeBytes.Length < 4)
        {
            return null;
        }

        try
        {
            int asymLength = BinaryPrimitives.ReadInt32BigEndian(envelopeBytes.AsSpan(0, 4));

            if (asymLength < 0 || 4 + asymLength > envelopeBytes.Length)
            {
                return null;
            }

            byte[] asymmetricEncrypted = new byte[asymLength];
            Array.Copy(envelopeBytes, 4, asymmetricEncrypted, 0, asymLength);

            int symLength = envelopeBytes.Length - 4 - asymLength;
            byte[] symmetricEncrypted = new byte[symLength];
            Array.Copy(envelopeBytes, 4 + asymLength, symmetricEncrypted, 0, symLength);

            return new HybridCipherEnvelope(asymmetricEncrypted, symmetricEncrypted);
        }
        catch
        {
            return null;
        }
    }
}
