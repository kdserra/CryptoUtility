using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CryptoUtility;

/// <summary>
/// Defines an envelope format for storing data encrypted with post-quantum + classical hybrid ciphers.
/// Encapsulates all required parameters for decryption in a raw binary format.
/// </summary>
public class HybridPostQuantumCipherEnvelope
{
    /// <summary>
    /// Gets the post-quantum KEM ciphertext.
    /// </summary>
    public byte[] KemCiphertext { get; }

    /// <summary>
    /// Gets the encrypted data produced by the classical asymmetric cipher.
    /// </summary>
    public byte[] AsymmetricEncrypted { get; }

    /// <summary>
    /// Gets the encrypted data produced by the symmetric cipher.
    /// </summary>
    public byte[] SymmetricEncrypted { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="HybridPostQuantumCipherEnvelope"/> class.
    /// </summary>
    /// <param name="kemCiphertext">The KEM ciphertext payload.</param>
    /// <param name="asymmetricEncrypted">The encrypted asymmetric payload.</param>
    /// <param name="symmetricEncrypted">The encrypted symmetric payload.</param>
    public HybridPostQuantumCipherEnvelope(byte[] kemCiphertext, byte[] asymmetricEncrypted, byte[] symmetricEncrypted)
    {
        KemCiphertext = kemCiphertext ?? throw new ArgumentNullException(nameof(kemCiphertext));
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
    /// Converts the specified HybridPostQuantumCipherEnvelope to its Base64 string representation.
    /// </summary>
    /// <param name="envelope">The envelope instance to convert. This parameter must not be null.</param>
    /// <returns>A Base64-encoded string that represents the serialized form of the envelope.</returns>
    public static string ToBase64(HybridPostQuantumCipherEnvelope envelope)
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
    /// Creates a new instance of the HybridPostQuantumCipherEnvelope class from a Base64-encoded string representation.
    /// </summary>
    /// <param name="envelopeBase64">The Base64-encoded string that represents a serialized envelope.</param>
    /// <returns>A HybridPostQuantumCipherEnvelope object if the input string is valid and conversion succeeds; otherwise, null.</returns>
    public static HybridPostQuantumCipherEnvelope? FromBase64(string envelopeBase64)
    {
        if (string.IsNullOrEmpty(envelopeBase64))
        {
            return null;
        }

        byte[] envelopeBytes = Array.Empty<byte>();
        HybridPostQuantumCipherEnvelope? envelope = null;

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
    /// Serializes the specified HybridPostQuantumCipherEnvelope instance to a byte array.
    /// Layout: [4-byte KEM Length][4-byte Asym Length][KEM Payload][Asym Payload][Sym Payload]
    /// </summary>
    /// <param name="envelope">The envelope to serialize. This parameter must not be null.</param>
    /// <returns>A byte array containing the serialized representation of the envelope.</returns>
    public static byte[] ToBytes(HybridPostQuantumCipherEnvelope envelope)
    {
        LibraryHelper.ThrowIfAnyNull(envelope);

        int length = 8 + envelope.KemCiphertext.Length + envelope.AsymmetricEncrypted.Length + envelope.SymmetricEncrypted.Length;
        byte[] result = new byte[length];

        BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(0, 4), envelope.KemCiphertext.Length);
        BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(4, 4), envelope.AsymmetricEncrypted.Length);

        envelope.KemCiphertext.CopyTo(result, 8);
        envelope.AsymmetricEncrypted.CopyTo(result, 8 + envelope.KemCiphertext.Length);
        envelope.SymmetricEncrypted.CopyTo(result, 8 + envelope.KemCiphertext.Length + envelope.AsymmetricEncrypted.Length);

        return result;
    }

    /// <summary>
    /// Deserializes a byte array into a new instance of the HybridPostQuantumCipherEnvelope class.
    /// </summary>
    /// <param name="envelopeBytes">The byte array containing the serialized envelope data.</param>
    /// <returns>A HybridPostQuantumCipherEnvelope instance if deserialization is successful; otherwise, null.</returns>
    public static HybridPostQuantumCipherEnvelope? FromBytes(byte[] envelopeBytes)
    {
        if (envelopeBytes == null || envelopeBytes.Length < 8)
        {
            return null;
        }

        try
        {
            int kemLength = BinaryPrimitives.ReadInt32BigEndian(envelopeBytes.AsSpan(0, 4));
            int asymLength = BinaryPrimitives.ReadInt32BigEndian(envelopeBytes.AsSpan(4, 4));

            if (kemLength < 0 || asymLength < 0 || 8 + kemLength + asymLength > envelopeBytes.Length)
            {
                return null;
            }

            byte[] kemCiphertext = new byte[kemLength];
            Array.Copy(envelopeBytes, 8, kemCiphertext, 0, kemLength);

            byte[] asymmetricEncrypted = new byte[asymLength];
            Array.Copy(envelopeBytes, 8 + kemLength, asymmetricEncrypted, 0, asymLength);

            int symLength = envelopeBytes.Length - 8 - kemLength - asymLength;
            byte[] symmetricEncrypted = new byte[symLength];
            Array.Copy(envelopeBytes, 8 + kemLength + asymLength, symmetricEncrypted, 0, symLength);

            return new HybridPostQuantumCipherEnvelope(kemCiphertext, asymmetricEncrypted, symmetricEncrypted);
        }
        catch
        {
            return null;
        }
    }
}
