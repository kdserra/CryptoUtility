using NaClPoly1305 = NaCl.Core.Poly1305;

namespace CryptoUtility.NaCl;
    /// <summary>
    /// Represents the poly1305 implementation.
    /// </summary>

[GenerateStaticApi]
public sealed class Poly1305Impl : IMacProvider
{
    /// <summary>
    /// Gets the shared instance.
    /// </summary>
    public static readonly Poly1305Impl Shared = new();
    /// <summary>
    /// Gets the required key size in bytes, or 0 if variable-length keys are accepted.
    /// </summary>

    public int RequiredKeySizeInBytes => 32;
    /// <summary>
    /// Gets the size of the computed MAC in bytes.
    /// </summary>

    public int MacSizeInBytes => 16;
    /// <summary>
    /// Computes the Message Authentication Code (MAC) for the specified message using the provided key.
    /// </summary>
    /// <param name="key">The symmetric key.</param>
    /// <param name="message">The input data to process.</param>
    /// <returns>A byte array containing the result.</returns>

    public byte[] ComputeMac(byte[] key, byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(key, message);

        return NaClPoly1305.ComputeMac(key, message);
    }
}
