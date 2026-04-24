using System.Text;

namespace CryptoUtility;

internal abstract class DigitalSignature
{
    /// <summary>
    /// Signs the specified message using the provided secret key and returns a value indicating whether the operation
    /// was successful along with the generated signature.
    /// </summary>
    /// <param name="message">The message to sign, represented as a byte array. This parameter must not be null or empty.</param>
    /// <param name="secretKey">The secret key used to sign the message, represented as a byte array. This parameter must not be null or empty.</param>
    /// <returns>A tuple containing a boolean that indicates whether the signing operation succeeded, and a byte array containing
    /// the generated signature. If the operation fails, the signature array will be empty.</returns>
    public abstract (bool success, byte[] signature) Sign(byte[] message, byte[] secretKey);

    /// <summary>
    /// Verifies the authenticity of a message using the specified digital signature and public key.
    /// </summary>
    /// <param name="message">The byte array containing the message whose signature is to be verified.</param>
    /// <param name="signature">The byte array that holds the digital signature to validate against the message.</param>
    /// <param name="publicKey">The byte array representing the public key to use for signature verification.</param>
    /// <returns>true if the signature is valid for the given message and public key; otherwise, false.</returns>
    public abstract bool Verify(byte[] message, byte[] signature, byte[] publicKey);

    public (bool success, string signature) SignBase64(string message, string secretKey)
    {
        if (!LibraryHelper.NotNull(message, secretKey))
        {
            return (false, string.Empty);
        }

        byte[] messageBytes = Encoding.UTF8.GetBytes(message);
        byte[] secretKeyBytes = Convert.FromBase64String(secretKey);

        (bool success, byte[] signatureBytes) = Sign(messageBytes, secretKeyBytes);
        string signature = Convert.ToBase64String(signatureBytes);

        return (success, signature);
    }

    public bool VerifyBase64(string message, string signature, string publicKey)
    {
        if (!LibraryHelper.NotNull(message, signature, publicKey))
        {
            return false;
        }

        byte[] messageBytes = Encoding.UTF8.GetBytes(message);
        byte[] signatureBytes = Convert.FromBase64String(signature);
        byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
        bool isValid = Verify(messageBytes, signatureBytes, publicKeyBytes);

        return isValid;
    }
}
