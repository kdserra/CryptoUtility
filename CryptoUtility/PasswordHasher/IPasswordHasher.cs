namespace CryptoUtility;

/// <summary>
/// Defines a contract for hashing and verifying passwords using standard PHC string formats.
/// </summary>
public interface IPasswordHasher
{
    /// <summary>
    /// Hashes the specified password and returns a PHC formatted string.
    /// </summary>
    /// <param name="password">The plaintext password to hash.</param>
    /// <returns>A PHC formatted hash string containing the algorithm identifier, parameters, salt, and hash.</returns>
    public string HashPassword(string password);

    /// <summary>
    /// Verifies the specified password against a PHC formatted hash string.
    /// </summary>
    /// <param name="password">The plaintext password to verify.</param>
    /// <param name="hashedPasswordString">The PHC formatted hash string.</param>
    /// <returns><c>true</c> if the password matches the hash; otherwise, <c>false</c>.</returns>
    public bool VerifyPassword(string password, string hashedPasswordString);
}
