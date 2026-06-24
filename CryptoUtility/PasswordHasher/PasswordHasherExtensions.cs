namespace CryptoUtility;

/// <summary>
/// Provides extension methods for the <see cref="IPasswordHasher"/> interface.
/// </summary>
public static class PasswordHasherExtensions
{
    /// <summary>
    /// Attempts to hash the specified password, catching any exceptions.
    /// </summary>
    /// <param name="hasher">The password hasher instance.</param>
    /// <param name="password">The plaintext password to hash.</param>
    /// <param name="hashedPasswordString">The resulting PHC formatted hash string, or an empty string on failure.</param>
    /// <returns><c>true</c> if hashing succeeded; otherwise, <c>false</c>.</returns>
    public static bool TryHashPassword(
        this IPasswordHasher hasher,
        string password,
        out string hashedPasswordString
    )
    {
        LibraryHelper.ThrowIfAnyNull(hasher);
        try
        {
            hashedPasswordString = hasher.HashPassword(password);
            return true;
        }
        catch
        {
            hashedPasswordString = string.Empty;
            return false;
        }
    }

    /// <summary>
    /// Attempts to verify the specified password against a hash string, catching any exceptions.
    /// </summary>
    /// <param name="hasher">The password hasher instance.</param>
    /// <param name="password">The plaintext password to verify.</param>
    /// <param name="hashedPasswordString">The PHC formatted hash string.</param>
    /// <returns><c>true</c> if verification succeeded and the password is correct; otherwise, <c>false</c>.</returns>
    public static bool TryVerifyPassword(
        this IPasswordHasher hasher,
        string password,
        string hashedPasswordString
    )
    {
        LibraryHelper.ThrowIfAnyNull(hasher);
        try
        {
            return hasher.VerifyPassword(password, hashedPasswordString);
        }
        catch
        {
            return false;
        }
    }
}
