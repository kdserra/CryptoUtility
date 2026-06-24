using Org.BouncyCastle.Crypto.Generators;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle Bcrypt Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class BcryptImpl : IPasswordHasher
{
    /// <summary>
    /// Shared static instance of <see cref="BcryptImpl"/>.
    /// </summary>
    public static readonly BcryptImpl Shared = new();

    private readonly int _defaultCost;

    /// <summary>
    /// Initializes a new instance of the <see cref="BcryptImpl"/> class with secure default cost (12).
    /// </summary>
    public BcryptImpl() : this(12)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="BcryptImpl"/> class with custom cost.
    /// </summary>
    /// <param name="defaultCost">The work factor (cost) between 4 and 31.</param>
    public BcryptImpl(int defaultCost)
    {
        if (defaultCost < 4 || defaultCost > 31)
            throw new ArgumentOutOfRangeException(nameof(defaultCost), "Cost must be between 4 and 31.");
        _defaultCost = defaultCost;
    }

    /// <inheritdoc />
    public string HashPassword(string password)
    {
        LibraryHelper.ThrowIfAnyNull(password);
        byte[] salt = CryptoHelper.GetBytes(16); // Bcrypt requires exactly 16 bytes of salt
        char[] passwordChars = password.ToCharArray();
        try
        {
            return OpenBsdBCrypt.Generate("2a", passwordChars, salt, _defaultCost);
        }
        finally
        {
            Array.Clear(passwordChars, 0, passwordChars.Length);
        }
    }

    /// <inheritdoc />
    public bool VerifyPassword(string password, string hashedPasswordString)
    {
        LibraryHelper.ThrowIfAnyNull(password, hashedPasswordString);
        char[] passwordChars = password.ToCharArray();
        try
        {
            return OpenBsdBCrypt.CheckPassword(hashedPasswordString, passwordChars);
        }
        catch
        {
            return false;
        }
        finally
        {
            Array.Clear(passwordChars, 0, passwordChars.Length);
        }
    }
}
