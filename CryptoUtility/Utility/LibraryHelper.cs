namespace CryptoUtility;

/// <summary>
/// Provides utility methods.
/// </summary>
internal static class LibraryHelper
{
    internal static IPasswordKdf? GetPasswordKdfFromID(PasswordKdfID kdfID)
    {
        switch (kdfID)
        {
            case PasswordKdfID.Pbkdf2:
                return Pbkdf2Impl.Shared;
            case PasswordKdfID.None:
            default:
                return null;
        }
    }

    internal static IKeyExpansionKdf? GetKeyExpansionKdfFromID(KeyExpansionKdfID kdfID)
    {
        switch (kdfID)
        {
#if NET8_0_OR_GREATER
            case KeyExpansionKdfID.HkdfSystem:
                return HkdfImpl.Shared;
#endif
            case KeyExpansionKdfID.None:
            default:
                return null;
        }
    }

    internal static ISymmetricCipher? GetSymmetricCipherFromID(SymmetricCipherID cipherID)
    {
        switch (cipherID)
        {
            case SymmetricCipherID.Aes128GcmSystem:
                return Aes128GcmImpl.Shared;
            case SymmetricCipherID.Aes192GcmSystem:
                return Aes192GcmImpl.Shared;
            case SymmetricCipherID.Aes256GcmSystem:
                return Aes256GcmImpl.Shared;
#if NET8_0_OR_GREATER
            case SymmetricCipherID.ChaCha20Poly1305System:
                return ChaCha20Poly1305Impl.Shared;
#endif
            case SymmetricCipherID.XorCipherStandard:
                return XorCipherImpl.Shared;
            case SymmetricCipherID.None:
            default:
                return null;
        }
    }

    internal static IAsymmetricCipher? GetAsymmetricCipherFromID(AsymmetricCipherID cipherID)
    {
        switch (cipherID)
        {
#if NET8_0_OR_GREATER
            case AsymmetricCipherID.Rsa1024System:
                return Rsa1024Impl.Shared;
            case AsymmetricCipherID.Rsa2048System:
                return Rsa2048Impl.Shared;
            case AsymmetricCipherID.Rsa3072System:
                return Rsa3072Impl.Shared;
            case AsymmetricCipherID.Rsa4096System:
                return Rsa4096Impl.Shared;
#endif
            case AsymmetricCipherID.None:
            default:
                return null;
        }
    }

    internal static bool NotNull(params object?[] objects)
    {
        foreach (object? obj in objects)
        {
            if (obj == null)
            {
                return false;
            }
        }

        return true;
    }

    internal static bool NotNullOrEmpty(params object?[] objects)
    {
        foreach (var obj in objects)
        {
            if (obj == null)
                return false;

            if (obj is string str && string.IsNullOrEmpty(str))
                return false;

            if (
                obj is System.Collections.IEnumerable enumerable
                && !enumerable.Cast<object>().Any()
            )
                return false;
        }

        return true;
    }

    internal static void ThrowIfAnyNull(params object?[] objects)
    {
        foreach (object? obj in objects)
        {
            if (obj == null)
            {
                throw new InvalidOperationException();
            }
        }
    }

    internal static bool IsNullOrEmpty<T>(this ICollection<T> collection)
    {
        return collection == null || collection.Count == 0;
    }
}
