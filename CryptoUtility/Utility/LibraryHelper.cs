using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace CryptoUtility;

internal static class LibraryHelper
{
    internal static void ThrowIfNull(
        [NotNull] object? argument,
        [CallerArgumentExpression(nameof(argument))] string? paramName = null
    )
    {
        if (argument is null)
        {
            throw new ArgumentNullException(paramName);
        }
    }
}
