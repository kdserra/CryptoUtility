namespace CryptoUtility;

internal static class LibraryHelper
{
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
                throw new ArgumentNullException();
            }
        }
    }

    internal static bool IsNullOrEmpty<T>(this ICollection<T> collection)
    {
        return collection == null || collection.Count == 0;
    }
}
