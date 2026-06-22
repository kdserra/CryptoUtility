namespace CryptoUtility;

internal static class LibraryHelper
{
    internal static void ThrowIfAnyNull(params object?[] objects)
    {
        if (objects == null)
        {
            throw new ArgumentNullException();
        }

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
