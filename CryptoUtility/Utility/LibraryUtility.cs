namespace CryptoUtility;

internal static class LibraryUtility
{
    public static bool IsNullOrEmpty<T>(this ICollection<T> collection)
    {
        return collection == null || collection.Count == 0;
    }
}
