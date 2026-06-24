using System;

namespace CryptoUtility;

/// <summary>
/// Provides Base64 encoding and decoding using the custom Argon2 B64 alphabet:
/// `./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz`
/// as defined by the PHC string format specification.
/// </summary>
public static class PhcB64
{
    private const string StdAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    private const string ArgAlphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    private static readonly char[] StdToArgMap = new char[256];
    private static readonly char[] ArgToStdMap = new char[256];

    static PhcB64()
    {
        for (int i = 0; i < 256; i++)
        {
            StdToArgMap[i] = '\0';
            ArgToStdMap[i] = '\0';
        }

        for (int i = 0; i < 64; i++)
            StdToArgMap[StdAlphabet[i]] = ArgAlphabet[i];

        for (int i = 0; i < 64; i++)
            ArgToStdMap[ArgAlphabet[i]] = StdAlphabet[i];
    }

    /// <summary>
    /// Encodes the specified byte array into a PHC-compliant Base64 string (no padding, custom alphabet).
    /// </summary>
    public static string ToB64String(byte[] data)
    {
        LibraryHelper.ThrowIfAnyNull(data);
        if (data.Length == 0)
            return string.Empty;

        string stdBase64 = Convert.ToBase64String(data).TrimEnd('=');
        char[] chars = stdBase64.ToCharArray();

        for (int i = 0; i < chars.Length; i++)
        {
            char mapped = StdToArgMap[chars[i]];
            if (mapped == '\0')
                throw new InvalidOperationException($"Invalid standard Base64 character: {chars[i]}");
            chars[i] = mapped;
        }

        return new string(chars);
    }

    /// <summary>
    /// Decodes a PHC-compliant Base64 string (no padding, custom alphabet) back to a byte array.
    /// </summary>
    public static byte[] FromB64String(string text)
    {
        LibraryHelper.ThrowIfAnyNull(text);
        if (text.Length == 0)
            return Array.Empty<byte>();

        char[] chars = text.ToCharArray();
        for (int i = 0; i < chars.Length; i++)
        {
            char mapped = ArgToStdMap[chars[i]];
            if (mapped == '\0')
                throw new ArgumentException($"Invalid Argon2 B64 character: {chars[i]}");
            chars[i] = mapped;
        }

        string stdBase64 = new string(chars);
        int padding = (4 - (stdBase64.Length % 4)) % 4;
        if (padding > 0)
        {
            stdBase64 += new string('=', padding);
        }

        return Convert.FromBase64String(stdBase64);
    }
}
