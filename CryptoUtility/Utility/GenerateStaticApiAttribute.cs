namespace CryptoUtility;

[AttributeUsage(AttributeTargets.Class)]
public sealed class GenerateStaticApiAttribute : Attribute
{
    public string? Name { get; set; }
}
