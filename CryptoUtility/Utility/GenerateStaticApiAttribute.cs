namespace CryptoUtility;

[AttributeUsage(AttributeTargets.Class)]
public sealed class GenerateStaticApiAttribute : Attribute
{
    public readonly string Name;

    public GenerateStaticApiAttribute(string name)
    {
        Name = name;
    }
}
