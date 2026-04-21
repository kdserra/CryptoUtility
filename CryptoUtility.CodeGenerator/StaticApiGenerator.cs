using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace CryptoUtility.CodeGenerator;

[Generator]
public sealed class StaticApiGenerator : IIncrementalGenerator
{
    public void Initialize(IncrementalGeneratorInitializationContext context)
    {
        var impls = context
            .SyntaxProvider.CreateSyntaxProvider(
                predicate: static (node, _) => node is ClassDeclarationSyntax,
                transform: static (ctx, _) => GetCandidate(ctx)
            )
            .Where(static x => x is not null);

        context.RegisterSourceOutput(
            impls,
            static (spc, symbol) =>
            {
                var source = Generate(symbol!);
                spc.AddSource($"{symbol!.Name}.g.cs", source);
            }
        );
    }

    private static INamedTypeSymbol? GetCandidate(GeneratorSyntaxContext ctx)
    {
        var classDecl = (ClassDeclarationSyntax)ctx.Node;
        var symbol = ctx.SemanticModel.GetDeclaredSymbol(classDecl) as INamedTypeSymbol;

        if (symbol is null)
            return null;

        var attr = symbol
            .GetAttributes()
            .FirstOrDefault(a => a.AttributeClass?.Name == "GenerateStaticApiAttribute");

        return attr is null ? null : symbol;
    }

    private static string Generate(INamedTypeSymbol symbol)
    {
        var ns = symbol.ContainingNamespace.ToDisplayString();
        var apiName = symbol.Name.Replace("Impl", "");
        var implName = symbol.Name;

        var sb = new StringBuilder();

        sb.AppendLine($"#nullable enable");
        sb.AppendLine($"namespace {ns};");
        sb.AppendLine();

        sb.AppendLine($"/// <inheritdoc cref=\"{implName}\" />");
        sb.AppendLine($"public static partial class {apiName}");
        sb.AppendLine("{");

        sb.AppendLine($"    private static readonly {implName} s_Cipher = new {implName}();");
        sb.AppendLine();

        foreach (var member in GetAllPublicMembers(symbol))
        {
            if (member is IMethodSymbol method && method.MethodKind == MethodKind.Ordinary)
            {
                if (method.ContainingType.SpecialType == SpecialType.System_Object)
                    continue;

                EmitMethod(sb, method);
            }
            else if (member is IPropertySymbol prop)
            {
                EmitProperty(sb, prop);
            }
        }

        sb.AppendLine("}");
        return sb.ToString();
    }

    private static void EmitMethod(StringBuilder sb, IMethodSymbol method)
    {
        var returnType = method.ReturnType.ToDisplayString();
        var name = method.Name;

        var parameters = string.Join(
            ", ",
            method.Parameters.Select(p => $"{p.Type.ToDisplayString()} {p.Name}")
        );

        var args = string.Join(", ", method.Parameters.Select(p => p.Name));

        sb.AppendLine(
            $"    /// <inheritdoc cref=\"{method.ContainingType.Name}.{method.Name}\" />"
        );
        sb.AppendLine($"    public static {returnType} {name}({parameters})");
        sb.AppendLine($"        => s_Cipher.{name}({args});");
        sb.AppendLine();
    }

    private static void EmitProperty(StringBuilder sb, IPropertySymbol prop)
    {
        var type = prop.Type.ToDisplayString();
        var name = prop.Name;

        sb.AppendLine($"    /// <inheritdoc cref=\"{prop.ContainingType.Name}.{prop.Name}\" />");

        if (prop.IsReadOnly)
        {
            sb.AppendLine($"    public static {type} {name} => s_Cipher.{name};");
        }
        else
        {
            sb.AppendLine($"    public static {type} {name}");
            sb.AppendLine("    {");
            sb.AppendLine($"        get => s_Cipher.{name};");
            sb.AppendLine($"        set => s_Cipher.{name} = value;");
            sb.AppendLine("    }");
        }

        sb.AppendLine();
    }

    private static IEnumerable<ISymbol> GetAllPublicMembers(INamedTypeSymbol symbol)
    {
        var seen = new HashSet<string>();

        for (INamedTypeSymbol? type = symbol; type is not null; type = type.BaseType)
        {
            foreach (var member in type.GetMembers())
            {
                if (member.DeclaredAccessibility != Accessibility.Public)
                    continue;

                var key = member switch
                {
                    IMethodSymbol m =>
                        $"{m.Name}({string.Join(",", m.Parameters.Select(p => p.Type.ToDisplayString()))})",

                    IPropertySymbol p => p.Name,

                    _ => member.Name,
                };

                if (!seen.Add(key))
                    continue;

                yield return member;
            }
        }
    }
}
