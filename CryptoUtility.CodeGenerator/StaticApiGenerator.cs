using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
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

        var compilationAndTypes = context.CompilationProvider.Combine(impls.Collect());

        context.RegisterSourceOutput(
            compilationAndTypes,
            static (spc, pair) =>
            {
                var (compilation, types) = pair;

                foreach (var symbol in types)
                {
                    var methods = GetNormalizedExtensionMethods(compilation, symbol!);
                    var source = Generate(symbol!, methods);
                    spc.AddSource($"{symbol!.Name}.g.cs", source);
                }
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

    private static List<NormalizedMethod> GetNormalizedExtensionMethods(
        Compilation compilation,
        INamedTypeSymbol targetType
    )
    {
        return GetAllTypes(compilation.Assembly.GlobalNamespace)
            .SelectMany(t => t.GetMembers())
            .OfType<IMethodSymbol>()
            .Where(m =>
                m.IsExtensionMethod
                && m.MethodKind == MethodKind.Ordinary
                && m.Parameters.Length > 0
                && compilation.ClassifyConversion(targetType, m.Parameters[0].Type).IsImplicit
            )
            .Select(m =>
            {
                var nonReceiverParams = m.Parameters.Skip(1).ToArray();
                var isInjected = nonReceiverParams
                    .Select(p => compilation.ClassifyConversion(targetType, p.Type).IsImplicit)
                    .ToArray();

                return new NormalizedMethod(m, nonReceiverParams, isInjected);
            })
            .ToList();
    }

    private readonly record struct NormalizedMethod(
        IMethodSymbol Symbol,
        IParameterSymbol[] ParametersWithoutReceiver,
        bool[] IsInjected
    );

    private static string Generate(INamedTypeSymbol symbol, List<NormalizedMethod> extensionMethods)
    {
        var ns = symbol.ContainingNamespace.ToDisplayString();
        var apiName = symbol.Name.Replace("Impl", "");
        var implName = symbol.Name;

        var sb = new StringBuilder();

        sb.AppendLine("#nullable enable");
        sb.AppendLine($"namespace {ns};");
        sb.AppendLine();

        sb.AppendLine($"/// <inheritdoc cref=\"{implName}\" />");
        sb.AppendLine($"public static partial class {apiName}");
        sb.AppendLine("{");

        sb.AppendLine($"    public static readonly {implName} Shared = {implName}.Shared;");
        sb.AppendLine();

        var generatedSignatures = new HashSet<string>();

        foreach (var member in GetAllPublicMembers(symbol))
        {
            if (member is IMethodSymbol method && method.MethodKind == MethodKind.Ordinary)
            {
                if (ShouldSkipMethod(method))
                    continue;

                var sigKey = GetSignatureKey(method.Name, method.Parameters);
                if (!generatedSignatures.Add(sigKey))
                    continue;

                EmitMethod(sb, method);
            }
            else if (member is IPropertySymbol prop)
            {
                var sigKey = $"prop:{prop.Name}";
                if (!generatedSignatures.Add(sigKey))
                    continue;

                EmitProperty(sb, prop);
            }
        }

        foreach (var ext in extensionMethods)
        {
            if (ShouldSkipMethod(ext.Symbol))
                continue;

            var wrappedParams = ext.ParametersWithoutReceiver.Where((_, i) => !ext.IsInjected[i]);

            var sigKey = GetSignatureKey(ext.Symbol.Name, wrappedParams);
            if (!generatedSignatures.Add(sigKey))
                continue;

            EmitExtensionWrapper(sb, ext);
        }

        sb.AppendLine("}");
        return sb.ToString();
    }

    private static string GetSignatureKey(string name, IEnumerable<IParameterSymbol> parameters)
    {
        var paramTypes = string.Join(
            ", ",
            parameters.Select(p =>
            {
                var prefix = p.RefKind switch
                {
                    RefKind.Ref => "ref ",
                    RefKind.Out => "out ",
                    RefKind.In => "in ",
                    _ => "",
                };
                return prefix + p.Type.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);
            })
        );
        return $"{name}({paramTypes})";
    }

    private static bool ShouldSkipMethod(IMethodSymbol method)
    {
        if (method.ContainingType.SpecialType == SpecialType.System_Object)
            return true;

        if (method.IsStatic && !method.IsExtensionMethod)
            return true;

        if (
            method.Name
            is nameof(object.GetType)
                or nameof(object.Equals)
                or nameof(object.GetHashCode)
                or nameof(object.ToString)
        )
            return true;

        return false;
    }

    private static void EmitMethod(StringBuilder sb, IMethodSymbol method)
    {
        var returnType = method.ReturnType.ToDisplayString(
            SymbolDisplayFormat.FullyQualifiedFormat
        );
        var name = method.Name;

        var parameters = string.Join(", ", method.Parameters.Select(RenderParameter));
        var args = string.Join(", ", method.Parameters.Select(p => p.Name));

        sb.AppendLine(
            $"    /// <inheritdoc cref=\"{method.ContainingType.Name}.{method.Name}\" />"
        );
        sb.AppendLine($"    public static {returnType} {name}({parameters})");
        sb.AppendLine($"        => Shared.{name}({args});");
        sb.AppendLine();
    }

    private static void EmitExtensionWrapper(StringBuilder sb, NormalizedMethod method)
    {
        var symbol = method.Symbol;
        var parameters = method.ParametersWithoutReceiver;
        var isInjected = method.IsInjected;

        var returnType = symbol.ReturnType.ToDisplayString(
            SymbolDisplayFormat.FullyQualifiedFormat
        );
        var name = symbol.Name;

        var renderedParams = string.Join(
            ", ",
            parameters.Where((_, i) => !isInjected[i]).Select(RenderParameter)
        );

        var argsList = new List<string> { "Shared" };
        argsList.AddRange(parameters.Select((p, i) => isInjected[i] ? "Shared" : p.Name));
        var args = string.Join(", ", argsList);

        var extClass = symbol.ContainingType.ToDisplayString(
            SymbolDisplayFormat.FullyQualifiedFormat
        );

        sb.AppendLine(
            $"    /// <inheritdoc cref=\"{symbol.ContainingType.Name}.{symbol.Name}\" />"
        );
        sb.AppendLine($"    public static {returnType} {name}({renderedParams})");
        sb.AppendLine($"        => {extClass}.{name}({args});");
        sb.AppendLine();
    }

    private static string RenderParameter(IParameterSymbol p)
    {
        var type = p.Type.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);

        if (p.NullableAnnotation == NullableAnnotation.Annotated)
            type += "?";

        if (p.HasExplicitDefaultValue)
            return $"{type} {p.Name} = {RenderDefaultValue(p)}";

        return $"{type} {p.Name}";
    }

    private static string RenderDefaultValue(IParameterSymbol p)
    {
        var value = p.ExplicitDefaultValue;

        if (value is null)
            return "null";

        if (p.Type.TypeKind == TypeKind.Enum)
        {
            var enumType = (INamedTypeSymbol)p.Type;

            foreach (var member in enumType.GetMembers().OfType<IFieldSymbol>())
            {
                if (member.HasConstantValue && Equals(member.ConstantValue, value))
                {
                    return $"{enumType.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat)}.{member.Name}";
                }
            }

            return $"({enumType.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat)}){value}";
        }

        return value switch
        {
            string s => $"\"{s}\"",
            char c => $"'{c}'",
            bool b => b ? "true" : "false",
            _ => value?.ToString() ?? "null",
        };
    }

    private static void EmitProperty(StringBuilder sb, IPropertySymbol prop)
    {
        var type = prop.Type.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);

        if (prop.NullableAnnotation == NullableAnnotation.Annotated)
            type += "?";

        sb.AppendLine($"    /// <inheritdoc cref=\"{prop.ContainingType.Name}.{prop.Name}\" />");

        if (prop.IsReadOnly)
        {
            sb.AppendLine($"    public static {type} {prop.Name} => Shared.{prop.Name};");
        }
        else
        {
            sb.AppendLine($"    public static {type} {prop.Name}");
            sb.AppendLine("    {");
            sb.AppendLine($"        get => Shared.{prop.Name};");
            sb.AppendLine($"        set => Shared.{prop.Name} = value;");
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

    private static IEnumerable<INamedTypeSymbol> GetAllTypes(INamespaceSymbol ns)
    {
        foreach (var type in ns.GetTypeMembers())
        {
            yield return type;

            foreach (var nested in GetNestedTypes(type))
                yield return nested;
        }

        foreach (var childNs in ns.GetNamespaceMembers())
        {
            foreach (var t in GetAllTypes(childNs))
                yield return t;
        }
    }

    private static IEnumerable<INamedTypeSymbol> GetNestedTypes(INamedTypeSymbol type)
    {
        foreach (var nested in type.GetTypeMembers())
        {
            yield return nested;

            foreach (var inner in GetNestedTypes(nested))
                yield return inner;
        }
    }
}
