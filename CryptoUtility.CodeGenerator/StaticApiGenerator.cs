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

        if (symbol == null)
            return null;

        var attr = symbol
            .GetAttributes()
            .FirstOrDefault(a => a.AttributeClass?.Name == "GenerateStaticApiAttribute");

        return attr is null ? null : symbol;
    }

    private static string Generate(INamedTypeSymbol symbol)
    {
        return $"// generated for {symbol.Name}";
    }
}
