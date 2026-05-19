using Tamp.Findings.Domain.Hashing;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Tests;

public class FindingHasherTests
{
    [Fact]
    public void Identical_inputs_produce_identical_hashes()
    {
        var a = FindingHasher.Compute(ScannerKind.CodeQL, "rule.x", "src/Foo.cs", "var q = 1;");
        var b = FindingHasher.Compute(ScannerKind.CodeQL, "rule.x", "src/Foo.cs", "var q = 1;");
        Assert.Equal(a, b);
    }

    [Fact]
    public void Whitespace_only_changes_in_snippet_do_not_change_the_hash()
    {
        var a = FindingHasher.Compute(ScannerKind.CodeQL, "rule.x", "src/Foo.cs", "var q = 1;");
        var b = FindingHasher.Compute(ScannerKind.CodeQL, "rule.x", "src/Foo.cs", "  var   q  =  1;  ");
        Assert.Equal(a, b);
    }

    [Fact]
    public void Different_scanners_produce_different_hashes_for_the_same_finding()
    {
        var a = FindingHasher.Compute(ScannerKind.CodeQL, "rule.x", "src/Foo.cs", "var q = 1;");
        var b = FindingHasher.Compute(ScannerKind.OpenGrep, "rule.x", "src/Foo.cs", "var q = 1;");
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Different_rule_ids_produce_different_hashes()
    {
        var a = FindingHasher.Compute(ScannerKind.CodeQL, "rule.x", "src/Foo.cs", "var q = 1;");
        var b = FindingHasher.Compute(ScannerKind.CodeQL, "rule.y", "src/Foo.cs", "var q = 1;");
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Different_file_paths_produce_different_hashes()
    {
        var a = FindingHasher.Compute(ScannerKind.CodeQL, "rule.x", "src/Foo.cs", "var q = 1;");
        var b = FindingHasher.Compute(ScannerKind.CodeQL, "rule.x", "src/Bar.cs", "var q = 1;");
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Null_or_empty_snippet_hashes_consistently()
    {
        var a = FindingHasher.Compute(ScannerKind.CodeQL, "rule.x", "src/Foo.cs", null);
        var b = FindingHasher.Compute(ScannerKind.CodeQL, "rule.x", "src/Foo.cs", "");
        var c = FindingHasher.Compute(ScannerKind.CodeQL, "rule.x", "src/Foo.cs", "   ");
        Assert.Equal(a, b);
        Assert.Equal(b, c);
    }

    [Fact]
    public void Hash_is_lowercase_hex_sha256()
    {
        var h = FindingHasher.Compute(ScannerKind.CodeQL, "rule.x", "src/Foo.cs", "var q = 1;");
        Assert.Equal(64, h.Length);
        Assert.All(h, c => Assert.True(char.IsDigit(c) || (c >= 'a' && c <= 'f'), $"non-lowercase-hex char '{c}'"));
    }
}
