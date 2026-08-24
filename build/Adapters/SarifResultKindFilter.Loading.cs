using Tamp.Sarif;

namespace Tamp.Findings.Build.Adapters;

// The file-loading half of SarifResultKindFilter.
//
// Split from the filtering logic deliberately: that half is pure
// string -> string with no dependency on Nuke or Tamp.Sarif, which lets the
// test project compile it directly. Referencing the Nuke build project from a
// test would drag its MSBuild transitives in, and this repo builds with
// TreatWarningsAsErrors — their advisories would fail the test build for
// reasons that have nothing to do with the code under test.
public static partial class SarifResultKindFilter
{
    /// <summary>
    /// Parse <paramref name="path"/>, keeping only results that are failures.
    /// </summary>
    /// <param name="dropped">How many non-failure results were removed.</param>
    public static SarifLog LoadFailuresOnly(AbsolutePath path, out int dropped)
    {
        var json = File.ReadAllText(path);
        var filtered = RemoveNonFailures(json, out dropped);
        return SarifReader.Parse(filtered);
    }
}
