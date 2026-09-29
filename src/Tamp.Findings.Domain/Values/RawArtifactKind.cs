namespace Tamp.Findings.Domain.Values;

// Which evidence stream a stored raw report backs. Kept small and stable — it partitions the raw
// artifact store and picks the parser on re-parse.
public enum RawArtifactKind
{
    TestResults = 0,
    Coverage = 1,
}
