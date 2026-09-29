using System.Xml;
using System.Xml.Linq;

namespace Tamp.Findings.Api.Ingest.Raw;

// Loads a raw report body as XML with the attack surface closed: no DTD, no external entities,
// no XML resolver. A raw ingest accepts a file from a CI producer we do not control, so the parser
// is the one hardened place that reshape happens — the whole point of owning it server-side instead
// of every adopter hand-rolling a parser with unknown XXE posture.
public static class RawReportXml
{
    // Reports are small (a .trx / cobertura for a repo is well under a megabyte; a large opencover
    // for a big solution is a few MB). Cap the body so a hostile or runaway upload can't exhaust
    // memory before we even parse it.
    public const long MaxBytes = 32 * 1024 * 1024;

    public sealed class TooLargeException(long limit) : Exception($"report exceeds the {limit}-byte limit");
    public sealed class MalformedException(string why) : Exception(why);

    // The parsed document plus the exact bytes read, so a caller can persist the raw file (evidence of
    // record) without reading the stream twice.
    public sealed record Loaded(XDocument Doc, byte[] Raw);

    public static async Task<XDocument> LoadAsync(Stream body, CancellationToken ct) =>
        (await LoadWithBytesAsync(body, ct)).Doc;

    public static async Task<Loaded> LoadWithBytesAsync(Stream body, CancellationToken ct)
    {
        // Copy through a capped buffer first: XmlReader would otherwise stream an unbounded body.
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int read;
        while ((read = await body.ReadAsync(chunk, ct)) > 0)
        {
            if (buffer.Length + read > MaxBytes) throw new TooLargeException(MaxBytes);
            buffer.Write(chunk, 0, read);
        }
        buffer.Position = 0;

        var settings = new XmlReaderSettings
        {
            // Ignore, not Prohibit: a DOCTYPE may be PRESENT (reportgenerator's Cobertura ships
            // `<!DOCTYPE coverage SYSTEM "coverage-04.dtd">` by default) but is never processed — the
            // DTD is skipped, no entity is defined, and with the resolver nulled nothing external is
            // fetched. So a well-known benign DOCTYPE parses, while XXE and billion-laughs stay closed:
            // any `&entity;` reference is undeclared and errors out rather than expanding.
            DtdProcessing = DtdProcessing.Ignore,
            XmlResolver = null,                         // no external entity or schema fetch
            MaxCharactersFromEntities = 0,
            IgnoreComments = true,
            IgnoreProcessingInstructions = true,
        };
        var raw = buffer.ToArray();
        try
        {
            using var reader = XmlReader.Create(buffer, settings);
            return new Loaded(XDocument.Load(reader), raw);
        }
        catch (XmlException ex)
        {
            throw new MalformedException(ex.Message);
        }
    }
}
