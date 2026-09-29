using System.IO.Compression;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Ingest.Raw;

// Persists the raw report a producer POSTed as the build's evidence of record (TFND-209). Replace-by-
// file with content dedup: the supersession identity is the producer's filename, or "sha256:<hash>"
// when none was given, so re-posting the same file replaces it, different files under one build
// coexist, and identical bytes are a no-op. Stored gzip-compressed; XML compresses ~10-20x.
public static class RawArtifactStore
{
    public static async Task UpsertAsync(
        FindingsDbContext db, Guid componentVersionId, RawArtifactKind kind, string format,
        string? fileName, string? toolName, byte[] raw, CancellationToken ct)
    {
        var sha = Convert.ToHexStringLower(SHA256.HashData(raw));
        // A named file supersedes by name; an unnamed one is content-addressed so distinct uploads
        // still coexist rather than clobbering each other under a shared default.
        var slotKey = string.IsNullOrWhiteSpace(fileName) ? $"sha256:{sha}" : fileName.Trim();

        var existing = await db.RawReportArtifacts
            .FirstOrDefaultAsync(a => a.ComponentVersionId == componentVersionId && a.Kind == kind && a.SlotKey == slotKey, ct);

        if (existing is not null && existing.Sha256 == sha)
        {
            existing.IngestedAt = DateTimeOffset.UtcNow;   // identical re-post: touch, don't rewrite
            existing.ToolName = toolName ?? existing.ToolName;
            return;
        }

        var compressed = Gzip(raw);
        if (existing is not null)
        {
            existing.Format = format;
            existing.FileName = string.IsNullOrWhiteSpace(fileName) ? existing.FileName : fileName.Trim();
            existing.Sha256 = sha;
            existing.SizeBytes = raw.Length;
            existing.CompressedBytes = compressed;
            existing.ToolName = toolName;
            existing.IngestedAt = DateTimeOffset.UtcNow;
            return;
        }

        db.RawReportArtifacts.Add(new RawReportArtifact
        {
            ComponentVersionId = componentVersionId,
            Kind = kind,
            Format = format,
            FileName = string.IsNullOrWhiteSpace(fileName) ? null : fileName.Trim(),
            SlotKey = slotKey,
            Sha256 = sha,
            SizeBytes = raw.Length,
            CompressedBytes = compressed,
            ToolName = toolName,
        });
    }

    public static byte[] Gzip(byte[] raw)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.SmallestSize, leaveOpen: true))
            gz.Write(raw, 0, raw.Length);
        return ms.ToArray();
    }

    public static byte[] Gunzip(byte[] compressed)
    {
        using var input = new MemoryStream(compressed);
        using var gz = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        gz.CopyTo(output);
        return output.ToArray();
    }
}
