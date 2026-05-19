using System.Text.Json;
using Tamp.Findings.Build.Ingest;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Build.Adapters;

// TruffleHog 3.x emits one JSON object per line ("jsonl") to its output
// file. Each object carries the detector name, a redacted view of the
// secret, the source location, and a Verified bool indicating whether
// the secret actually authenticated against the live service.
//
// Severity mapping is opinionated: a verified secret is Critical (it
// authenticates RIGHT NOW), an unverified detection is High (it matches
// the detector pattern but we couldn't or didn't probe).
public static class TrufflehogIngestMapper
{
    public static IngestRequestDto? Map(string jsonlPath, IngestBuildContext ctx)
    {
        if (!File.Exists(jsonlPath)) return null;

        var findings = new List<IngestFindingDto>();
        foreach (var line in File.ReadLines(jsonlPath))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            JsonElement obj;
            try { obj = JsonDocument.Parse(line).RootElement; }
            catch (JsonException) { continue; }

            var detector = obj.TryGetProperty("DetectorName", out var d) ? d.GetString() : null;
            if (string.IsNullOrEmpty(detector)) continue;

            var verified = obj.TryGetProperty("Verified", out var v) && v.GetBoolean();

            string? filePath = null;
            int? line2 = null;
            if (obj.TryGetProperty("SourceMetadata", out var sm)
                && sm.TryGetProperty("Data", out var data)
                && data.TryGetProperty("Filesystem", out var fs))
            {
                if (fs.TryGetProperty("file", out var fp)) filePath = fp.GetString();
                if (fs.TryGetProperty("line", out var ln) && ln.ValueKind == JsonValueKind.Number)
                    line2 = ln.GetInt32();
            }

            // Redacted preview — TruffleHog provides Redacted, but the raw
            // is needed for hash stability. We hash on the Redacted value
            // (or Raw if Redacted absent) so two scans of the same secret
            // dedupe but we don't store the raw secret in the snippet field.
            var redacted = obj.TryGetProperty("Redacted", out var r) ? r.GetString() : null;

            findings.Add(new IngestFindingDto(
                RuleId: detector!,
                Severity: verified ? Severity.Critical : Severity.High,
                Title: verified
                    ? $"Verified {detector} secret"
                    : $"Potential {detector} secret",
                Description: verified
                    ? $"TruffleHog verified this secret against the live {detector} service."
                    : $"TruffleHog detected a value matching the {detector} pattern; verification disabled or failed.",
                FilePath: filePath,
                Line: line2,
                Snippet: redacted));
        }

        if (findings.Count == 0) return null;

        return new IngestRequestDto(
            Client: ctx.Client,
            Project: ctx.Project,
            Component: ctx.Component,
            ComponentKind: ctx.ComponentKind,
            Flavor: ctx.Flavor,
            Version: ctx.Version,
            CommitSha: ctx.CommitSha,
            Branch: ctx.Branch,
            BuildId: ctx.BuildId,
            PullRequestRef: ctx.PullRequestRef,
            Scanner: ScannerKind.TruffleHog,
            Findings: findings);
    }
}
