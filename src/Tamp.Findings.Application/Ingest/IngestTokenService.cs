using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Application.Ingest;

public sealed record MintedToken(IngestToken Record, string Plaintext);

// Issues, validates, and revokes bearer tokens used by /ingest/* callers.
// Plaintext is returned exactly once (at mint time); persistence only
// keeps SHA-256 hex of the wire token. Lookup on validate hits the
// unique hash index, so the request path is a single-row read.
public sealed class IngestTokenService(FindingsDbContext db)
{
    public const string ClientPrefix = "cli_";
    public const string ProjectPrefix = "prj_";

    public async Task<MintedToken> MintClientTokenAsync(Guid clientId, string name, Guid byUserId, CancellationToken ct)
    {
        var plaintext = ClientPrefix + GenerateRandomPart();
        var record = new IngestToken
        {
            Scope = IngestTokenScope.Client,
            ClientId = clientId,
            ProjectId = null,
            TokenHash = Hash(plaintext),
            Name = name,
            CreatedByUserId = byUserId,
        };
        db.IngestTokens.Add(record);
        await db.SaveChangesAsync(ct);
        return new MintedToken(record, plaintext);
    }

    public async Task<MintedToken> MintProjectTokenAsync(Guid projectId, string name, Guid byUserId, CancellationToken ct)
    {
        var plaintext = ProjectPrefix + GenerateRandomPart();
        var record = new IngestToken
        {
            Scope = IngestTokenScope.Project,
            ClientId = null,
            ProjectId = projectId,
            TokenHash = Hash(plaintext),
            Name = name,
            CreatedByUserId = byUserId,
        };
        db.IngestTokens.Add(record);
        await db.SaveChangesAsync(ct);
        return new MintedToken(record, plaintext);
    }

    // Returns the live token row if the wire token is well-formed,
    // hashes to a known row, and that row isn't revoked. Bumps
    // LastUsedAt as a side effect — callers can ignore that.
    public async Task<IngestToken?> ValidateAsync(string wireToken, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(wireToken)) return null;
        if (!wireToken.StartsWith(ClientPrefix, StringComparison.Ordinal)
            && !wireToken.StartsWith(ProjectPrefix, StringComparison.Ordinal)) return null;

        var hash = Hash(wireToken);
        var row = await db.IngestTokens
            .FirstOrDefaultAsync(t => t.TokenHash == hash && t.RevokedAt == null, ct);
        if (row is null) return null;

        row.LastUsedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);
        return row;
    }

    public async Task<bool> RevokeAsync(Guid tokenId, CancellationToken ct)
    {
        var row = await db.IngestTokens.FirstOrDefaultAsync(t => t.Id == tokenId, ct);
        if (row is null || row.RevokedAt is not null) return false;
        row.RevokedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);
        return true;
    }

    // 32 random bytes → ~43 chars of base64url (no padding, no '+', no '/').
    // Total wire-token length with prefix: 47 chars. Plenty of entropy
    // (256 bits) and short enough to drop into env vars / GitHub secrets.
    private static string GenerateRandomPart()
    {
        Span<byte> bytes = stackalloc byte[32];
        RandomNumberGenerator.Fill(bytes);
        // Base64Url isn't in the BCL — translate from standard base64.
        var s = Convert.ToBase64String(bytes);
        return s.TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static string Hash(string wireToken)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(Encoding.UTF8.GetBytes(wireToken), hash);
        return Convert.ToHexString(hash);
    }
}
