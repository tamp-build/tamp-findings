namespace Tamp.Findings.Api.Endpoints;

// TFND-266: every /ingest/* route returns a body describing what was STORED, but none declared it, so
// /openapi/v1.json documented success as a bare "200 OK" and producers (and generated clients) concluded there was
// nothing to read. One place declares the contract so a new ingest route cannot forget it — a test walks the
// document and fails on any /ingest/* 200 response without a schema.
internal static class IngestContractDocs
{
    // The build-identity rule, stated on every ingest that attaches evidence to a single build. Strata could not tell
    // from the docs whether consecutive nightlies on different commits replace each other or accumulate (TFND-264).
    internal const string BuildIdentity =
        " Build identity: the evidence is attached to the build for the commitSha you send — always send it, and send"
        + " the SAME commitSha as the build's other evidence. One commit is one build whatever version string is stamped"
        + " on it; two commits are two builds even with the same version string. Without a commitSha the version string"
        + " identifies the build. The response's componentVersionId and build.commitSha name the build it landed on.";

    internal const string ReplaceOnIngest =
        " Replace-on-ingest: a later post of this evidence for the SAME build replaces this one; a different commit"
        + " never replaces it.";

    /// <summary>Summary + declared success body + the auth/validation statuses every ingest route can return.</summary>
    internal static RouteHandlerBuilder WithIngestContract<TResponse>(
        this RouteHandlerBuilder route, string summary, bool singleBuild = true, bool replaceOnIngest = false) =>
        route.WithSummary(summary
                + (replaceOnIngest ? ReplaceOnIngest : "")
                + (singleBuild ? BuildIdentity : ""))
            .Produces<TResponse>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized);
}
