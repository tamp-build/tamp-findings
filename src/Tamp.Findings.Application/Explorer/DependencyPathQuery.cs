using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;

namespace Tamp.Findings.Application.Explorer;

/// <summary>
/// Why is this package here (TFND-7 / F6.2).
///
/// The single most-asked question about an SBOM, and the one a flat dependency
/// list cannot answer. A team told they have a critical CVE in a transitive
/// package they have never heard of needs to know what pulled it in before they
/// can do anything at all — upgrade the direct dependency, or argue with its
/// maintainer, or accept it.
///
/// The edges are already ingested per snapshot; nothing rendered them.
///
/// This walks BACKWARDS from the package to the roots, because that is the
/// direction of the question. Walking forwards from every root and keeping the
/// paths that happen to arrive would explore the whole graph to answer
/// something local.
/// </summary>
public sealed class DependencyPathQuery
{
    private readonly FindingsDbContext _db;

    public DependencyPathQuery(FindingsDbContext db) => _db = db;

    /// <summary>
    /// Every route from a root of the graph down to this package.
    ///
    /// Capped, and the cap is reported: on a large graph a package can be
    /// reachable by hundreds of paths, and a reader needs two or three of them,
    /// not all of them. Shortest first — the shortest path is the one with the
    /// fewest maintainers between the team and the fix.
    /// </summary>
    public async Task<DependencyPaths> ForAsync(
        Guid projectId, string? commitSha, string purl, int limit = 5, CancellationToken ct = default)
    {
        // The snapshot this package appears in. Newest first, so the answer is
        // about the build the reader is looking at rather than the first one
        // ever ingested.
        var snapshotId = await (
            from sc in _db.SbomComponents.AsNoTracking()
            join snap in _db.SbomSnapshots.AsNoTracking() on sc.SbomSnapshotId equals snap.Id
            join cv in _db.ComponentVersions.AsNoTracking() on snap.ComponentVersionId equals cv.Id
            join c in _db.Components.AsNoTracking() on cv.ComponentId equals c.Id
            where c.ProjectId == projectId
                  && (commitSha == null || cv.CommitSha == commitSha)
                  && sc.Purl == purl
            orderby cv.CreatedAt descending
            select (Guid?)snap.Id).FirstOrDefaultAsync(ct);

        if (snapshotId is not { } snapshot) return DependencyPaths.None;

        var packages = await _db.SbomComponents.AsNoTracking()
            .Where(p => p.SbomSnapshotId == snapshot)
            .Select(p => new { p.Id, p.Purl, p.Name, p.Version })
            .ToArrayAsync(ct);

        var edges = await _db.SbomDependencies.AsNoTracking()
            .Where(d => d.SbomSnapshotId == snapshot)
            .Select(d => new { d.ParentComponentId, d.ChildComponentId })
            .ToArrayAsync(ct);

        // No edges at all is a real and common state: plenty of SBOM producers
        // emit a flat component list with no dependency graph. Saying so is the
        // honest answer — an empty path list would read as "nothing depends on
        // this", which is a different and much more interesting claim.
        if (edges.Length == 0) return DependencyPaths.NoGraph;

        var target = packages.FirstOrDefault(p =>
            string.Equals(p.Purl, purl, StringComparison.OrdinalIgnoreCase));
        if (target is null) return DependencyPaths.None;

        var labels = packages.ToDictionary(
            p => p.Id, p => new DependencyNode(p.Purl, p.Name, p.Version));

        var parentsOf = edges
            .GroupBy(e => e.ChildComponentId)
            .ToDictionary(g => g.Key, g => g.Select(e => e.ParentComponentId).Distinct().ToArray());

        var hasParent = parentsOf.Keys.ToHashSet();

        // Direct dependency of the build itself — nothing above it.
        if (!hasParent.Contains(target.Id))
            return new DependencyPaths(true, [], Direct: true, Truncated: false);

        var paths = new List<IReadOnlyList<DependencyNode>>();
        var truncated = false;

        // Breadth-first from the target upwards, so shorter routes come out
        // first without sorting afterwards.
        var queue = new Queue<List<Guid>>();
        queue.Enqueue([target.Id]);

        // A hard ceiling on work, not just on results. A malformed SBOM can
        // contain cycles — the per-path visited set below stops one path
        // looping forever, but a graph with many cycles can still generate
        // paths without bound, and a screen must not hang because somebody's
        // generator emitted a bad edge.
        var explored = 0;
        const int MaxExplored = 20_000;
        const int MaxDepth = 24;

        while (queue.Count > 0 && paths.Count < limit && explored < MaxExplored)
        {
            var path = queue.Dequeue();
            explored++;

            var head = path[^1];

            if (!parentsOf.TryGetValue(head, out var parents) || parents.Length == 0)
            {
                // Reached a root. The path was built child-first, so reverse it
                // — a reader wants to read downwards, from what they chose to
                // depend on to what arrived with it.
                paths.Add(path.AsEnumerable().Reverse()
                    .Where(labels.ContainsKey)
                    .Select(id => labels[id])
                    .ToArray());
                continue;
            }

            if (path.Count >= MaxDepth)
            {
                truncated = true;
                continue;
            }

            foreach (var parent in parents)
            {
                // Per-PATH visited set, not global: two different routes may
                // legitimately share a node, and a global set would hide the
                // second one. This only stops a path revisiting itself, which
                // is a cycle.
                if (path.Contains(parent)) continue;

                queue.Enqueue([.. path, parent]);
            }
        }

        if (queue.Count > 0 || explored >= MaxExplored) truncated = true;

        return new DependencyPaths(true, paths, Direct: false, truncated);
    }
}

/// <summary>
/// How a package came to be in the build.
///
/// <paramref name="HasGraph"/> distinguishes "this SBOM has no dependency
/// edges" from "nothing depends on this". They look identical as an empty list
/// and mean opposite things — the first is a limitation of the producer, the
/// second is a claim about the build.
/// </summary>
public sealed record DependencyPaths(
    bool HasGraph,
    IReadOnlyList<IReadOnlyList<DependencyNode>> Paths,
    bool Direct,
    bool Truncated)
{
    /// <summary>The package is not in this project's newest SBOM.</summary>
    public static DependencyPaths None { get; } = new(true, [], false, false);

    /// <summary>The SBOM carries components but no edges between them.</summary>
    public static DependencyPaths NoGraph { get; } = new(false, [], false, false);
}

public sealed record DependencyNode(string Purl, string Name, string Version);
