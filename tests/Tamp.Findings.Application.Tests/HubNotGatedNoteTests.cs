using Tamp.Findings.Application.Projects;
using Xunit;

namespace Tamp.Findings.Application.Tests;

/// <summary>
/// The sentence shown on a build the gate does not judge (TFND-244).
///
/// Lives on <see cref="ProjectHubData"/> rather than in the Razor template, so
/// it can be tested at all. A judgement about the evidence that lives in markup
/// is one that goes untested and then wrong — and this one's whole job is to
/// stop a reader mistaking a pull-request score for the release decision.
/// </summary>
public class HubNotGatedNoteTests
{
    private static ProjectHubData Build(
        bool canonical, string? branch = null, string? pr = null) =>
        new(
            Project: new ProjectRef(Guid.NewGuid(), "client", Guid.NewGuid(), "project", null, null),
            CommitSha: "abc1234",
            VersionString: "1.0.0",
            BuiltAt: DateTimeOffset.UtcNow,
            PolicyName: "Tamp Standard v1",
            ComplianceBaseline: null,
            CoverageTarget: 80,
            CoverageFloor: 70,
            Risk: null!,
            Gates: null!,
            Inputs: null!,
            History: [],
            Images: [],
            IsCanonicalBuild: canonical,
            BranchName: branch,
            PullRequestRef: pr);

    [Fact]
    public void The_gated_build_says_nothing()
    {
        // An unconditional banner would train readers to ignore it, which is
        // worse than no banner on the one page where it matters.
        Assert.Null(Build(canonical: true).NotGatedNote);
        Assert.Null(Build(canonical: true, branch: "main").NotGatedNote);
    }

    [Fact]
    public void A_pull_request_build_names_the_pull_request()
    {
        var note = Build(canonical: false, branch: "feature/x", pr: "42").NotGatedNote;

        Assert.NotNull(note);
        Assert.Contains("Pull request #42", note!, StringComparison.Ordinal);
        Assert.Contains("gates judge the latest build on main", note, StringComparison.Ordinal);
    }

    [Fact]
    public void The_pull_request_wins_over_the_branch_when_both_are_present()
    {
        // "#42" identifies the change to a human better than "feature/x" does,
        // and a PR build always has a branch too — so without a precedence the
        // less useful one would win by accident.
        var note = Build(canonical: false, branch: "feature/x", pr: "42").NotGatedNote;

        Assert.DoesNotContain("feature/x", note!, StringComparison.Ordinal);
    }

    [Fact]
    public void A_branch_build_with_no_pull_request_names_the_branch()
    {
        var note = Build(canonical: false, branch: "feature/y").NotGatedNote;

        Assert.Contains("Branch feature/y", note!, StringComparison.Ordinal);
    }

    [Fact]
    public void With_neither_it_does_not_invent_a_label()
    {
        // Non-canonical with no branch and no PR ref: nothing identifies the
        // build beyond its commit, so the note says only the part it can
        // support rather than guessing at a name.
        var note = Build(canonical: false).NotGatedNote;

        Assert.Equal(
            "Gates judge the latest build on main. This page scores the commit you asked for.",
            note);
        Assert.DoesNotContain("Branch", note!, StringComparison.Ordinal);
        Assert.DoesNotContain("Pull request", note!, StringComparison.Ordinal);
    }
}
