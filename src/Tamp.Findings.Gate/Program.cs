using Tamp.Findings.Gate;
using System.Net;
using System.Text.Json;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

// tamp findings gate — a fail-closed CI acceptance gate (ADR 0004 §4).
//
// Runs after ingest, reads /projects/{id}/gate from the in-enclave findings
// instance with the same cli_/prj_ token that posted the build, and exits per
// the §4.5 decision table. Advisory never fails the build; enforcing fails on
// anything that is not a definitive Pass — including "could not reach a
// verdict", which is the whole point of a hard gate.

var opts = GateArgs.Parse(args);
if (opts is null) { GateArgs.PrintUsage(); return GateArgs.UsageExit; }

using var http = new HttpClient { BaseAddress = new Uri(opts.Url), Timeout = TimeSpan.FromSeconds(15) };
http.DefaultRequestHeaders.Add("Authorization", $"Bearer {opts.Token}");
http.DefaultRequestHeaders.Add("User-Agent", "tamp-findings-gate");

var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(opts.TimeoutSeconds);
GateResponse? decision = null;
string? reason = null;

while (true)
{
    (decision, reason, var retriable) = await FetchAsync(http, opts);

    if (decision is not null)
    {
        // If a specific commit was named, wait until the instance has evaluated
        // THAT build — ingest/evaluation may still be catching up.
        if (opts.Commit is not null
            && !string.Equals(decision.CommitSha, opts.Commit, StringComparison.OrdinalIgnoreCase))
        {
            reason = $"latest evaluated commit is {Short(decision.CommitSha)}, waiting for {Short(opts.Commit)}";
            decision = null;
            retriable = true;
        }
        else
        {
            break;
        }
    }

    if (!retriable || DateTimeOffset.UtcNow >= deadline) break;
    await Task.Delay(TimeSpan.FromSeconds(opts.PollSeconds));
}

GateOutcome outcome;
EnforcementMode mode;
if (decision is null)
{
    // No verdict reached. The mode is unknown (we could not ask), so fall back
    // to the caller's declared intent: block unless --advisory was passed.
    outcome = GateOutcome.Unreachable;
    mode = opts.Advisory ? EnforcementMode.Advisory : EnforcementMode.Enforcing;
}
else
{
    mode = Enum.TryParse<EnforcementMode>(decision.EnforcementMode, ignoreCase: true, out var m)
        ? m
        : EnforcementMode.Enforcing;
    var verdicts = (decision.Gates ?? [])
        .Select(g => Enum.TryParse<GateVerdict>(g.Verdict, ignoreCase: true, out var v) ? v : GateVerdict.Error);
    outcome = GateExit.OutcomeFrom(verdicts);
}

var effectiveCode = GateExit.CodeFor(outcome, mode);

if (opts.Json) Console.WriteLine(RenderJson(decision, outcome, mode, effectiveCode, reason));
else RenderHuman(decision, outcome, mode, effectiveCode, reason, opts);

// --explain is a dry run: report what WOULD happen, never fail the build.
return opts.Explain ? 0 : effectiveCode;

// ---- helpers --------------------------------------------------------------

static async Task<(GateResponse? decision, string? reason, bool retriable)> FetchAsync(HttpClient http, GateOptions o)
{
    try
    {
        using var resp = await http.GetAsync($"/projects/{o.Project}/gate");
        switch (resp.StatusCode)
        {
            case HttpStatusCode.OK:
                var body = await resp.Content.ReadAsStringAsync();
                var jsonOpts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                return (JsonSerializer.Deserialize<GateResponse>(body, jsonOpts), null, false);

            // The build's CVs may not be persisted yet right after ingest, so a
            // 404 is retriable within the timeout.
            case HttpStatusCode.NotFound:
                return (null, "no build/verdict yet", true);

            // Auth failures are not transient — do not burn the timeout on them.
            case HttpStatusCode.Unauthorized:
            case HttpStatusCode.Forbidden:
                return (null, $"authentication failed ({(int)resp.StatusCode})", false);

            default:
                var retriable = (int)resp.StatusCode >= 500;
                return (null, $"server returned {(int)resp.StatusCode}", retriable);
        }
    }
    catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
    {
        return (null, $"unreachable: {ex.Message}", true);
    }
}

static string Short(string? sha) => string.IsNullOrEmpty(sha) ? "(none)" : (sha.Length > 8 ? sha[..8] : sha);

static string Mark(string verdict) => verdict switch
{
    "Pass" => "OK ",
    "Fail" => "X  ",
    "Unknown" => "?  ",
    "Error" => "!  ",
    _ => "   ",
};

static void RenderHuman(GateResponse? d, GateOutcome outcome, EnforcementMode mode, int code, string? reason, GateOptions o)
{
    Console.WriteLine($"tamp.findings gate — {mode.ToString().ToLowerInvariant()} mode");
    if (d is not null)
    {
        Console.WriteLine($"build: {Short(d.CommitSha)} ({d.VersionString})   {d.GatesEnabled} gates enabled");
        foreach (var g in d.Gates ?? [])
        {
            var detail = string.IsNullOrEmpty(g.Reason) ? g.Observed : $"{g.Observed} — {g.Reason}";
            Console.WriteLine($"  {Mark(g.Verdict)}{g.Key}: {g.Verdict} ({detail})");
        }
    }
    else
    {
        Console.WriteLine($"build: could not reach a verdict — {reason}");
    }

    var ship = outcome switch
    {
        GateOutcome.Pass => "CLEAR TO SHIP",
        GateOutcome.Fail => "BLOCKED",
        GateOutcome.Unknown => "NOT ASSESSED (a gate could not be evaluated)",
        GateOutcome.Error => "NOT ASSESSED (evaluation error)",
        GateOutcome.Unreachable => "NOT ASSESSED (no verdict)",
        _ => outcome.ToString(),
    };
    Console.WriteLine($"verdict: {ship}");

    if (o.Explain)
        Console.WriteLine($"[dry run] would exit {code}; exiting 0 (--explain)");
    else if (mode == EnforcementMode.Advisory)
        Console.WriteLine(code == 0 ? "advisory: not blocking (exit 0)" : $"advisory: would block, but not failing the build (exit 0)");
    else
        Console.WriteLine(code == 0 ? "clear (exit 0)" : $"FAILING THE BUILD (exit {code})");
}

static string RenderJson(GateResponse? d, GateOutcome outcome, EnforcementMode mode, int code, string? reason)
    => JsonSerializer.Serialize(new
    {
        outcome = outcome.ToString(),
        mode = mode.ToString(),
        exitCode = code,
        commitSha = d?.CommitSha,
        versionString = d?.VersionString,
        gatesEnabled = d?.GatesEnabled,
        gatesBlocking = d?.GatesBlocking,
        gatesFailed = d?.GatesFailed,
        gatesUnknown = d?.GatesUnknown,
        reason,
        gates = (d?.Gates ?? []).Select(g => new { g.Key, g.Verdict, g.Blocks, g.Observed, g.Reason }),
    }, new JsonSerializerOptions { WriteIndented = true });

namespace Tamp.Findings.Gate
{
// ---- args + wire types ----------------------------------------------------

sealed record GateOptions(
    string Url, string Token, Guid Project, string? Commit,
    int TimeoutSeconds, int PollSeconds, bool Json, bool Explain, bool Advisory);

static class GateArgs
{
    public const int UsageExit = 2;

    public static GateOptions? Parse(string[] args)
    {
        string? url = null, token = Environment.GetEnvironmentVariable("TAMP_FINDINGS_INGEST_TOKEN");
        string? project = null, commit = null;
        int timeout = 60, poll = 3;
        bool json = false, explain = false, advisory = false;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--url": url = Next(args, ref i); break;
                case "--token": token = Next(args, ref i); break;
                case "--project": project = Next(args, ref i); break;
                case "--commit": commit = Next(args, ref i); break;
                case "--timeout": _ = int.TryParse(Next(args, ref i), out timeout); break;
                case "--poll": _ = int.TryParse(Next(args, ref i), out poll); break;
                case "--json": json = true; break;
                case "--explain": explain = true; break;
                case "--advisory": advisory = true; break;
                case "-h" or "--help": return null;
                default:
                    Console.Error.WriteLine($"unknown argument: {args[i]}");
                    return null;
            }
        }

        if (string.IsNullOrWhiteSpace(url) || string.IsNullOrWhiteSpace(token) || !Guid.TryParse(project, out var pid))
        {
            Console.Error.WriteLine("--url, --token (or TAMP_FINDINGS_INGEST_TOKEN) and --project <guid> are required.");
            return null;
        }

        return new GateOptions(url!, token!, pid, commit,
            Math.Max(0, timeout), Math.Max(1, poll), json, explain, advisory);
    }

    private static string? Next(string[] args, ref int i) => ++i < args.Length ? args[i] : null;

    public static void PrintUsage() => Console.Error.WriteLine(
        "usage: tamp-findings-gate --url <base> --token <cli_/prj_> --project <guid> "
        + "[--commit <sha>] [--timeout <s>] [--poll <s>] [--json] [--explain] [--advisory]");
}

sealed record GateResponse(
    Guid ProjectId, string? CommitSha, string VersionString, string EnforcementMode,
    int GatesEnabled, int GatesBlocking, int GatesFailed, int GatesUnknown,
    List<GateVerdictRow>? Gates);

sealed record GateVerdictRow(string Key, string Verdict, bool Blocks, string Observed, string? Reason);
}
