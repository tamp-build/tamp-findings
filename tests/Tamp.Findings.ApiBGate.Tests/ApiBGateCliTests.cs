using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;
using Xunit;

namespace Tamp.Findings.ApiBGate.Tests;

/// <summary>
/// Drives the CLI gate through its real entry point (the compiler-generated Main of the top-level
/// program) against an in-process stub HTTP server, asserting stdout and the exit code — the
/// contract a CI pipeline actually consumes (ADR 0004 section 4.5).
/// </summary>
[Collection("console")]
public sealed class ApiBGateCliTests
{
    private static readonly Guid Project = Guid.Parse("11111111-2222-3333-4444-555555555555");

    private sealed record Seen(string Path, string? Authorization, string? UserAgent);

    private sealed record Stub(string BaseUrl, List<Seen> Seen, HttpListener Listener) : IDisposable
    {
        public void Dispose() => Listener.Close();
    }

    // Each queued reply is served once, in order; the last one repeats.
    private static Stub StartStub(params (int status, string? body)[] replies)
    {
        int port;
        using (var probe = new TcpListener(IPAddress.Loopback, 0))
        {
            probe.Start();
            port = ((IPEndPoint)probe.LocalEndpoint).Port;
        }

        var listener = new HttpListener();
        listener.Prefixes.Add($"http://localhost:{port}/");
        listener.Start();
        var seen = new List<Seen>();
        var index = 0;

        _ = Task.Run(async () =>
        {
            while (listener.IsListening)
            {
                HttpListenerContext ctx;
                try { ctx = await listener.GetContextAsync(); }
                catch { return; }

                lock (seen) seen.Add(new Seen(ctx.Request.Url!.AbsolutePath, ctx.Request.Headers["Authorization"], ctx.Request.UserAgent));
                var (status, body) = replies[Math.Min(index++, replies.Length - 1)];
                ctx.Response.StatusCode = status;
                if (body is not null)
                {
                    var bytes = Encoding.UTF8.GetBytes(body);
                    ctx.Response.ContentType = "application/json";
                    await ctx.Response.OutputStream.WriteAsync(bytes);
                }
                ctx.Response.Close();
            }
        });

        return new Stub($"http://localhost:{port}", seen, listener);
    }

    private static string Decision(string? commit, string mode, params (string key, string verdict, string? reason)[] gates) =>
        JsonSerializer.Serialize(new
        {
            projectId = Project,
            commitSha = commit,
            versionString = "1.2.3",
            enforcementMode = mode,
            gatesEnabled = gates.Length,
            gatesBlocking = gates.Count(g => g.verdict != "Pass"),
            gatesFailed = gates.Count(g => g.verdict == "Fail"),
            gatesUnknown = gates.Count(g => g.verdict == "Unknown"),
            gates = gates.Select(g => new { key = g.key, verdict = g.verdict, blocks = g.verdict != "Pass", observed = "obs", reason = g.reason }),
        });

    private static async Task<(int code, string stdout, string stderr)> RunAsync(params string[] args)
    {
        var entry = Assembly.Load(new AssemblyName("tamp-findings-gate")).EntryPoint
            ?? throw new InvalidOperationException("gate has no entry point");

        var oldOut = Console.Out;
        var oldErr = Console.Error;
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        Console.SetOut(stdout);
        Console.SetError(stderr);
        try
        {
            // The generated entry point is either the async <Main>$ (Task<int>) or its synchronous
            // Main wrapper (int); run it off the test thread and accept both.
            var result = await Task.Run(() => entry.Invoke(null, [args]));
            var code = result is Task<int> task ? await task : (int)result!;
            return (code, stdout.ToString(), stderr.ToString());
        }
        finally
        {
            Console.SetOut(oldOut);
            Console.SetError(oldErr);
        }
    }

    private static string[] Base(Stub s, params string[] extra) =>
        [.. new[] { "--url", s.BaseUrl, "--token", "prj_secret", "--project", Project.ToString(), "--timeout", "0" }, .. extra];

    // ---- argument handling -----------------------------------------------------

    [Theory]
    [InlineData("--bogus")]
    [InlineData("--help")]
    [InlineData("-h")]
    public async Task Unknown_or_help_arguments_print_usage_and_exit_2(string arg)
    {
        var (code, _, err) = await RunAsync(arg);

        Assert.Equal(2, code);
        Assert.Contains("usage: tamp-findings-gate", err, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Missing_required_arguments_exit_2_and_say_which()
    {
        Environment.SetEnvironmentVariable("TAMP_FINDINGS_INGEST_TOKEN", null);

        var (code, _, err) = await RunAsync("--url", "http://localhost:1", "--project", "not-a-guid");

        Assert.Equal(2, code);
        Assert.Contains("--project <guid>", err, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_flag_with_no_value_is_a_usage_error_rather_than_a_crash()
    {
        var (code, _, _) = await RunAsync("--url");
        Assert.Equal(2, code);
    }

    // ---- verdicts ----------------------------------------------------------------

    [Fact]
    public async Task All_gates_passing_exits_zero_and_sends_the_bearer_token()
    {
        using var stub = StartStub((200, Decision("abcdef1234567890", "Enforcing", ("coverage", "Pass", null), ("sast", "Pass", null))));

        var (code, stdout, _) = await RunAsync(Base(stub));

        Assert.Equal(0, code);
        Assert.Contains("CLEAR TO SHIP", stdout, StringComparison.Ordinal);
        Assert.Contains("enforcing mode", stdout, StringComparison.Ordinal);
        Assert.Contains("build: abcdef12", stdout, StringComparison.Ordinal);   // sha shortened
        Assert.Contains("clear (exit 0)", stdout, StringComparison.Ordinal);
        var req = Assert.Single(stub.Seen);
        Assert.Equal($"/projects/{Project}/gate", req.Path);
        Assert.Equal("Bearer prj_secret", req.Authorization);
        Assert.Equal("tamp-findings-gate", req.UserAgent);
    }

    [Fact]
    public async Task A_failing_gate_blocks_an_enforcing_project_with_the_fail_code()
    {
        using var stub = StartStub((200, Decision("c1", "Enforcing", ("sast", "Fail", "2 criticals"), ("coverage", "Pass", null))));

        var (code, stdout, _) = await RunAsync(Base(stub));

        Assert.Equal(GateExit.Fail, code);
        Assert.Contains("BLOCKED", stdout, StringComparison.Ordinal);
        Assert.Contains($"FAILING THE BUILD (exit {GateExit.Fail})", stdout, StringComparison.Ordinal);
        Assert.Contains("X  sast: Fail (obs — 2 criticals)", stdout, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Unknown", GateExit.Unknown, "NOT ASSESSED (a gate could not be evaluated)")]
    [InlineData("Error", GateExit.Error, "NOT ASSESSED (evaluation error)")]
    [InlineData("SomethingNew", GateExit.Error, "NOT ASSESSED (evaluation error)")]   // unparseable verdicts fail closed as Error
    public async Task Non_definitive_verdicts_fail_closed_with_their_own_codes(string verdict, int expected, string banner)
    {
        using var stub = StartStub((200, Decision("c1", "Enforcing", ("sast", verdict, null))));

        var (code, stdout, _) = await RunAsync(Base(stub));

        Assert.Equal(expected, code);
        Assert.Contains(banner, stdout, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Advisory_mode_reports_but_never_fails_the_build()
    {
        using var stub = StartStub((200, Decision("c1", "Advisory", ("sast", "Fail", null))));

        var (code, stdout, _) = await RunAsync(Base(stub));

        Assert.Equal(0, code);
        // In advisory mode the decision table yields exit 0 even for Fail, so the "would block" branch
        // in the renderer is never reached; the banner still says BLOCKED for the verdict itself.
        Assert.Contains("BLOCKED", stdout, StringComparison.Ordinal);
        Assert.Contains("advisory: not blocking (exit 0)", stdout, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_unrecognised_enforcement_mode_defaults_to_enforcing()
    {
        using var stub = StartStub((200, Decision("c1", "Weird", ("sast", "Fail", null))));

        var (code, _, _) = await RunAsync(Base(stub));

        Assert.Equal(GateExit.Fail, code);
    }

    [Fact]
    public async Task Advisory_mode_with_only_passing_gates_says_not_blocking()
    {
        using var stub = StartStub((200, Decision("c1", "Advisory", ("sast", "Pass", null))));

        var (code, stdout, _) = await RunAsync(Base(stub));

        Assert.Equal(0, code);
        Assert.Contains("advisory: not blocking (exit 0)", stdout, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Explain_is_a_dry_run_that_always_exits_zero()
    {
        using var stub = StartStub((200, Decision("c1", "Enforcing", ("sast", "Fail", null))));

        var (code, stdout, _) = await RunAsync(Base(stub, "--explain"));

        Assert.Equal(0, code);
        Assert.Contains($"[dry run] would exit {GateExit.Fail}; exiting 0 (--explain)", stdout, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Json_output_carries_the_outcome_exit_code_and_each_gate()
    {
        using var stub = StartStub((200, Decision("c1", "Enforcing", ("sast", "Fail", "bad"), ("cov", "Pass", null))));

        var (code, stdout, _) = await RunAsync(Base(stub, "--json"));

        Assert.Equal(GateExit.Fail, code);
        using var doc = JsonDocument.Parse(stdout);
        var root = doc.RootElement;
        Assert.Equal("Fail", root.GetProperty("outcome").GetString());
        Assert.Equal("Enforcing", root.GetProperty("mode").GetString());
        Assert.Equal(GateExit.Fail, root.GetProperty("exitCode").GetInt32());
        Assert.Equal("1.2.3", root.GetProperty("versionString").GetString());
        Assert.Equal(2, root.GetProperty("gates").GetArrayLength());
        Assert.Equal("bad", root.GetProperty("gates")[0].GetProperty("Reason").GetString());
    }

    // ---- no verdict ----------------------------------------------------------------

    [Fact]
    public async Task Authentication_failures_are_not_retried_and_fail_closed()
    {
        using var stub = StartStub((401, null));

        var (code, stdout, _) = await RunAsync([.. Base(stub), "--timeout", "30"]);

        Assert.Equal(GateExit.Unreachable, code);
        Assert.Contains("authentication failed (401)", stdout, StringComparison.Ordinal);
        Assert.Contains("NOT ASSESSED (no verdict)", stdout, StringComparison.Ordinal);
        Assert.Single(stub.Seen);   // not retriable: no burning the timeout
    }

    [Fact]
    public async Task Forbidden_is_treated_like_unauthorised()
    {
        using var stub = StartStub((403, null));

        var (code, stdout, _) = await RunAsync(Base(stub));

        Assert.Equal(GateExit.Unreachable, code);
        Assert.Contains("(403)", stdout, StringComparison.Ordinal);
    }

    [Fact]
    public async Task No_build_yet_and_server_errors_report_why_when_the_timeout_is_spent()
    {
        using var notFound = StartStub((404, null));
        var (code404, out404, _) = await RunAsync(Base(notFound));
        Assert.Equal(GateExit.Unreachable, code404);
        Assert.Contains("no build/verdict yet", out404, StringComparison.Ordinal);

        using var broken = StartStub((503, null));
        var (code503, out503, _) = await RunAsync(Base(broken));
        Assert.Equal(GateExit.Unreachable, code503);
        Assert.Contains("server returned 503", out503, StringComparison.Ordinal);

        using var teapot = StartStub((418, null));
        var (code418, out418, _) = await RunAsync([.. Base(teapot), "--timeout", "30"]);
        Assert.Equal(GateExit.Unreachable, code418);
        Assert.Single(teapot.Seen);   // a 4xx other than 404 is final
    }

    [Fact]
    public async Task An_unreachable_server_is_unreachable_and_advisory_mode_still_does_not_block()
    {
        int port;
        using (var probe = new TcpListener(IPAddress.Loopback, 0))
        {
            probe.Start();
            port = ((IPEndPoint)probe.LocalEndpoint).Port;
        }
        string[] args = ["--url", $"http://127.0.0.1:{port}", "--token", "t", "--project", Project.ToString(), "--timeout", "0"];

        var (code, stdout, _) = await RunAsync(args);
        Assert.Equal(GateExit.Unreachable, code);
        Assert.Contains("unreachable:", stdout, StringComparison.Ordinal);

        var (advisoryCode, advisoryOut, _) = await RunAsync([.. args, "--advisory"]);
        Assert.Equal(0, advisoryCode);
        Assert.Contains("advisory mode", advisoryOut, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_named_commit_is_waited_for_until_that_build_has_been_evaluated()
    {
        using var stub = StartStub(
            (200, Decision("0000000000000000", "Enforcing", ("sast", "Pass", null))),
            (200, Decision("feedface12345678", "Enforcing", ("sast", "Pass", null))));

        var (code, stdout, _) = await RunAsync(["--url", stub.BaseUrl, "--token", "t", "--project", Project.ToString(),
            "--commit", "FEEDFACE12345678", "--timeout", "10", "--poll", "1"]);

        Assert.Equal(0, code);
        Assert.Equal(2, stub.Seen.Count);
        Assert.Contains("CLEAR TO SHIP", stdout, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_commit_that_never_shows_up_is_unreachable_with_the_reason()
    {
        using var stub = StartStub((200, Decision(null, "Enforcing", ("sast", "Pass", null))));

        var (code, stdout, _) = await RunAsync(Base(stub, "--commit", "abc"));

        Assert.Equal(GateExit.Unreachable, code);
        Assert.Contains("latest evaluated commit is (none), waiting for abc", stdout, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_token_can_come_from_the_environment()
    {
        using var stub = StartStub((200, Decision("c", "Enforcing", ("sast", "Pass", null))));
        Environment.SetEnvironmentVariable("TAMP_FINDINGS_INGEST_TOKEN", "env_token");
        try
        {
            var (code, _, _) = await RunAsync("--url", stub.BaseUrl, "--project", Project.ToString(), "--timeout", "0");

            Assert.Equal(0, code);
            Assert.Equal("Bearer env_token", stub.Seen[0].Authorization);
        }
        finally
        {
            Environment.SetEnvironmentVariable("TAMP_FINDINGS_INGEST_TOKEN", null);
        }
    }

    [Fact]
    public async Task A_decision_with_no_gates_list_is_a_pass_and_unparseable_numbers_fall_back_to_defaults()
    {
        using var stub = StartStub((200, """{"projectId":"11111111-2222-3333-4444-555555555555","versionString":"v","enforcementMode":"Enforcing","gatesEnabled":0,"gatesBlocking":0,"gatesFailed":0,"gatesUnknown":0}"""));

        var (code, stdout, _) = await RunAsync(["--url", stub.BaseUrl, "--token", "t", "--project", Project.ToString(),
            "--timeout", "nan", "--poll", "x", "--json"]);

        Assert.Equal(0, code);
        Assert.Contains("\"outcome\": \"Pass\"", stdout, StringComparison.Ordinal);
    }
}

[CollectionDefinition("console", DisableParallelization = true)]
public sealed class ApiBConsoleCollection;
