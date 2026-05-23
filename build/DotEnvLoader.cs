using System.IO;

namespace Tamp.Findings.Build;

// Tiny KEY=VALUE loader for repo-root .env. Lines starting with '#' and
// blank lines are skipped. Values are NOT shell-expanded (no $VAR
// substitution); quotes around the value are stripped. Existing env
// vars win — .env doesn't clobber what the operator already set.
internal static class DotEnvLoader
{
    public static void LoadFromRepoRoot()
    {
        // Walk up from the build script's working dir looking for .env
        // next to the .git folder. Falls back silently if nothing found.
        var dir = new DirectoryInfo(Directory.GetCurrentDirectory());
        while (dir is not null)
        {
            var envPath = Path.Combine(dir.FullName, ".env");
            if (File.Exists(envPath) && Directory.Exists(Path.Combine(dir.FullName, ".git")))
            {
                ApplyFile(envPath);
                return;
            }
            dir = dir.Parent;
        }
    }

    private static void ApplyFile(string path)
    {
        foreach (var raw in File.ReadAllLines(path))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            var eq = line.IndexOf('=');
            if (eq <= 0) continue;
            var key = line[..eq].Trim();
            var value = line[(eq + 1)..].Trim();
            if (value.Length >= 2
                && ((value[0] == '"' && value[^1] == '"')
                 || (value[0] == '\'' && value[^1] == '\'')))
            {
                value = value[1..^1];
            }
            if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable(key)))
            {
                Environment.SetEnvironmentVariable(key, value);
            }
        }
    }
}
