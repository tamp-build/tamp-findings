using System.Text.RegularExpressions;
using Tamp.Findings.Web.Localization;

namespace Tamp.Findings.Api.Tests;

// Localization (TFND-67). The React i18n work retired with the SPA, and the
// hand-off's rules are stricter than what was there: strings in resources,
// composed fragments with numbered placeholders instead of embedded markup,
// and ~40% expansion verified against a pseudo-locale.
public class LocalizationTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public LocalizationTests(TestApiFactory factory) => _factory = factory;

    [Fact]
    public async Task Chrome_strings_resolve_from_the_catalogue()
    {
        // IStringLocalizer returns the KEY when a resource is missing, so a
        // resx at the wrong path fails silently and every label renders as
        // "Nav.Portfolio". Asserting the English value catches that.
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/portfolio");

        Assert.Contains("attestation evidence", body, StringComparison.Ordinal);
        Assert.DoesNotContain("Brand.Kicker", body, StringComparison.Ordinal);
        Assert.DoesNotContain("Nav.Portfolio", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_pseudo_locale_accents_pads_and_brackets_catalogue_strings()
    {
        var client = _factory.CreateSignedIn();

        var raw = await client.GetStringAsync("/portfolio?culture=" + PseudoLocale.CultureName);

        // Blazor HTML-encodes non-ASCII, so the response carries &#x27E6; and
        // not the literal bracket. Decode before asserting — checking the raw
        // response for "⟦" fails even when the culture applied perfectly.
        var body = System.Net.WebUtility.HtmlDecode(raw);

        // Brackets prove the whole string arrived; accents prove it came from
        // the catalogue rather than being hardcoded in markup.
        Assert.Contains("⟦", body, StringComparison.Ordinal);
        Assert.Contains("⟧", body, StringComparison.Ordinal);
        Assert.DoesNotContain("attestation evidence", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_lang_attribute_reflects_the_actual_culture()
    {
        // WCAG 2.1 SC 3.1.1 Language of Page. Screen readers pick a voice from
        // this, so a hardcoded "en" becomes a lie the moment a second locale
        // exists — and this product ships an accessibility scanner.
        var client = _factory.CreateSignedIn();

        var english = await client.GetStringAsync("/portfolio");
        var pseudo = await client.GetStringAsync("/portfolio?culture=" + PseudoLocale.CultureName);

        Assert.Contains("lang=\"en\"", english, StringComparison.Ordinal);
        Assert.DoesNotContain("lang=\"en\"", pseudo, StringComparison.Ordinal);
    }

    [Fact]
    public void The_pseudo_culture_can_be_constructed_in_this_process()
    {
        var culture = System.Globalization.CultureInfo.GetCultureInfo(PseudoLocale.CultureName);
        Assert.Equal(PseudoLocale.CultureName, culture.Name, ignoreCase: true);
    }

    [Fact]
    public void Pseudo_localisation_expands_by_roughly_forty_percent()
    {
        const string source = "Scanners and ingest";

        var transformed = PseudoLocale.Transform(source);

        // Brackets and padding are the point: a layout sized for the English
        // string has to survive this much more text.
        Assert.StartsWith("⟦", transformed, StringComparison.Ordinal);
        Assert.EndsWith("⟧", transformed, StringComparison.Ordinal);
        Assert.True(transformed.Length > source.Length * 1.3,
            $"expected meaningful expansion, got {transformed.Length} from {source.Length}");
    }

    [Fact]
    public void Placeholders_survive_pseudo_localisation_intact()
    {
        // Mangling a placeholder would break the very substitution being
        // tested — and the hand-off requires numbered placeholders precisely
        // so translators never see markup.
        var transformed = PseudoLocale.Transform("{0} of {1} enabled gates failing");

        Assert.Contains("{0}", transformed, StringComparison.Ordinal);
        Assert.Contains("{1}", transformed, StringComparison.Ordinal);
    }

    [Fact]
    public void Data_values_are_deliberately_not_translatable()
    {
        // "sast" is an identifier used in URLs, config and ingest payloads.
        // Translating it would break the mapping between what the screen says
        // and what the API accepts.
        var spine = UiText.Data("sast");

        Assert.Equal("sast", spine.Value);
        Assert.False(spine.ResourceNotFound);
    }

    // ------------------------------------------------------------------
    // The standing rule
    // ------------------------------------------------------------------

    [Fact]
    public void No_localized_component_carries_a_hardcoded_user_visible_string()
    {
        // The hand-off: "Strings belong in resources, never hard-coded in
        // markup." Enforced as a test rather than an analyzer — an analyzer is
        // a lot of machinery for a rule a directory scan states plainly.
        //
        // The allowlist is screens not yet localized. It should only ever
        // SHRINK: a screen joins the localized set when its ticket lands, and
        // TFND-129 should find this list empty.
        string[] localizedDirs =
        [
            "Components/Layout",
        ];

        var root = FindWebProjectRoot();
        var offenders = new List<string>();

        foreach (var dir in localizedDirs)
        {
            var full = Path.Combine(root, dir.Replace('/', Path.DirectorySeparatorChar));
            foreach (var file in Directory.EnumerateFiles(full, "*.razor", SearchOption.AllDirectories))
            {
                foreach (var literal in UserVisibleLiterals(File.ReadAllText(file)))
                {
                    offenders.Add($"{Path.GetFileName(file)}: \"{literal}\"");
                }
            }
        }

        Assert.True(offenders.Count == 0,
            "Hardcoded user-visible strings found — move them to Resources/Localization/UiStrings.resx:\n  "
            + string.Join("\n  ", offenders));
    }

    // Text sitting directly between tags, ignoring Razor expressions, comments
    // and markup. Crude on purpose: it has to be obvious what it flags.
    private static IEnumerable<string> UserVisibleLiterals(string razor)
    {
        // Strip Razor comments and the @code block — C# strings there are
        // covered by the LocalizedString parameter types instead.
        razor = Regex.Replace(razor, @"@\*.*?\*@", "", RegexOptions.Singleline);
        var codeIndex = razor.IndexOf("\n@code", StringComparison.Ordinal);
        if (codeIndex > 0) razor = razor[..codeIndex];

        foreach (Match m in Regex.Matches(razor, @">([^<>@{}]+)<"))
        {
            var text = m.Groups[1].Value.Trim();
            if (text.Length < 3) continue;
            // Punctuation-only separators and entities are not copy.
            if (!Regex.IsMatch(text, "[A-Za-z]{3}")) continue;
            // The product name is a proper noun. "tamp.findings" is not
            // translated any more than "PostgreSQL" is, and putting it in the
            // catalogue would invite someone to translate it.
            if (ProperNouns.Contains(text)) continue;
            yield return text;
        }
    }

    private static readonly HashSet<string> ProperNouns =
        new(StringComparer.Ordinal) { "tamp", ".findings", "tamp.findings" };

    private static string FindWebProjectRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "src", "Tamp.Findings.Web")))
            dir = dir.Parent;

        Assert.NotNull(dir);
        return Path.Combine(dir!.FullName, "src", "Tamp.Findings.Web");
    }
}
