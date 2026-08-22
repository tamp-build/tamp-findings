using System.Globalization;
using Microsoft.Extensions.Localization;

namespace Tamp.Findings.Web.Localization;

/// <summary>
/// Wraps the real <see cref="IStringLocalizer"/> and pseudo-localises every
/// value when the current culture is <see cref="PseudoLocale.CultureName"/>.
///
/// Sits on top rather than beside the resource lookup on purpose: a string only
/// reaches this if it went through the catalogue, so anything still rendering
/// as plain ASCII under the pseudo-locale is a hardcoded literal. That is the
/// test, and it only works if the decoration happens at exactly this seam.
/// </summary>
public sealed class PseudoStringLocalizer<T> : IStringLocalizer<T>
{
    private readonly IStringLocalizer<T> _inner;

    public PseudoStringLocalizer(IStringLocalizerFactory factory) =>
        _inner = new StringLocalizer<T>(factory);

    private static bool Active =>
        string.Equals(CultureInfo.CurrentUICulture.Name, PseudoLocale.CultureName, StringComparison.OrdinalIgnoreCase);

    public LocalizedString this[string name] => Decorate(_inner[name]);

    public LocalizedString this[string name, params object[] arguments]
    {
        get
        {
            // Format FIRST, then pseudo-localise, so the arguments themselves
            // are not mangled — a build sha or a count must stay readable.
            var s = _inner[name, arguments];
            return Decorate(s);
        }
    }

    public IEnumerable<LocalizedString> GetAllStrings(bool includeParentCultures) =>
        _inner.GetAllStrings(includeParentCultures).Select(Decorate);

    private static LocalizedString Decorate(LocalizedString s) =>
        Active
            ? new LocalizedString(s.Name, PseudoLocale.Transform(s.Value), s.ResourceNotFound, s.SearchedLocation)
            : s;
}
