using Microsoft.Extensions.Localization;

namespace Tamp.Findings.Web.Localization;

/// <summary>
/// Helpers for the places a UI label is NOT translatable copy.
/// </summary>
public static class UiText
{
    /// <summary>
    /// Wraps a value that is data rather than copy — a spine name, a rule id, a
    /// commit sha, a file path, a policy key.
    ///
    /// These must not go through the catalogue: "sast" is an identifier the
    /// product uses in URLs, config and ingest payloads, and translating it
    /// would break the mapping between what the screen says and what the API
    /// accepts. Wrapping them explicitly keeps the type system honest — a
    /// LocalizedString-typed label cannot be handed a bare literal by accident,
    /// which is what makes the "no hardcoded strings" rule enforceable.
    ///
    /// If you are reaching for this for a sentence or a button label, it is the
    /// wrong tool: put it in Resources/UiStrings.resx.
    /// </summary>
    public static LocalizedString Data(string value) => new(value, value, resourceNotFound: false);
}
