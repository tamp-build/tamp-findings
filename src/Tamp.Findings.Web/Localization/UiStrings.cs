namespace Tamp.Findings.Web.Localization;

/// <summary>
/// Marker type for the UI string catalogue. IStringLocalizer&lt;UiStrings&gt;
/// resolves against Resources/UiStrings.resx.
///
/// One catalogue for the whole app rather than one per component: the strings
/// are chrome and labels shared across screens, and splitting them would mean
/// translating "Portfolio" more than once.
/// </summary>
public sealed class UiStrings;
