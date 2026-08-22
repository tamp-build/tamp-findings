namespace Tamp.Findings.Web.Components.Primitives;

// Vendored lucide glyphs (ISC licence), as inline SVG path data.
//
// There is no official Blazor package for lucide and none is needed — the
// icons are plain SVG. They are vendored rather than fetched so the app stays
// self-contained and works air-gapped, the same reasoning as the fonts.
//
// DO NOT substitute a Material or Fluent icon set: stroke-width 1.5 is part
// of the aesthetic, and those sets are drawn on different grids at different
// weights.
//
// Severity ladders, status marks and registration corners are deliberately
// NOT here — they are text glyphs and CSS, not assets.
//
// To add a glyph, take the inner markup of the icon's .svg from lucide-static
// and paste it as a new entry. Keep the list alphabetical.
internal static class LucideIcons
{
    internal static readonly IReadOnlyDictionary<string, string> Paths =
        new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["activity"] = @"<path d=""M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2"" />",
        ["check"] = @"<path d=""M20 6 9 17l-5-5"" />",
        ["chevron-down"] = @"<path d=""m6 9 6 6 6-6"" />",
        ["chevron-left"] = @"<path d=""m15 18-6-6 6-6"" />",
        ["chevron-right"] = @"<path d=""m9 18 6-6-6-6"" />",
        ["circle-alert"] = @"<circle cx=""12"" cy=""12"" r=""10"" /> <line x1=""12"" x2=""12"" y1=""8"" y2=""12"" /> <line x1=""12"" x2=""12.01"" y1=""16"" y2=""16"" />",
        ["clock"] = @"<circle cx=""12"" cy=""12"" r=""10"" /> <path d=""M12 6v6l4 2"" />",
        ["copy"] = @"<rect width=""14"" height=""14"" x=""8"" y=""8"" rx=""2"" ry=""2"" /> <path d=""M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"" />",
        ["download"] = @"<path d=""M12 15V3"" /> <path d=""M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"" /> <path d=""m7 10 5 5 5-5"" />",
        ["external-link"] = @"<path d=""M15 3h6v6"" /> <path d=""M10 14 21 3"" /> <path d=""M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"" />",
        ["eye"] = @"<path d=""M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0"" /> <circle cx=""12"" cy=""12"" r=""3"" />",
        ["file-text"] = @"<path d=""M6 22a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h8a2.4 2.4 0 0 1 1.704.706l3.588 3.588A2.4 2.4 0 0 1 20 8v12a2 2 0 0 1-2 2z"" /> <path d=""M14 2v5a1 1 0 0 0 1 1h5"" /> <path d=""M10 9H8"" /> <path d=""M16 13H8"" /> <path d=""M16 17H8"" />",
        ["folder"] = @"<path d=""M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"" />",
        ["git-commit-horizontal"] = @"<circle cx=""12"" cy=""12"" r=""3"" /> <line x1=""3"" x2=""9"" y1=""12"" y2=""12"" /> <line x1=""15"" x2=""21"" y1=""12"" y2=""12"" />",
        ["link"] = @"<path d=""M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"" /> <path d=""M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"" />",
        ["lock"] = @"<rect width=""18"" height=""11"" x=""3"" y=""11"" rx=""2"" ry=""2"" /> <path d=""M7 11V7a5 5 0 0 1 10 0v4"" />",
        ["log-out"] = @"<path d=""m16 17 5-5-5-5"" /> <path d=""M21 12H9"" /> <path d=""M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"" />",
        ["package"] = @"<path d=""M11 21.73a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73z"" /> <path d=""M12 22V12"" /> <polyline points=""3.29 7 12 12 20.71 7"" /> <path d=""m7.5 4.27 9 5.15"" />",
        ["pencil"] = @"<path d=""M21.174 6.812a1 1 0 0 0-3.986-3.987L3.842 16.174a2 2 0 0 0-.5.83l-1.321 4.352a.5.5 0 0 0 .623.622l4.353-1.32a2 2 0 0 0 .83-.497z"" /> <path d=""m15 5 4 4"" />",
        ["play"] = @"<path d=""M5 5a2 2 0 0 1 3.008-1.728l11.997 6.998a2 2 0 0 1 .003 3.458l-12 7A2 2 0 0 1 5 19z"" />",
        ["plus"] = @"<path d=""M5 12h14"" /> <path d=""M12 5v14"" />",
        ["printer"] = @"<path d=""M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"" /> <path d=""M6 9V3a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v6"" /> <rect x=""6"" y=""14"" width=""12"" height=""8"" rx=""1"" />",
        ["refresh-cw"] = @"<path d=""M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"" /> <path d=""M21 3v5h-5"" /> <path d=""M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"" /> <path d=""M8 16H3v5"" />",
        ["search"] = @"<path d=""m21 21-4.34-4.34"" /> <circle cx=""11"" cy=""11"" r=""8"" />",
        ["settings"] = @"<path d=""M9.671 4.136a2.34 2.34 0 0 1 4.659 0 2.34 2.34 0 0 0 3.319 1.915 2.34 2.34 0 0 1 2.33 4.033 2.34 2.34 0 0 0 0 3.831 2.34 2.34 0 0 1-2.33 4.033 2.34 2.34 0 0 0-3.319 1.915 2.34 2.34 0 0 1-4.659 0 2.34 2.34 0 0 0-3.32-1.915 2.34 2.34 0 0 1-2.33-4.033 2.34 2.34 0 0 0 0-3.831A2.34 2.34 0 0 1 6.35 6.051a2.34 2.34 0 0 0 3.319-1.915"" /> <circle cx=""12"" cy=""12"" r=""3"" />",
        ["shield"] = @"<path d=""M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"" />",
        ["trash-2"] = @"<path d=""M10 11v6"" /> <path d=""M14 11v6"" /> <path d=""M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"" /> <path d=""M3 6h18"" /> <path d=""M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"" />",
        ["triangle-alert"] = @"<path d=""m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"" /> <path d=""M12 9v4"" /> <path d=""M12 17h.01"" />",
        ["user"] = @"<path d=""M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"" /> <circle cx=""12"" cy=""7"" r=""4"" />",
        ["x"] = @"<path d=""M18 6 6 18"" /> <path d=""m6 6 12 12"" />",
    };
}
