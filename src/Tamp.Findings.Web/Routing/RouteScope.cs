namespace Tamp.Findings.Web.Routing;

/// <summary>
/// The current client / project / component / build / spine / selection.
///
/// The hand-off calls this out specifically: most redesign state is ordinary
/// component state, but "the scope route parameters and the policy draft are
/// the two pieces worth lifting into scoped services so several components can
/// read them". The sidebar scope card, the header URL chip, the breadcrumb and
/// every screen body all need the same answer, and they must not each parse the
/// URL for themselves.
///
/// Registered scoped, so one instance per Blazor circuit. Pages set it from
/// their route parameters; readers subscribe to <see cref="Changed"/>.
///
/// Deliberately NOT a router: it holds what the route said. Navigation goes
/// through NavigationManager with a URL from <see cref="Routes"/>.
/// </summary>
public sealed class RouteScope
{
    public string? Client { get; private set; }
    public string? Project { get; private set; }
    public string? Component { get; private set; }
    public string? Build { get; private set; }
    public string? Spine { get; private set; }
    public string? Selection { get; private set; }

    /// <summary>True once a client and project are known — most screens need both.</summary>
    public bool HasProject => Client is not null && Project is not null;

    /// <summary>Raised when any part of the scope changes. Readers call StateHasChanged.</summary>
    public event Action? Changed;

    public void SetProject(string? client, string? project, string? build = null)
    {
        if (Client == client && Project == project && Build == build) return;
        Client = client;
        Project = project;
        Build = build;
        // A new project invalidates anything narrower. Leaving a stale
        // component or selection behind is how a screen ends up showing one
        // project's data under another project's heading.
        Component = null;
        Spine = null;
        Selection = null;
        Changed?.Invoke();
    }

    public void SetBuild(string? build)
    {
        if (Build == build) return;
        Build = build;
        Changed?.Invoke();
    }

    public void SetComponent(string? component)
    {
        if (Component == component) return;
        Component = component;
        Changed?.Invoke();
    }

    public void SetExplorer(string? spine, string? selection)
    {
        if (Spine == spine && Selection == selection) return;
        Spine = spine;
        Selection = selection;
        Changed?.Invoke();
    }

    public void Clear()
    {
        if (Client is null && Project is null && Build is null && Component is null
            && Spine is null && Selection is null) return;
        Client = Project = Component = Build = Spine = Selection = null;
        Changed?.Invoke();
    }
}
