namespace TheCorner.Web;

// One copy of a site: production or staging, its address, and (where it has accounts) the Supabase
// project it signs people in with. Nothing here is secret: a project's id and publishable key only
// identify it; the database decides what the key may do. Analytics is the Cloudflare Web Analytics
// token (public, it is in every page), or null for none.
public sealed record SiteEnvironment(string Name, string Host, string? SupabaseProject = null, string? SupabaseKey = null, string? Analytics = null)
{
    public bool IsProduction => Name == "production";
    public bool HasAccounts => SupabaseProject is not null && SupabaseKey is not null;
    public string SupabaseUrl => HasAccounts ? $"https://{SupabaseProject}.supabase.co"
        : throw new InvalidOperationException($"{Host} has no Supabase project");
}

// What a site allows beyond its own address, and its two copies. Each site makes one of these at
// start-up; the Gate builds the page policy from it, so one site's allowances never reach another.
public sealed record SiteSettings
{
    public required string Name { get; init; }
    public required SiteEnvironment Production { get; init; }
    public required SiteEnvironment Staging { get; init; }

    // Other origins pages may load scripts, images or frames from, post forms to, or talk to.
    // World leaves them all empty: its browser talks to thecornerworld.com and nothing else.
    public IReadOnlyList<string> ScriptSources { get; init; } = [];
    public IReadOnlyList<string> ImageSources { get; init; } = [];
    public IReadOnlyList<string> FrameSources { get; init; } = [];
    public IReadOnlyList<string> FormActions { get; init; } = [];
    public IReadOnlyList<string> ConnectSources { get; init; } = [];

    // Pages under these path prefixes get this whole policy instead of the site's own (the longest
    // prefix wins): for pages that can't keep to the site's policy, such as a trip page that styles
    // itself inline. Name the narrowest prefix that will do, and keep frame-ancestors 'none' in it.
    public IReadOnlyList<(string Prefix, string Policy)> PagePolicies { get; init; } = [];

    // Paths that take posts from other sites, each known by its own signature (a payment
    // provider's webhook). Every other post must come from the site's own pages.
    public IReadOnlyList<string> CrossSitePostPaths { get; init; } = [];

    // Where a visitor lands to sign in, and where emailed links that fail are reported
    public string AccountPath { get; init; } = "/account";

    public SiteEnvironment Other(SiteEnvironment env) => env == Production ? Staging : Production;

    // A server must say which copy it is (the app setting SITE_ENV). There is no default: one that
    // names neither fails to start, so a staging server can never quietly serve as the live site.
    public SiteEnvironment Choose(string? name) => name switch
    {
        "production" => Production,
        "staging" => Staging,
        _ => throw new InvalidOperationException($"SITE_ENV must be production or staging (got '{name ?? "nothing"}')"),
    };
}
