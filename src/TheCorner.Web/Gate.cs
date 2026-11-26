using System.Security.Cryptography;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace TheCorner.Web;

// What every request passes through first (from TheCornerFC's Site/Gate.cs, made site-neutral).
public static class Gate
{
    //   Strict-Transport-Security   browsers use https for a year, here and on every subdomain
    //   X-Content-Type-Options      a file is only ever what its type says
    //   Referrer-Policy             other sites see only the site's address, never the page
    //   Permissions-Policy          no page may ask for the camera, microphone, location, payment
    //                               handler or USB, or join ad-topic tracking
    //   X-Frame-Options             no other site may frame a page (old browsers; the CSP says it too)
    public static readonly IReadOnlyDictionary<string, string> SecurityHeaders = new Dictionary<string, string>
    {
        ["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains",
        ["X-Content-Type-Options"] = "nosniff",
        ["Referrer-Policy"] = "strict-origin-when-cross-origin",
        ["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()",
        ["X-Frame-Options"] = "DENY",
    };

    const string NonceKey = "csp-nonce";
    public static string Nonce(this HttpContext context) => (string)context.Items[NonceKey]!;

    static string With(string directive, IEnumerable<string> extra) =>
        string.Join(' ', new[] { directive }.Concat(extra.Distinct()));

    // What a page may load and run: this site's own files, scripts it writes into the page (named
    // by a one-off nonce), and only what the site's settings add. No inline styles; nothing may frame
    // a page. Cloudflare Web Analytics' counter is added on a copy that has an analytics token.
    public static string Policy(SiteSettings site, SiteEnvironment env, string nonce)
    {
        var analytics = env.Analytics is not null;
        string[] scripts = [$"'nonce-{nonce}'", .. site.ScriptSources, .. analytics ? ["https://static.cloudflareinsights.com"] : Array.Empty<string>()];
        string[] connect = [.. site.ConnectSources, .. analytics ? ["https://cloudflareinsights.com"] : Array.Empty<string>()];
        string[] forms = [.. site.FormActions, .. env.HasAccounts ? [env.SupabaseUrl] : Array.Empty<string>()];
        var parts = new List<string>
        {
            "default-src 'self'",
            With("script-src 'self'", scripts),
            "style-src 'self'",
            With("img-src 'self' data:", site.ImageSources),
            With("connect-src 'self'", connect),
            "manifest-src 'self'",
            "object-src 'none'",
            "base-uri 'self'",
            With("form-action 'self'", forms),
            "frame-ancestors 'none'",
        };
        if (site.FrameSources.Count > 0) parts.Insert(2, With("frame-src", site.FrameSources));
        return string.Join("; ", parts);
    }

    // Where a request is sent before any page runs, or null to go on: the site's address over http,
    // and www, go to https on the site's own address.
    public static string? Redirect(SiteEnvironment env, string scheme, string host, string path, string query) =>
        (host == env.Host && scheme == "http") || host == $"www.{env.Host}" ? $"https://{env.Host}{path}{query}" : null;

    public static IApplicationBuilder UseGate(this IApplicationBuilder app, SiteSettings site, SiteEnvironment env) => app.Use(async (context, next) =>
    {
        var request = context.Request;
        var response = context.Response;
        // The other copy's address reaching this server means staging is answering for the live
        // site or the other way round: serve nothing.
        if (request.Host.Host == site.Other(env).Host)
        {
            response.StatusCode = 500;
            await response.WriteAsync("This server is not for this site");
            return;
        }

        // hex, not Base64: a + or / would be escaped where the page writes it, and the script tag
        // would no longer match the policy
        var nonce = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        context.Items[NonceKey] = nonce;
        response.OnStarting(() =>
        {
            var h = response.Headers;
            foreach (var (k, v) in SecurityHeaders) h[k] = v;
            if (response.ContentType?.StartsWith("text/html", StringComparison.Ordinal) == true)
                h.ContentSecurityPolicy = Policy(site, env, nonce);
            // a page may differ by who asks: nothing between may hand one visitor's copy to another
            h.Append("Vary", "Cookie");
            // staging is never for search engines, whatever links to it
            if (!env.IsProduction) h["X-Robots-Tag"] = "noindex, nofollow";
            return Task.CompletedTask;
        });

        if (Redirect(env, request.Scheme, request.Host.Host, request.Path.Value ?? "/", request.QueryString.Value ?? "") is { } to)
        {
            response.StatusCode = 301;
            response.Headers.Location = to;
            return;
        }
        await next(context);
    });
}
