using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace TheCorner.Web;

public static class Endpoints
{
    // Which copy answered and the commit it was built from: what a deploy check reads to know what
    // is really live. Never cached.
    public static IEndpointRouteBuilder MapVersion(this IEndpointRouteBuilder app, SiteSettings site, SiteEnvironment env, string? commit)
    {
        app.MapGet("/version", (HttpContext c) =>
        {
            c.Response.Headers.CacheControl = "no-store";
            return Results.Json(new { site = site.Name, environment = env.Name, commit = commit ?? "local" });
        });
        return app;
    }

    // Search engines: the live site's own address may be crawled, with its sitemap named; staging,
    // or the live app reached by any other address, may not be crawled at all.
    public static string Robots(SiteEnvironment env, string host) =>
        env.IsProduction && host == env.Host
            ? $"User-agent: *\nAllow: /\n\nSitemap: https://{env.Host}/sitemap.xml\n"
            : "User-agent: *\nDisallow: /\n";

    public static IEndpointRouteBuilder MapRobots(this IEndpointRouteBuilder app, SiteEnvironment env)
    {
        app.MapGet("/robots.txt", (HttpContext c) =>
        {
            c.Response.Headers.CacheControl = "public, max-age=3600";
            return Results.Text(Robots(env, c.Request.Host.Host), "text/plain; charset=utf-8");
        });
        return app;
    }
}
