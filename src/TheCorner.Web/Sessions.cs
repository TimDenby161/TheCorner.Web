using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace TheCorner.Web;

// Who is asking: signed in or not. The token is what the database checks for itself on every
// request it is sent with, so nothing here decides what a visitor may see.
public sealed record Visitor(Session? Session)
{
    public bool SignedIn => Session is not null;
    public static Visitor Of(HttpContext c) => c.Items[nameof(Visitor)] as Visitor ?? new((Session?)null);
}

// Posts only from the site's own pages, and who is signed in (from TheCornerFC's Site/Sessions.cs).
// The session lives in a cookie the page's scripts can't read (HttpOnly), sent only to this site
// and, over HTTPS, only over HTTPS; nothing about it is kept in the browser's storage.
public static class Sessions
{
    public const string Cookie = "sb-session", PkceCookie = "sb-pkce";
    // a session is renewed when it has less than this left (as Supabase's own library does)
    static readonly TimeSpan Margin = TimeSpan.FromSeconds(90);
    // the kinds of emailed link that sign in
    static readonly HashSet<string> LinkTypes = ["signup", "email", "recovery", "magiclink", "invite", "email_change"];
    static readonly string[] LinkParams = ["code", "token_hash", "type", "error", "error_code", "error_description"];

    static CookieOptions Options(HttpRequest request, TimeSpan life) => new()
    {
        HttpOnly = true, Secure = request.IsHttps, SameSite = SameSiteMode.Lax, Path = "/", MaxAge = life,
    };
    public static void Keep(HttpContext c, Session s) =>
        c.Response.Cookies.Append(Cookie, Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(s)), Options(c.Request, TimeSpan.FromDays(400)));
    public static void Forget(HttpContext c) => c.Response.Cookies.Delete(Cookie, Options(c.Request, TimeSpan.Zero));
    public static void KeepVerifier(HttpContext c, string verifier) => c.Response.Cookies.Append(PkceCookie, verifier, Options(c.Request, TimeSpan.FromMinutes(10)));

    public static Session? Read(HttpRequest request)
    {
        if (request.Cookies[Cookie] is not { Length: > 0 } raw) return null;
        try
        {
            var s = JsonSerializer.Deserialize<Session>(Encoding.UTF8.GetString(Convert.FromBase64String(raw)));
            return s is { AccessToken.Length: > 0, RefreshToken.Length: > 0, UserId.Length: > 0 } ? s : null;
        }
        catch (Exception e) when (e is FormatException or JsonException or DecoderFallbackException) { return null; }
    }

    // A form or a script's post may only come from this site's own pages. One from anywhere else, or
    // that won't say where it's from, goes no further. The site's named cross-site paths (a payment
    // webhook, known by its signature) are the exception; a refusal of theirs re-run as an error
    // page still counts as theirs.
    public static bool PostAllowed(SiteSettings site, HttpContext context)
    {
        var request = context.Request;
        if (!HttpMethods.IsPost(request.Method)) return true;
        var sentTo = context.Features.Get<IStatusCodeReExecuteFeature>()?.OriginalPath
            ?? context.Features.Get<IExceptionHandlerPathFeature>()?.Path ?? request.Path.Value;
        if (sentTo is not null && site.CrossSitePostPaths.Contains(sentTo)) return true;
        return request.Headers.Origin.ToString() == $"{request.Scheme}://{request.Host}";
    }

    // Posts from the site's own pages only. For a site without accounts (World today) this is all.
    public static IApplicationBuilder UseOriginCheck(this IApplicationBuilder app, SiteSettings site) => app.Use(async (context, next) =>
    {
        if (!PostAllowed(site, context))
        {
            context.Response.StatusCode = 403;
            await context.Response.WriteAsync("Cross-site form submissions are forbidden");
            return;
        }
        await next(context);
    });

    // The origin check, then sign-in: emailed links and Google's return are finished here, the
    // session renewed when about to run out, and a signed-in visitor's pages never cached. Needs
    // AuthClient and TimeProvider registered.
    public static IApplicationBuilder UseSessions(this IApplicationBuilder app, SiteSettings site) => app.UseOriginCheck(site).Use(async (context, next) =>
    {
        var auth = context.RequestServices.GetRequiredService<AuthClient>();
        var clock = context.RequestServices.GetRequiredService<TimeProvider>();
        var request = context.Request;
        var q = request.Query;

        // Back from an emailed link (?token_hash=&type=) or from Google (?code=): finish the sign-in,
        // then show the same address without those. A link that has expired or been used opens the
        // account page saying so.
        if (HttpMethods.IsGet(request.Method) && (q.ContainsKey("token_hash") || q.ContainsKey("code") || q.ContainsKey("error_description")))
        {
            var kept = q.Where(kv => !LinkParams.Contains(kv.Key))
                .SelectMany(kv => kv.Value.Select(v => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(v ?? "")}")).ToList();
            var back = AuthClient.SafePath($"{request.Path}{(kept.Count > 0 ? "?" + string.Join('&', kept) : "")}");
            string? failed = q.ContainsKey("error_description") ? (q["error_code"].ToString() is { Length: > 0 } ec ? ec : "error") : null;
            var recovery = false;
            if (failed is null && q.ContainsKey("token_hash") && LinkTypes.Contains(q["type"].ToString()))
            {
                var a = await auth.Verify(q["token_hash"]!, q["type"]!);
                if (a.Ok && a.Session is { } s) Keep(context, s); else failed = a.Code ?? "error";
                recovery = q["type"] == "recovery";
            }
            else if (failed is null && q.ContainsKey("code"))
            {
                var verifier = request.Cookies[PkceCookie];
                var a = verifier is { Length: > 0 } v ? await auth.ExchangeCode(q["code"]!, v) : new AuthAnswer(null, "pkce_code_verifier_not_found", 400);
                if (a.Ok && a.Session is { } s) Keep(context, s); else failed = a.Code ?? "error";
                context.Response.Cookies.Delete(PkceCookie, Options(request, TimeSpan.Zero));
            }
            else if (failed is null) failed = "error";
            context.Response.StatusCode = 303;
            context.Response.Headers.Location = failed is not null ? $"{site.AccountPath}?failed={Uri.EscapeDataString(failed)}"
                : recovery ? $"{site.AccountPath}?view=newpass" : back;
            return;
        }

        // Who is signed in, if anyone: renewed first when the access token is about to run out. A
        // session the service no longer knows is forgotten; one it couldn't be asked about just now
        // counts as signed out for this request and is kept for the next.
        var session = Read(request);
        if (session is not null && DateTimeOffset.FromUnixTimeSeconds(session.ExpiresAt) - clock.GetUtcNow() < Margin)
        {
            var a = await auth.Refresh(session.RefreshToken);
            if (a.Ok && a.Session is { } fresh) { session = fresh; Keep(context, fresh); }
            else { if (!a.Unreachable) Forget(context); session = null; }
        }
        else if (session is null && request.Cookies.ContainsKey(Cookie)) Forget(context);
        var visitor = new Visitor(session);
        context.Items[nameof(Visitor)] = visitor;

        // a signed-in visitor's pages are never kept, by the browser or anything between
        if (visitor.SignedIn)
            context.Response.OnStarting(() => { context.Response.Headers.CacheControl = "private, no-store"; return Task.CompletedTask; });
        await next(context);
    });
}
