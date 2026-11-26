using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Time.Testing;

namespace TheCorner.Web.Tests;

// A site with accounts (as TT will be) and one without and allowing nothing outside (as World is)
static class Sites
{
    public static readonly SiteSettings WithAccounts = new()
    {
        Name = "test",
        Production = new("production", "example.com", "prodproj", "sb_publishable_prod", Analytics: "token"),
        Staging = new("staging", "staging.example.com", "stageproj", "sb_publishable_stage"),
        CrossSitePostPaths = ["/stripe/webhook"],
    };
    public static readonly SiteSettings Closed = new()
    {
        Name = "world",
        Production = new("production", "world.example"),
        Staging = new("staging", "staging.world.example"),
    };
}

// Supabase Auth, played by the test: answers by path, and counts the calls
sealed class FakeAuth(Func<HttpRequestMessage, HttpResponseMessage> answer) : HttpMessageHandler
{
    public List<string> Calls { get; } = [];
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    {
        Calls.Add(request.RequestUri!.PathAndQuery);
        return Task.FromResult(answer(request));
    }
    public static HttpResponseMessage Json(HttpStatusCode status, object body) =>
        new(status) { Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json") };
}

sealed class TestSite : IAsyncDisposable
{
    public required IHost Host { get; init; }
    public required FakeAuth Auth { get; init; }
    public required FakeTimeProvider Clock { get; init; }
    public HttpClient Client(string host = "example.com", bool https = true)
    {
        var c = Host.GetTestServer().CreateClient();
        c.BaseAddress = new Uri($"{(https ? "https" : "http")}://{host}/");
        return c;
    }
    public ValueTask DisposeAsync() { Host.Dispose(); return ValueTask.CompletedTask; }

    public static async Task<TestSite> Start(SiteSettings site, string envName = "production", Func<HttpRequestMessage, HttpResponseMessage>? auth = null)
    {
        var env = site.Choose(envName);
        var fake = new FakeAuth(auth ?? (_ => new HttpResponseMessage(HttpStatusCode.InternalServerError)));
        var clock = new FakeTimeProvider(DateTimeOffset.Parse("2026-11-26T12:00:00Z"));
        var host = await new HostBuilder().ConfigureWebHost(web => web.UseTestServer()
            .ConfigureServices(s =>
            {
                s.AddRouting();
                s.AddSingleton<TimeProvider>(clock);
                if (env.HasAccounts) s.AddSingleton(new AuthClient(new HttpClient(fake), env));
            })
            .Configure(app =>
            {
                app.UseGate(site, env);
                if (env.HasAccounts) app.UseSessions(site); else app.UseOriginCheck(site);
                app.UseRouting();
                app.UseEndpoints(e =>
                {
                    e.MapGet("/", (HttpContext c) => Results.Content($"<p>{(Visitor.Of(c).SignedIn ? "in" : "out")} {c.Nonce()}</p>", "text/html"));
                    e.MapGet("/data.json", () => Results.Json(new { ok = true }));
                    e.MapPost("/form", () => Results.Text("posted"));
                    e.MapPost("/stripe/webhook", () => Results.Text("webhook"));
                    e.MapVersion(site, env, "abc123");
                    e.MapRobots(env);
                });
            })).StartAsync();
        return new TestSite { Host = host, Auth = fake, Clock = clock };
    }
}

public class GateTests
{
    [Fact]
    public async Task Every_response_carries_the_security_headers_and_pages_the_policy()
    {
        await using var site = await TestSite.Start(Sites.WithAccounts);
        var page = await site.Client().GetAsync("/");
        var json = await site.Client().GetAsync("/data.json");
        foreach (var r in new[] { page, json })
            foreach (var (k, v) in Gate.SecurityHeaders) Assert.Equal(v, r.Headers.GetValues(k).Single());
        Assert.True(page.Headers.Contains("Content-Security-Policy"));
        Assert.False(json.Headers.Contains("Content-Security-Policy"));
    }

    [Fact]
    public async Task The_nonce_is_fresh_for_each_page_and_is_the_one_in_its_policy()
    {
        await using var site = await TestSite.Start(Sites.WithAccounts);
        var a = await site.Client().GetAsync("/");
        var b = await site.Client().GetAsync("/");
        var nonceA = (await a.Content.ReadAsStringAsync()).Split(' ')[1].TrimEnd('<', '/', 'p', '>');
        var nonceB = (await b.Content.ReadAsStringAsync()).Split(' ')[1].TrimEnd('<', '/', 'p', '>');
        Assert.NotEqual(nonceA, nonceB);
        Assert.Matches("^[0-9a-f]{32}$", nonceA);
        Assert.Contains($"'nonce-{nonceA}'", a.Headers.GetValues("Content-Security-Policy").Single());
    }

    [Fact]
    public void A_closed_site_allows_nothing_from_anywhere_else()
    {
        var policy = Gate.Policy(Sites.Closed, Sites.Closed.Production, "n");
        Assert.DoesNotContain("https://", policy);
        Assert.Contains("default-src 'self'", policy);
        Assert.Contains("frame-ancestors 'none'", policy);
        Assert.Contains("object-src 'none'", policy);
        Assert.DoesNotContain("unsafe-inline", policy);
        Assert.DoesNotContain("unsafe-eval", policy);
    }

    [Fact]
    public void A_named_path_gets_its_own_policy_and_nothing_else_does()
    {
        var site = Sites.Closed with { PagePolicies = [("/c/", "client"), ("/plan/samples/", "trip"), ("/plan/samples/x/", "narrow")] };
        Assert.Equal("client", Gate.PolicyFor(site, site.Production, "/c/abc/", "n"));
        Assert.Equal("trip", Gate.PolicyFor(site, site.Production, "/plan/samples/japan/", "n"));
        Assert.Equal("narrow", Gate.PolicyFor(site, site.Production, "/plan/samples/x/", "n"));
        Assert.Equal(Gate.Policy(site, site.Production, "n"), Gate.PolicyFor(site, site.Production, "/plan/", "n"));
        Assert.Equal(Gate.Policy(site, site.Production, "n"), Gate.PolicyFor(site, site.Production, "/cat/", "n"));
    }

    [Fact]
    public void Analytics_and_sign_in_are_allowed_only_where_that_copy_has_them()
    {
        var live = Gate.Policy(Sites.WithAccounts, Sites.WithAccounts.Production, "n");
        var staging = Gate.Policy(Sites.WithAccounts, Sites.WithAccounts.Staging, "n");
        Assert.Contains("https://static.cloudflareinsights.com", live);
        Assert.DoesNotContain("cloudflareinsights", staging);
        Assert.Contains("form-action 'self' https://prodproj.supabase.co", live);
        Assert.Contains("form-action 'self' https://stageproj.supabase.co", staging);
    }

    [Theory]
    [InlineData("example.com", false, "https://example.com/a?b=1")]
    [InlineData("www.example.com", true, "https://example.com/a?b=1")]
    public async Task Http_and_www_go_to_https_on_the_site_itself(string host, bool https, string to)
    {
        await using var site = await TestSite.Start(Sites.WithAccounts);
        var r = await site.Client(host, https).GetAsync("/a?b=1");
        Assert.Equal(HttpStatusCode.MovedPermanently, r.StatusCode);
        Assert.Equal(to, r.Headers.Location!.ToString());
    }

    [Fact]
    public async Task The_other_copys_address_gets_nothing()
    {
        await using var live = await TestSite.Start(Sites.WithAccounts);
        await using var staging = await TestSite.Start(Sites.WithAccounts, "staging");
        Assert.Equal(HttpStatusCode.InternalServerError, (await live.Client("staging.example.com").GetAsync("/")).StatusCode);
        Assert.Equal(HttpStatusCode.InternalServerError, (await staging.Client("example.com").GetAsync("/")).StatusCode);
    }

    [Fact]
    public async Task Staging_is_never_for_search_engines()
    {
        await using var staging = await TestSite.Start(Sites.WithAccounts, "staging");
        await using var live = await TestSite.Start(Sites.WithAccounts);
        var s = await staging.Client("staging.example.com").GetAsync("/");
        Assert.Equal("noindex, nofollow", s.Headers.GetValues("X-Robots-Tag").Single());
        Assert.False((await live.Client().GetAsync("/")).Headers.Contains("X-Robots-Tag"));
        Assert.Contains("Disallow: /", await staging.Client("staging.example.com").GetStringAsync("/robots.txt"));
        Assert.Contains("Allow: /", await live.Client().GetStringAsync("/robots.txt"));
    }

    [Fact]
    public void A_server_must_say_which_copy_it_is()
    {
        Assert.Throws<InvalidOperationException>(() => Sites.WithAccounts.Choose(null));
        Assert.Throws<InvalidOperationException>(() => Sites.WithAccounts.Choose("prod"));
        Assert.Equal("staging", Sites.WithAccounts.Choose("staging").Name);
    }

    [Fact]
    public async Task Version_says_which_copy_and_commit()
    {
        await using var site = await TestSite.Start(Sites.WithAccounts, "staging");
        var v = await site.Client("staging.example.com").GetStringAsync("/version");
        Assert.Contains("\"environment\":\"staging\"", v);
        Assert.Contains("\"commit\":\"abc123\"", v);
    }
}

public class OriginTests
{
    static HttpRequestMessage Post(string path, string? origin)
    {
        var m = new HttpRequestMessage(HttpMethod.Post, path) { Content = new StringContent("x") };
        if (origin is not null) m.Headers.Add("Origin", origin);
        return m;
    }

    [Theory]
    [InlineData(null)]
    [InlineData("https://evil.example")]
    [InlineData("http://example.com")]
    [InlineData("https://example.com.evil.example")]
    public async Task A_post_from_anywhere_but_the_site_is_refused(string? origin)
    {
        await using var site = await TestSite.Start(Sites.WithAccounts);
        Assert.Equal(HttpStatusCode.Forbidden, (await site.Client().SendAsync(Post("/form", origin))).StatusCode);
    }

    [Fact]
    public async Task A_post_from_the_sites_own_pages_goes_through()
    {
        await using var site = await TestSite.Start(Sites.WithAccounts);
        Assert.Equal("posted", await (await site.Client().SendAsync(Post("/form", "https://example.com"))).Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Only_the_named_webhook_takes_posts_from_elsewhere()
    {
        await using var site = await TestSite.Start(Sites.WithAccounts);
        Assert.Equal("webhook", await (await site.Client().SendAsync(Post("/stripe/webhook", null))).Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task A_site_without_accounts_still_refuses_cross_site_posts()
    {
        await using var site = await TestSite.Start(Sites.Closed);
        Assert.Equal(HttpStatusCode.Forbidden, (await site.Client("world.example").SendAsync(Post("/form", "https://evil.example"))).StatusCode);
    }
}

public class SessionTests
{
    static string CookieFor(Session s) => $"{Sessions.Cookie}={Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(s))}";
    static readonly object Fresh = new { access_token = "new-access", refresh_token = "new-refresh", expires_in = 3600, user = new { id = "u1", email = "a@example.com" } };

    static async Task<HttpResponseMessage> Get(TestSite site, string path, string? cookie = null)
    {
        var m = new HttpRequestMessage(HttpMethod.Get, path);
        if (cookie is not null) m.Headers.Add("Cookie", cookie);
        return await site.Client().SendAsync(m);
    }

    [Fact]
    public async Task A_valid_session_signs_in_and_its_pages_are_never_cached()
    {
        await using var site = await TestSite.Start(Sites.WithAccounts);
        var s = new Session("a", "r", site.Clock.GetUtcNow().AddHours(1).ToUnixTimeSeconds(), "u1", "a@example.com");
        var r = await Get(site, "/", CookieFor(s));
        Assert.StartsWith("<p>in", await r.Content.ReadAsStringAsync());
        Assert.True(r.Headers.CacheControl!.Private && r.Headers.CacheControl.NoStore);
        Assert.Empty(site.Auth.Calls);
    }

    [Theory]
    [InlineData("%25%25%25")]
    [InlineData("e30=")] // {}
    public async Task A_broken_cookie_is_signed_out_and_forgotten(string raw)
    {
        await using var site = await TestSite.Start(Sites.WithAccounts);
        var r = await Get(site, "/", $"{Sessions.Cookie}={raw}");
        Assert.StartsWith("<p>out", await r.Content.ReadAsStringAsync());
        Assert.Contains(r.Headers.GetValues("Set-Cookie"), c => c.StartsWith($"{Sessions.Cookie}=;"));
    }

    [Fact]
    public async Task A_session_about_to_run_out_is_renewed_in_a_locked_down_cookie()
    {
        await using var site = await TestSite.Start(Sites.WithAccounts, auth: _ => FakeAuth.Json(HttpStatusCode.OK, Fresh));
        var s = new Session("a", "old-refresh", site.Clock.GetUtcNow().AddSeconds(30).ToUnixTimeSeconds(), "u1", "a@example.com");
        var r = await Get(site, "/", CookieFor(s));
        Assert.StartsWith("<p>in", await r.Content.ReadAsStringAsync());
        Assert.Contains("/auth/v1/token?grant_type=refresh_token", site.Auth.Calls.Single());
        var set = r.Headers.GetValues("Set-Cookie").Single();
        Assert.Contains("httponly", set.ToLowerInvariant());
        Assert.Contains("samesite=lax", set.ToLowerInvariant());
        Assert.Contains("secure", set.ToLowerInvariant());
    }

    [Fact]
    public async Task A_session_the_service_refuses_is_forgotten()
    {
        await using var site = await TestSite.Start(Sites.WithAccounts, auth: _ => FakeAuth.Json(HttpStatusCode.BadRequest, new { error_code = "refresh_token_not_found" }));
        var s = new Session("a", "r", site.Clock.GetUtcNow().ToUnixTimeSeconds(), "u1", "a@example.com");
        var r = await Get(site, "/", CookieFor(s));
        Assert.StartsWith("<p>out", await r.Content.ReadAsStringAsync());
        Assert.Contains(r.Headers.GetValues("Set-Cookie"), c => c.StartsWith($"{Sessions.Cookie}=;"));
    }

    [Fact]
    public async Task A_session_that_couldnt_be_checked_just_now_is_kept_for_next_time()
    {
        await using var site = await TestSite.Start(Sites.WithAccounts, auth: _ => throw new HttpRequestException("down"));
        var s = new Session("a", "r", site.Clock.GetUtcNow().ToUnixTimeSeconds(), "u1", "a@example.com");
        var r = await Get(site, "/", CookieFor(s));
        Assert.StartsWith("<p>out", await r.Content.ReadAsStringAsync());
        Assert.False(r.Headers.Contains("Set-Cookie"));
    }

    [Fact]
    public async Task An_emailed_link_signs_in_and_returns_to_the_page_without_its_token()
    {
        await using var site = await TestSite.Start(Sites.WithAccounts, auth: _ => FakeAuth.Json(HttpStatusCode.OK, Fresh));
        var r = await Get(site, "/places/?tab=x&token_hash=abc&type=signup");
        Assert.Equal(HttpStatusCode.SeeOther, r.StatusCode);
        Assert.Equal("/places/?tab=x", r.Headers.Location!.ToString());
        Assert.Contains(r.Headers.GetValues("Set-Cookie"), c => c.StartsWith($"{Sessions.Cookie}=") && !c.StartsWith($"{Sessions.Cookie}=;"));
    }

    [Fact]
    public async Task A_link_can_never_send_the_visitor_to_another_site()
    {
        await using var site = await TestSite.Start(Sites.WithAccounts, auth: _ => FakeAuth.Json(HttpStatusCode.OK, Fresh));
        var r = await Get(site, "https://example.com//evil.example/x?token_hash=abc&type=signup");
        Assert.Equal(HttpStatusCode.SeeOther, r.StatusCode);
        Assert.Equal("/", r.Headers.Location!.ToString());
    }

    [Fact]
    public async Task A_used_or_expired_link_opens_the_account_page_saying_so()
    {
        await using var site = await TestSite.Start(Sites.WithAccounts, auth: _ => FakeAuth.Json(HttpStatusCode.Forbidden, new { error_code = "otp_expired" }));
        var r = await Get(site, "/?token_hash=abc&type=recovery");
        Assert.Equal("/account?failed=otp_expired", r.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Googles_return_without_this_browsers_key_fails_safely()
    {
        await using var site = await TestSite.Start(Sites.WithAccounts);
        var r = await Get(site, "/?code=abc");
        Assert.Equal("/account?failed=pkce_code_verifier_not_found", r.Headers.Location!.ToString());
        Assert.Empty(site.Auth.Calls);
    }
}

public class AuthTests
{
    [Theory]
    [InlineData("/account", "/account")]
    [InlineData("/places/japan/?tab=weather", "/places/japan/?tab=weather")]
    [InlineData("//evil.example", "/")]
    [InlineData("https://evil.example", "/")]
    [InlineData("/\\evil.example", "/")]
    [InlineData("javascript:alert(1)", "/")]
    [InlineData("", "/")]
    [InlineData(null, "/")]
    public void Return_addresses_stay_on_the_site(string? to, string expected) => Assert.Equal(expected, AuthClient.SafePath(to));

    [Fact]
    public void Errors_never_say_whether_an_email_has_an_account()
    {
        // a wrong password and an unknown email read the same
        Assert.Equal(AuthClient.ErrorText("invalid_credentials"), AuthClient.ErrorText(new AuthAnswer(null, "invalid_credentials", 400)));
        Assert.DoesNotContain("no account", AuthClient.ErrorText("invalid_credentials").ToLowerInvariant());
        Assert.Equal("Something went wrong. Try again in a moment.", AuthClient.ErrorText("user_not_found"));
    }

    [Fact]
    public void A_session_needs_both_tokens_and_an_account()
    {
        var now = DateTimeOffset.Parse("2026-11-26T12:00:00Z");
        Assert.Null(AuthClient.SessionOf("""{"user":{"id":"u1"}}""", now));
        var s = AuthClient.SessionOf("""{"access_token":"a","refresh_token":"r","expires_in":60,"user":{"id":"u1","email":"e"}}""", now)!;
        Assert.Equal(now.ToUnixTimeSeconds() + 60, s.ExpiresAt);
    }

    [Fact]
    public void Google_sign_in_uses_a_fresh_pkce_key()
    {
        var auth = new AuthClient(new HttpClient(), Sites.WithAccounts.Production);
        var (url1, v1) = auth.GoogleUrl("https://example.com/");
        var (_, v2) = auth.GoogleUrl("https://example.com/");
        Assert.NotEqual(v1, v2);
        Assert.StartsWith("https://prodproj.supabase.co/auth/v1/authorize?provider=google", url1);
        Assert.Contains("code_challenge_method=s256", url1);
    }

    [Fact]
    public void A_site_without_accounts_has_no_sign_in_service()
    {
        Assert.False(Sites.Closed.Production.HasAccounts);
        Assert.Throws<InvalidOperationException>(() => Sites.Closed.Production.SupabaseUrl);
    }
}
