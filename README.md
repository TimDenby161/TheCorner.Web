# TheCorner.Web

The security core shared by The Corner's .NET sites (The Corner World, The Corner TT; The Corner FC
later), taken from TheCornerFC's `site/` and made site-neutral. Each site adds it as a git
submodule and passes its own `SiteSettings`; a security fix lands here once.

| File | Does |
|---|---|
| `SiteEnvironment.cs` | A site's two copies (production, staging), its address, Supabase project and analytics token; `SITE_ENV` must name one or the server won't start |
| `Gate.cs` | Security headers on every response; a CSP with a fresh nonce on every page, built from the site's own allowances (a site that allows nothing outside gets a policy with no other origin in it); http→https and www→apex; the other copy's address refused; staging `noindex` |
| `Sessions.cs` | Posts only from the site's own origin (named webhook paths excepted); the Supabase session cookie (HttpOnly, Secure, SameSite=Lax); emailed links and Google sign-in finished on the server; renewal before expiry; signed-in pages never cached; return addresses kept on the site |
| `AuthClient.cs` | Supabase Auth over its web addresses: sign in and up, recover, verify, refresh, PKCE code exchange, whose token, sign out; error texts that never say whether an email has an account |
| `Endpoints.cs` | `/version` and `robots.txt` |

```csharp
var site = new SiteSettings { Name = "world", Production = new("production", "thecornerworld.com"), Staging = new("staging", "staging.thecornerworld.com") };
var env = site.Choose(builder.Configuration["SITE_ENV"]);
app.UseGate(site, env);
app.UseOriginCheck(site);          // or app.UseSessions(site) for a site with accounts (register AuthClient and TimeProvider)
app.MapVersion(site, env, builder.Configuration["COMMIT"]);
app.MapRobots(env);
```

`dotnet test` (39 tests; CI runs them on every push).
