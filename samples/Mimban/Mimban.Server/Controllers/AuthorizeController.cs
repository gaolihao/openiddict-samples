using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;
using static OpenIddict.Abstractions.OpenIddictConstants;
using OpenIddict.Server.AspNetCore;
using Microsoft.AspNetCore.Http.Extensions;
using OpenIddict.Abstractions;

namespace Mimban.Server.Controllers;

[ApiController]
//[Route("[controller]")]
[Route("authorize")]
public class AuthorizeController(ILogger<AuthorizeController> logger) : ControllerBase
{
    private static readonly string[] Summaries =
    [
        "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    ];

    private readonly ILogger<AuthorizeController> logger = logger;

    [HttpGet, HttpPost]
    public async Task<IResult> Get()
    {
        /*
        return Enumerable.Range(1, 5).Select(index => new WeatherForecast
        {
            Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            TemperatureC = Random.Shared.Next(-20, 55),
            Summary = Summaries[Random.Shared.Next(Summaries.Length)]
        })
        .ToArray();
        */

        // Resolve the claims stored in the cookie created after the GitHub authentication dance.
        // If the principal cannot be found, trigger a new challenge to redirect the user to GitHub.
        //
        // For scenarios where the default authentication handler configured in the ASP.NET Core
        // authentication options shouldn't be used, a specific scheme can be specified here.

        var context = HttpContext;

        var result = (await context.AuthenticateAsync());
        var principal = result?.Principal;
        if (principal is null)
        {
            var properties = new AuthenticationProperties
            {
                RedirectUri = context.Request.GetEncodedUrl()
            };

            var r = Results.Challenge(properties, [Providers.Microsoft]);
            return r;
        }

        var name = principal.FindFirst(ClaimTypes.Name)!.Value;
        var email = principal.FindFirst(ClaimTypes.Email)!.Value;
        var identifier = principal.FindFirst(ClaimTypes.NameIdentifier)!.Value;

        // Create the claims-based identity that will be used by OpenIddict to generate tokens.
        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        // Import a few select claims from the identity stored in the local cookie.
        identity.AddClaim(new Claim(Claims.Subject, identifier));
        identity.AddClaim(new Claim(Claims.Name, name).SetDestinations(Destinations.AccessToken));
        identity.AddClaim(new Claim(Claims.PreferredUsername, identifier).SetDestinations(Destinations.AccessToken));
        identity.AddClaim(new Claim(Claims.Email, email).SetDestinations(Destinations.AccessToken));

        return Results.SignIn(new ClaimsPrincipal(identity), properties: null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
}
public class WeatherForecast
{
    public DateOnly Date { get; set; }

    public int TemperatureC { get; set; }

    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);

    public string? Summary { get; set; }
}

