using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;
using static OpenIddict.Abstractions.OpenIddictConstants;
using OpenIddict.Server.AspNetCore;
using Microsoft.AspNetCore.Http.Extensions;
using OpenIddict.Abstractions;
using Microsoft.AspNetCore;

namespace Mimban.Server.Controllers;

[ApiController]
//[Route("[controller]")]
[Route("authorize_microsoft")]
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
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

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

