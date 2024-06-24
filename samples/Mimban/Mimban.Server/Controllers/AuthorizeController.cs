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
using Microsoft.AspNetCore.Identity;
using Mimban.Server.Models;

namespace Mimban.Server.Controllers;

[ApiController]
//[Route("[controller]")]
[Route("authorize_microsoft")]
public class AuthorizeController : ControllerBase
{
    private static readonly string[] Summaries =
    [
        "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    ];

    //private readonly ILogger<AuthorizeController> logger = logger;
    private readonly UserManager<ApplicationUser> userManager;

    public AuthorizeController(
        UserManager<ApplicationUser> userManager)
    {
        this.userManager = userManager;
    }


    [HttpGet, HttpPost]
    public async Task<IResult> Get()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        var context = HttpContext;

        // Important: when using ASP.NET Core Identity and its default UI, the identity created in this action is
        // not directly persisted in the final authentication cookie (called "application cookie" by Identity) but
        // in an intermediate authentication cookie called "external cookie" (the final authentication cookie is
        // later created by Identity's ExternalLogin Razor Page by calling SignInManager.ExternalLoginSignInAsync()).
        //
        // Unfortunately, this process doesn't preserve the claims added here, which prevents flowing claims
        // returned by the external provider down to the final authentication cookie. For scenarios that
        // require that, the claims can be stored in Identity's database by calling UserManager.AddClaimAsync()
        // directly in this action or by scaffolding the ExternalLogin.cshtml page that is part of the default UI:
        // https://learn.microsoft.com/en-us/aspnet/core/security/authentication/social/additional-claims#add-and-update-user-claims.
        //
        // Alternatively, if flowing the claims from the "external cookie" to the "application cookie" is preferred,
        // the default ExternalLogin.cshtml page provided by Identity can be scaffolded to replace the call to
        // SignInManager.ExternalLoginSignInAsync() by a manual sign-in operation that will preserve the claims.
        // For scenarios where scaffolding the ExternalLogin.cshtml page is not convenient, a custom SignInManager
        // with an overridden SignInOrTwoFactorAsync() method can also be used to tweak the default Identity logic.
        //
        // For more information, see https://haacked.com/archive/2019/07/16/external-claims/ and
        // https://stackoverflow.com/questions/42660568/asp-net-core-identity-extract-and-save-external-login-tokens-and-add-claims-to-l/42670559#42670559.
        var result = (await context.AuthenticateAsync(IdentityConstants.ExternalScheme));
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

        var user = await userManager.GetUserAsync(principal);

        var name = principal.FindFirst(ClaimTypes.Name)!.Value;
      
        var email = principal.FindFirst(ClaimTypes.Email)!.Value;
        var identifier = principal.FindFirst(ClaimTypes.NameIdentifier)!.Value;
        var role = principal.FindFirst(ClaimTypes.Role)!.Value;

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
        identity.AddClaim(new Claim(Claims.Role, role).SetDestinations(Destinations.AccessToken));

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

