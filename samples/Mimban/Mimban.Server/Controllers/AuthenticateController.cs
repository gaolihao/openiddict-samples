using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;
using static OpenIddict.Abstractions.OpenIddictConstants;
using OpenIddict.Server.AspNetCore;
using Microsoft.AspNetCore.Http.Extensions;
using OpenIddict.Abstractions;
using Polly;

namespace Mimban.Server.Controllers;

[ApiController]
//[Route("[controller]")]
[Route("callback/login/github")]
public class AuthenticateController(ILogger<AuthorizeController> logger) : ControllerBase
{

    private readonly ILogger<AuthorizeController> logger = logger;

    [HttpGet, HttpPost]
    public async Task<IResult> Get()
    {
        var context = HttpContext;
        var result = await context.AuthenticateAsync(Providers.GitHub);

        var identity = new ClaimsIdentity(
            authenticationType: "ExternalLogin",
            nameType: ClaimTypes.Name,
            roleType: ClaimTypes.Role);

        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, result.Principal!.FindFirst("id")!.Value));

        var properties = new AuthenticationProperties
        {
            RedirectUri = result.Properties!.RedirectUri
        };

        // For scenarios where the default sign-in handler configured in the ASP.NET Core
        // authentication options shouldn't be used, a specific scheme can be specified here.
        return Results.SignIn(new ClaimsPrincipal(identity), properties);
    }
}
