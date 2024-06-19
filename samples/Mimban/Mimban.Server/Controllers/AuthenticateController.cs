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
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore;

namespace Mimban.Server.Controllers;

[ApiController]
//[Route("[controller]")]
[Route("callback/login/microsoft")]
public class AuthenticateController(ILogger<AuthorizeController> logger) : ControllerBase
{

    private readonly ILogger<AuthorizeController> logger = logger;

    [HttpGet, HttpPost]
    public async Task<IResult> Get()
    {

        var context = HttpContext;
        var result = await context.AuthenticateAsync(Providers.Microsoft);

        var identity = new ClaimsIdentity(
            authenticationType: "ExternalLogin",
            nameType: ClaimTypes.Name,
        roleType: ClaimTypes.Role);

        var n = result.Principal!.FindFirst("Name")!.Value;
        var e = result.Principal!.GetClaim(ClaimTypes.Email) ?? "";
        //var e1 = result.Principal!.GetClaim(ClaimTypes.Expiration) ?? "";
        //var e2 = result.Principal!.GetClaim(ClaimTypes.UserData) ?? "";
        //var e3 = result.Principal!.GetClaim(ClaimTypes.AuthenticationMethod) ?? "";
        //var e4 = result.Principal!.GetClaim(ClaimTypes.Authentication) ?? "";
        //var e5 = result.Principal!.GetClaim(ClaimTypes.DateOfBirth) ?? "";
        var e6 = result.Principal!.GetClaim(ClaimTypes.NameIdentifier) ?? "";
        //var e1 = result.Principal!.GetClaim(ClaimTypes.Country);
        //var e2 = result.Principal!.GetClaim(ClaimTypes.CookiePath);
        //var e3 = result.Principal!.GetClaim(ClaimTypes.Sid);
        identity.AddClaim(new Claim(ClaimTypes.Name, n));
        identity.AddClaim(new Claim(ClaimTypes.Email, e));
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, e6));

        var properties = new AuthenticationProperties
        {
            RedirectUri = result.Properties!.RedirectUri
        };

        // For scenarios where the default sign-in handler configured in the ASP.NET Core
        // authentication options shouldn't be used, a specific scheme can be specified here.
        return Results.SignIn(new ClaimsPrincipal(identity), properties);
    }
}
