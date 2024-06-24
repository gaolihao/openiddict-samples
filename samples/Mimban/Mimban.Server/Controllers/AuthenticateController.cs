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
using OpenIddict.Client.AspNetCore;
using Mimban.Server.Models;
using Microsoft.AspNetCore.Authorization;

namespace Mimban.Server.Controllers;

[ApiController]
//[Route("[controller]")]
[Route("callback111/login/microsoft")]
public class AuthenticateController : ControllerBase
{
    private readonly UserManager<ApplicationUser> userManager;


    public AuthenticateController(
        UserManager<ApplicationUser> userManager)
    {
        this.userManager = userManager;
    }

    [HttpGet, HttpPost]
    public async Task<IResult> Get()
    {

        //var request = HttpContext.GetOpenIddictServerRequest();
        //var user = await userManager.FindByNameAsync(request!.Username!);

        var context = HttpContext;
        var result = await context.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
        //var result = await context.AuthenticateAsync(Providers.Microsoft);

        var identity = new ClaimsIdentity(Providers.Microsoft);
        /*
        var identity = new ClaimsIdentity(
            authenticationType: "ExternalLogin",
            nameType: ClaimTypes.Name,
        roleType: ClaimTypes.Role);
        */

        var n = result.Principal!.FindFirst("Name")!.Value;
        var e = result.Principal!.GetClaim(ClaimTypes.Email) ?? "";
        var role = result.Principal!.GetClaim("roles") ?? "";
        //var e1 = result.Principal!.GetClaim(ClaimTypes.Expiration) ?? "";
        //var e2 = result.Principal!.GetClaim(ClaimTypes.UserData) ?? "";
        //var e3 = result.Principal!.GetClaim(ClaimTypes.AuthenticationMethod) ?? "";
        //var e4 = result.Principal!.GetClaim(ClaimTypes.Authentication) ?? "";
        //var e5 = result.Principal!.GetClaim(ClaimTypes.DateOfBirth) ?? "";
        var e6 = result.Principal!.GetClaim(ClaimTypes.NameIdentifier) ?? "";
        //var e1 = result.Principal!.GetClaim(ClaimTypes.Country);
        //var e2 = result.Principal!.GetClaim(ClaimTypes.CookiePath);
        //var e3 = result.Principal!.GetClaim(ClaimTypes.Sid);

        // By default, OpenIddict will automatically try to map the email/name and name identifier claims from
        // their standard OpenID Connect or provider-specific equivalent, if available. If needed, additional
        // claims can be resolved from the external identity and copied to the final authentication cookie.
        identity.SetClaim(ClaimTypes.Email, result.Principal.GetClaim(ClaimTypes.Email))
                .SetClaim(ClaimTypes.Name, result.Principal.GetClaim(ClaimTypes.Name))
                .SetClaim(ClaimTypes.NameIdentifier, result.Principal.GetClaim(ClaimTypes.NameIdentifier));

        //identity.AddClaim(new Claim(ClaimTypes.Name, n));
        //identity.AddClaim(new Claim(ClaimTypes.Email, e));
        //identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, e6));
        identity.AddClaim(new Claim(ClaimTypes.Role, role));

        var properties = new AuthenticationProperties
        {
            RedirectUri = result.Properties!.RedirectUri
        };

        // If needed, the tokens returned by the authorization server can be stored in the authentication cookie.
        // To make cookies less heavy, tokens that are not used are filtered out before creating the cookie.
        properties.StoreTokens(result.Properties.GetTokens().Where(token => token.Name is
            // Preserve the access and refresh tokens returned in the token response, if available.
            OpenIddictClientAspNetCoreConstants.Tokens.BackchannelAccessToken or
            OpenIddictClientAspNetCoreConstants.Tokens.RefreshToken));



        // For scenarios where the default sign-in handler configured in the ASP.NET Core
        // authentication options shouldn't be used, a specific scheme can be specified here.
        return Results.SignIn(new ClaimsPrincipal(identity), properties);
    }
}
