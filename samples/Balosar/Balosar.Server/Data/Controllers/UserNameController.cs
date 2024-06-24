﻿using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;
using System.Reflection.Metadata;
using System.Security.Claims;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;
using static OpenIddict.Abstractions.OpenIddictConstants;
namespace Mimban.Server;


public record Username(string value);

[ApiController]
//[Route("[controller]")]
[Authorize(Roles = "Signin")]
[Route("userinfo")]
public class UserNameController : Controller
{
    [HttpGet("usernameid")]
    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    public Task<ActionResult<string>> GetUserName()
    {
        var identity = (ClaimsIdentity)User.Identity!;
        //var userName = identity.Name;
        //var claims = identity.Claims;
        var userNameId = identity.FindFirst(Claims.PreferredUsername)!.Value;

        if (string.IsNullOrEmpty(userNameId))
        {
            return Task.FromResult<ActionResult<string>>(("User name not found."));
        }
        return Task.FromResult<ActionResult<string>>((userNameId ?? ""));

    }


    [HttpGet("username")]
    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    public Task<ActionResult<string>> GetUserNameId()
    {
        var identity = (ClaimsIdentity)User.Identity!;
        var userName = identity.FindFirst(Claims.Name)!.Value;

        if (string.IsNullOrEmpty(userName))
        {
            return Task.FromResult<ActionResult<string>>(("User name not found."));
        }
        return Task.FromResult<ActionResult<string>>((userName ?? ""));

    }

    [HttpGet("email")]
    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    public Task<ActionResult<string>> GetEmail()
    {
        var identity = (ClaimsIdentity)User.Identity!;
        var email = identity.FindFirst(Claims.Email)!.Value;

        if (string.IsNullOrEmpty(email))
        {
            return Task.FromResult<ActionResult<string>>(("User name not found."));
        }
        return Task.FromResult<ActionResult<string>>((email ?? ""));

    }
}