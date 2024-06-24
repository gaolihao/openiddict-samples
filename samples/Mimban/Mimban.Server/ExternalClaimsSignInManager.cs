// Some of this code is copied and modified from
// https://github.com/aspnet/AspNetCore/blob/master/src/Identity/Core/src/SignInManager.cs
// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See the license for that code at
// https://github.com/aspnet/AspNetCore/blob/master/LICENSE.txt
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Mimban.Server;

public class ExternalClaimsSignInManager<TUser>
    : SignInManager<TUser> where TUser : class
{
    public ExternalClaimsSignInManager(
        UserManager<TUser> userManager,
        IHttpContextAccessor contextAccessor,
        IUserClaimsPrincipalFactory<TUser> claimsFactory,
        IOptions<IdentityOptions> optionsAccessor,
        ILogger<SignInManager<TUser>> logger,
        IAuthenticationSchemeProvider schemes,
        IUserConfirmation<TUser> confirmation)
        : base(
            userManager,
            contextAccessor,
            claimsFactory,
            optionsAccessor,
            logger,
            schemes,
            confirmation)
    {
    }

    protected override async Task<SignInResult> SignInOrTwoFactorAsync(
        TUser user,
        bool isPersistent,
        string? loginProvider = null,
        bool bypassTwoFactor = false)
    {
        if (!bypassTwoFactor && await IsTfaEnabled(user))
        {
            if (!await IsTwoFactorClientRememberedAsync(user))
            {
                // Store the userId for use after two factor check
                var userId = await UserManager.GetUserIdAsync(user);
                await Context.SignInAsync(IdentityConstants.TwoFactorUserIdScheme, StoreTwoFactorInfo(userId, loginProvider!));
                return SignInResult.TwoFactorRequired;
            }
        }

        // Grab external login info before we clean up the external cookie.
        // This contains the external tokens and claims.
        var externalLoginInfo = await GetExternalLoginInfoAsync();

        // Cleanup external cookie
        if (loginProvider != null)
        {
            await Context.SignOutAsync(IdentityConstants.ExternalScheme);
        }
        await SignInAsyncWithExternalClaims(
            user,
            isPersistent,
            loginProvider!,
            externalLoginInfo!);
        return SignInResult.Success;
    }

    async Task SignInAsyncWithExternalClaims(
        TUser user,
        bool isPersistent,
        string loginProvider,
        ExternalLoginInfo externalLoginInfo)
    {
        var authenticationProperties = new AuthenticationProperties
        {
            IsPersistent = isPersistent
        };
        var userPrincipal = await CreateUserPrincipalAsync(user);
        if (loginProvider != null)
        {
            userPrincipal
                .Identities
                .First()
                .AddClaim(new Claim(ClaimTypes.AuthenticationMethod, loginProvider));

            // Add External Claimns that start with "urn:"
            var claims = externalLoginInfo
                .Principal
                .Claims
                .Where(c => c.Type.StartsWith("urn:"));
            userPrincipal.Identities.First().AddClaims(claims);
        }
        await Context.SignInAsync(IdentityConstants.ApplicationScheme,
            userPrincipal,
            authenticationProperties);
    }

    private async Task<bool> IsTfaEnabled(TUser user)
        => UserManager.SupportsUserTwoFactor &&
        await UserManager.GetTwoFactorEnabledAsync(user) &&
        (await UserManager.GetValidTwoFactorProvidersAsync(user)).Count > 0;


    /// <summary>
    /// Creates a claims principal for the specified 2fa information.
    /// </summary>
    /// <param name="userId">The user whose is logging in via 2fa.</param>
    /// <param name="loginProvider">The 2fa provider.</param>
    /// <returns>A <see cref="ClaimsPrincipal"/> containing the user 2fa information.</returns>
    internal ClaimsPrincipal StoreTwoFactorInfo(string userId, string loginProvider)
    {
        var identity = new ClaimsIdentity(IdentityConstants.TwoFactorUserIdScheme);
        identity.AddClaim(new Claim(ClaimTypes.Name, userId));
        if (loginProvider != null)
        {
            identity.AddClaim(new Claim(ClaimTypes.AuthenticationMethod, loginProvider));
        }
        return new ClaimsPrincipal(identity);
    }
}