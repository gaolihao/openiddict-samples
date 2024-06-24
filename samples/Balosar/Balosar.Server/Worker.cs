using System;
using System.Threading;
using System.Threading.Tasks;
using Balosar.Server.Data;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Balosar.Server;

public class Worker : IHostedService
{
    private readonly IServiceProvider _serviceProvider;

    public Worker(IServiceProvider serviceProvider)
        => _serviceProvider = serviceProvider;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        // Create a new application registration matching the values configured in Mimban.Client.
        // Note: in a real world application, this step should be part of a setup script.
        await using (var scope = _serviceProvider.CreateAsyncScope())
        {
            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            await context.Database.EnsureCreatedAsync();

            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            if (await manager.FindByClientIdAsync("console_app") == null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ApplicationType = ApplicationTypes.Native,
                    ClientId = "console_app",
                    ClientType = ClientTypes.Public,
                    RedirectUris =
            {
                new Uri("http://localhost/")
            },
                    Permissions =
            {
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.AuthorizationCode,
                Permissions.ResponseTypes.Code,
            }
                });
            }
        }

        // await using var scope = _serviceProvider.CreateAsyncScope();

        /*
        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        await context.Database.EnsureCreatedAsync();

        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        if (await manager.FindByClientIdAsync("console_app") is null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "console_app",
                ConsentType = ConsentTypes.Explicit,
                DisplayName = "Blazor client application",
                ClientType = ClientTypes.Public,
                RedirectUris =
                {
                    new Uri("http://localhost/")
                },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Logout,
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles
                },
                Requirements =
                {
                    Requirements.Features.ProofKeyForCodeExchange
                }
            });
            
        }
        */

    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
