﻿using Microsoft.Extensions.Hosting;
using System.IO;
using System.Windows;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Client;
using System.Reflection;

namespace MyTestingGround;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>

public partial class App : Application
{
    public event EventHandler? Loaded;

    public static IHost? AppHost { get; private set; }


    protected override async void OnStartup(StartupEventArgs e)
    {
        // base.OnStartup(e);



        AppHost = Host.CreateDefaultBuilder(e.Args)
            .ConfigureAppConfiguration((context, builder) =>
            {
                builder.AddJsonFile("app.settings.json", optional: true, reloadOnChange: true)
                        .AddEnvironmentVariables();
            })
            .ConfigureServices((context, services) =>
            {
                services.AddDbContext<DbContext>(options =>
                {
                    options.UseSqlite($"Filename={Path.Combine(Path.GetTempPath(), "openiddict-mimban5-client.sqlite3")}");
                    options.UseOpenIddict();
                });

                services.AddOpenIddict()

                    // Register the OpenIddict core components.
                    .AddCore(options =>
                    {
                        // Configure OpenIddict to use the Entity Framework Core stores and models.
                        // Note: call ReplaceDefaultEntities() to replace the default OpenIddict entities.
                        options.UseEntityFrameworkCore()
                                .UseDbContext<DbContext>();
                    })

                    // Register the OpenIddict client components.
                    .AddClient(options =>
                    {
                        // Note: this sample uses the authorization code flow,
                        // but you can enable the other flows if necessary.
                        options.AllowAuthorizationCodeFlow()
                                .AllowRefreshTokenFlow();

                        // Register the signing and encryption credentials used to protect
                        // sensitive data like the state tokens produced by OpenIddict.
                        options.AddDevelopmentEncryptionCertificate()
                                .AddDevelopmentSigningCertificate();

                        // Add the operating system integration.
                        options.UseSystemIntegration();

                        // Register the System.Net.Http integration and use the identity of the current
                        // assembly as a more specific user agent, which can be useful when dealing with
                        // providers that use the user agent as a way to throttle requests (e.g Reddit).
                        options.UseSystemNetHttp()
                                .SetProductInformation(typeof(App).Assembly);

                        // Add a client registration matching the client application definition in the server project.
                        options.AddRegistration(new OpenIddictClientRegistration
                        {
                            Issuer = new Uri("https://localhost:44310/", UriKind.Absolute),

                            ClientId = "console_app",
                            RedirectUri = new Uri("/", UriKind.Relative)
                        });
                    });

                // Register the worker responsible for creating the database used to store tokens
                // and adding the registry entries required to register the custom URI scheme.
                //
                // Note: in a real world application, this step should be part of a setup script.

                services.AddHostedService<Worker>();
                //services.AddSingleton((Application)this);
                //services.AddSingleton<MainWindow>();
                services.AddSingleton<IMainViewModel, MainViewModel>();

                // Register the background service responsible for handling the console interactions.
            })
            .Build();

        //PowerPointHelper.Initilize();

        await AppHost.StartAsync();

        this.Loaded?.Invoke(this, EventArgs.Empty);
        this.Loaded = null;

        await AppHost.WaitForShutdownAsync();
        this.Shutdown();
    }

    protected override async void OnExit(ExitEventArgs e)
    {
        base.OnExit(e);
        if (AppHost != null)
        {
            await AppHost.StopAsync();
            AppHost.Dispose();
        }
    }

    public static T GetViewModelInstance<T>()
    {
        _ = AppHost ?? throw new InvalidOperationException("Host not initialized");
        var res = AppHost.Services.GetService<T>();
        if (res == null)
        {
            string error = $"DI: Error occurred loading {typeof(T).Name} in Noviview version: {Assembly.GetEntryAssembly()!.GetName().Version}";
            MessageBox.Show(error, "Error");
            throw new InvalidOperationException(error);
        }
        return res;
    }
}
/*
protected override void OnStartup(StartupEventArgs e)
{

    base.OnStartup(e);

    var mainWindowViewModel = new MainViewModel();
    var mainWindow = new MainWindow
    {
        DataContext = mainWindowViewModel
    };

    MainWindow = mainWindow;
    MainWindow.Show();


}
*/



public class Worker : IHostedService
{
    private readonly IServiceProvider _provider;

    public Worker(IServiceProvider provider)
        => _provider = provider;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using var scope = _provider.CreateScope();

        var context = scope.ServiceProvider.GetRequiredService<DbContext>();
        await context.Database.EnsureCreatedAsync();
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

