﻿using CommunityToolkit.Mvvm.Input;
using PropertyChanged;
using System.ComponentModel;
using System.Net.Http;
using System.Runtime.CompilerServices;
using static System.Runtime.InteropServices.JavaScript.JSType;
using System.Security.Claims;
using System.Windows;
using OpenIddict.Client;
using System.Net.Http.Headers;

namespace MyTestingGround;


[AddINotifyPropertyChangedInterface]
public partial class MainViewModel : IMainViewModel
{
    //Client client;
    public OpenIddictClientService Service { get; }
    public MainViewModel(OpenIddictClientService service)
    {
        //var httpClient = new HttpClient();
        //client = new MyNamespace.Client("http://localhost:5232/", httpClient);
        Service = service;
    }
    public int MyProperty { get; set; } = 1;

    [RelayCommand]
    private void Increment() => ++MyProperty;


    /*
    public string s { get; set; } = "";

    [RelayCommand]
    private async Task ExtractAsync()
    {

        var results = await client.TodoAllAsync();
        s = string.Join("\n", results.Select(todo => todo.Name));
    }
    

    [RelayCommand]
    private async Task GetUsernameAsync()
    {
        var results = await client.UsernameAsync();
        username = results.Value;
    }


    [RelayCommand]
    private async Task AuthorizeAsync()
    {

        //var results = await client.LoginPOSTAsync(provider);
        //s = string.Join("\n", results.Select(todo => todo.Name));
    }

    */
    public string username { get; set; } = "";

    private async Task<string> GetResourceAsync(string token, CancellationToken cancellationToken = default)
    {

        using var client = new HttpClient();

        using var request = new HttpRequestMessage(HttpMethod.Get, "https://localhost:44383/username");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var response = await client.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadAsStringAsync(cancellationToken);


        /*
        using var client = new HttpClient();

        using var request = new HttpRequestMessage(HttpMethod.Get, "https://localhost:5232/username");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var response = await client.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadAsStringAsync(cancellationToken);
        */
    }

    [RelayCommand]
    private async Task LoginAsync()
    {
        // Disable the login button to prevent concurrent authentication operations.
        try
        {
            using var source = new CancellationTokenSource(delay: TimeSpan.FromSeconds(90));

            try
            {
                // Ask OpenIddict to initiate the authentication flow (typically, by starting the system browser).
                var result = await Service.ChallengeInteractivelyAsync(new()
                {
                    CancellationToken = source.Token
                });

                // Wait for the user to complete the authorization process.
                var response = (await Service.AuthenticateInteractivelyAsync(new()
                {
                    CancellationToken = source.Token,
                    Nonce = result.Nonce
                }));

                var responseToken = response.BackchannelAccessToken ?? response.FrontchannelAccessToken;
                if (responseToken != null)
                {
                    var token = await GetResourceAsync(responseToken, source.Token);
                    // var v = response.Principal.FindFirst(ClaimTypes.Name)!.Value;
                    username = ($"Your GitHub identifier is: {token}");

                }
            }

            catch (OperationCanceledException)
            {
                MessageBox.Show("The authentication process was aborted.",
                "Authentication timed out", MessageBoxButton.OK, MessageBoxImage.Warning);
            }

            catch
            {
                MessageBox.Show("An error occurred while trying to authenticate the user.",
                    "Authentication failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        finally
        {
            // Re-enable the login button to allow starting a new authentication operation.
            // LoginButton.IsEnabled = true;
        }
    }

}