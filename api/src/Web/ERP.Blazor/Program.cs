using ERP.Blazor.Components;
using ERP.Blazor.Services;
using Microsoft.AspNetCore.Components.Authorization;
using DotNetEnv;

var envPath = Path.Combine(Directory.GetCurrentDirectory(), "..", "..", "..", "..", "..", ".env");
if (File.Exists(envPath))
{
    Env.Load(envPath);
    Console.WriteLine("✅ [Blazor] Arquivo .env carregado com sucesso!");
}
else
{
    Console.WriteLine($"⚠️  [Blazor] Arquivo .env não encontrado em: {envPath}");
}

var builder = WebApplication.CreateBuilder(args);

builder.Configuration.AddEnvironmentVariables();

var authApiUrl = Environment.GetEnvironmentVariable("AuthAPI__BaseUrl") 
    ?? "http://localhost:5281";

Console.WriteLine($"✅ [Blazor] Auth API URL configurada: {authApiUrl}");

builder.Services.AddHttpClient("AuthAPI", client =>
{
    client.BaseAddress = new Uri(authApiUrl);
    client.Timeout = TimeSpan.FromSeconds(30);
});

builder.Services.AddScoped(sp =>
{
    var httpClientFactory = sp.GetRequiredService<IHttpClientFactory>();
    return httpClientFactory.CreateClient("AuthAPI");
});

builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<AuthenticationStateProvider, CustomAuthStateProvider>();
builder.Services.AddAuthorizationCore();
builder.Services.AddCascadingAuthenticationState();

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/error", createScopeForErrors: true);
    app.UseHsts();
}

if (!app.Environment.IsDevelopment())
{
    app.UseHttpsRedirection();
}

app.UseStaticFiles();
app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

Console.WriteLine("🚀 [Blazor] Frontend iniciado com sucesso!");
Console.WriteLine($"   Auth API: {authApiUrl}");
Console.WriteLine($"   Blazor UI: http://localhost:7143");

app.Run();