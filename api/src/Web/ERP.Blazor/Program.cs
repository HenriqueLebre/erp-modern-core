using ERP.Blazor.Components;
using ERP.Blazor.Services;
using Microsoft.AspNetCore.Components.Authorization;

var builder = WebApplication.CreateBuilder(args);

// Configurar HttpClient para a Auth API
builder.Services.AddHttpClient("AuthAPI", client =>
{
    var authApiUrl = builder.Configuration["Services:AuthAPI:Url"] ?? "http://localhost:5281";
    client.BaseAddress = new Uri(authApiUrl);
    client.Timeout = TimeSpan.FromSeconds(30);
});

// Serviços de autenticação
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<AuthenticationStateProvider, CustomAuthStateProvider>();
builder.Services.AddAuthorizationCore();

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();

app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
