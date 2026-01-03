using Auth.Application;
using Auth.Domain.Entities;
using Auth.Domain.Interfaces;
using Auth.Infrastructure;
using AspNetCoreRateLimit;
using DotNetEnv;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using SharedKernel.Application.Options;
using System.Text;

// ============================================
// CARREGAR VARIÁVEIS DE AMBIENTE
// ============================================
var envPath = Path.Combine(Directory.GetCurrentDirectory(), "..", "..", "..", "..", "..", ".env");
if (File.Exists(envPath))
{
    Env.Load(envPath);
    Console.WriteLine("✅ Arquivo .env carregado com sucesso!");
}
else
{
    Console.WriteLine($"⚠️  Arquivo .env não encontrado em: {envPath}");
}

var builder = WebApplication.CreateBuilder(args);

// Adicionar variáveis de ambiente à configuração
builder.Configuration.AddEnvironmentVariables();

// ============================================
// VALIDAR JWT KEY
// ============================================
var jwtKey = Environment.GetEnvironmentVariable("Jwt__Key")
    ?? throw new InvalidOperationException(
        "❌ JWT Key não configurada! Configure Jwt__Key no arquivo .env\n" +
        "Gere uma chave forte usando PowerShell:\n" +
        "-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 40 | % {[char]$_})");

if (jwtKey.Length < 32)
    throw new InvalidOperationException("❌ JWT Key deve ter no mínimo 32 caracteres!");

Console.WriteLine($"✅ JWT Key configurada ({jwtKey.Length} caracteres)");

// Atualizar configuração com valor do ambiente
builder.Configuration["Jwt:Key"] = jwtKey;
builder.Configuration["Jwt:Issuer"] = Environment.GetEnvironmentVariable("Jwt__Issuer") ?? "AuthAPI";
builder.Configuration["Jwt:Audience"] = Environment.GetEnvironmentVariable("Jwt__Audience") ?? "ERPModern";

// ============================================
// CONNECTION STRING
// ============================================
var connectionString = Environment.GetEnvironmentVariable("ConnectionStrings__DefaultConnection")
    ?? throw new InvalidOperationException(
        "❌ Connection String não configurada! Configure ConnectionStrings__DefaultConnection no arquivo .env");

Console.WriteLine($"🔍 DEBUG Connection String: {connectionString}");
Console.WriteLine("✅ Connection String configurada");

// Atualizar configuração
builder.Configuration["ConnectionStrings:DefaultConnection"] = connectionString;

// Configurar opções de JWT
builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection("Jwt"));

// ============================================
// RATE LIMITING
// ============================================
builder.Services.AddMemoryCache();
builder.Services.Configure<IpRateLimitOptions>(options =>
{
    options.EnableEndpointRateLimiting = true;
    options.StackBlockedRequests = false;
    options.HttpStatusCode = 429;
    options.RealIpHeader = "X-Real-IP";
    options.GeneralRules = new List<RateLimitRule>
    {
        new RateLimitRule
        {
            Endpoint = "POST:/auth/login",
            Period = "1m",
            Limit = 20
        },
        new RateLimitRule
        {
            Endpoint = "*",
            Period = "1m",
            Limit = 30
        }
    };
});
builder.Services.AddSingleton<IIpPolicyStore, MemoryCacheIpPolicyStore>();
builder.Services.AddSingleton<IRateLimitCounterStore, MemoryCacheRateLimitCounterStore>();
builder.Services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();
builder.Services.AddSingleton<IProcessingStrategy, AsyncKeyLockProcessingStrategy>();

builder.Services.AddControllers();
builder.Services.AddHealthChecks();

builder.Services.AddAuthInfrastructure(builder.Configuration);
builder.Services.AddAuthApplication();

// ============================================
// CORS
// ============================================
var allowedOrigins = Environment.GetEnvironmentVariable("CORS__AllowedOrigins")?.Split(',')
    ?? new[] { "http://localhost:7143", "http://localhost:5000" };

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowBlazor", policy =>
    {
        policy.WithOrigins(allowedOrigins)
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials();
    });
});

Console.WriteLine($"✅ CORS configurado para: {string.Join(", ", allowedOrigins)}");

// ============================================
// SWAGGER
// ============================================
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "ERP Modern - Auth API",
        Version = "v1",
        Description = "API de autenticação com JWT para modernização de ERP legado"
    });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Entre com: Bearer {seu token JWT}"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

// ============================================
// AUTH
// ============================================
var jwtOptions = builder.Configuration.GetSection("Jwt").Get<JwtOptions>()
    ?? throw new InvalidOperationException("Jwt options are not configured.");

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtOptions.Issuer,
            ValidAudience = jwtOptions.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.Key)),
            ClockSkew = TimeSpan.FromSeconds(30)
        };
    });

builder.Services.AddAuthorization();

// ============================================
// BUILD APP
// ============================================
var app = builder.Build();

// ============================================
// SECURITY HEADERS (CSP relaxado para Swagger em Development)
// ============================================
app.Use(async (context, next) =>
{
    var path = context.Request.Path.Value ?? "";
    var isSwagger = path.StartsWith("/swagger", StringComparison.OrdinalIgnoreCase);

    // Prevenir clickjacking
    context.Response.Headers.Append("X-Frame-Options", "DENY");

    // Prevenir MIME type sniffing
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");

    // Proteção XSS (navegadores modernos)
    context.Response.Headers.Append("X-XSS-Protection", "1; mode=block");

    // Referrer Policy
    context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");

    // Permissions Policy
    context.Response.Headers.Append("Permissions-Policy", "geolocation=(), microphone=(), camera=()");

    // Content Security Policy (NÃO aplicar no Swagger em Development, para não dar tela branca)
    if (!(app.Environment.IsDevelopment() && isSwagger))
    {
        context.Response.Headers.Append(
            "Content-Security-Policy",
            "default-src 'self'; frame-ancestors 'none'; form-action 'self'"
        );
    }

    // HSTS (somente em produção)
    if (!app.Environment.IsDevelopment())
    {
        context.Response.Headers.Append(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains; preload"
        );
    }

    // Remover headers que revelam informação do servidor
    context.Response.Headers.Remove("Server");
    context.Response.Headers.Remove("X-Powered-By");

    await next();
});

// ============================================
// SEED USUÁRIO ADMIN
// ============================================
using (var scope = app.Services.CreateScope())
{
    try
    {
        var userRepo = scope.ServiceProvider.GetRequiredService<IUserRepository>();
        var passwordHasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();

        var existing = await userRepo.GetByUsernameAsync("admin");
        if (existing is null)
        {
            var user = new User(
                username: "admin",
                passwordHash: passwordHasher.HashPassword("admin"),
                email: "admin@local",
                role: "Admin"
            );

            await userRepo.AddAsync(user);
            Console.WriteLine("✅ Usuário admin criado (username: admin, password: admin)");
        }
        else
        {
            Console.WriteLine("ℹ️  Usuário admin já existe");
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"⚠️  Erro ao criar usuário admin: {ex.Message}");
        Console.WriteLine("   Database pode não estar acessível ainda.");
    }
}

// ============================================
// CONFIGURE HTTP PIPELINE
// ============================================
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Auth API v1");
        c.RoutePrefix = "swagger";
    });
}

// CORS - deve vir antes de Authentication
app.UseCors("AllowBlazor");

// Rate limiting - deve vir antes de Authentication
app.UseIpRateLimiting();

// Health checks endpoints
app.MapHealthChecks("/health");
app.MapHealthChecks("/health/ready", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
{
    Predicate = check => check.Tags.Contains("ready")
});
app.MapHealthChecks("/health/live", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
{
    Predicate = _ => false
});

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

Console.WriteLine("🚀 Auth API iniciada com sucesso!");
Console.WriteLine("   Swagger UI: http://localhost:5281/swagger");
Console.WriteLine("   Health Check: http://localhost:5281/health");

app.Run();