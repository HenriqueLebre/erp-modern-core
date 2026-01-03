using Auth.Application;
using Auth.Domain.Entities;
using Auth.Domain.Interfaces;
using Auth.Infrastructure;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.OpenApi.Models;
using Microsoft.Extensions.Options;
using SharedKernel.Application.Options;
using AspNetCoreRateLimit;

var builder = WebApplication.CreateBuilder(args);

// Load JWT configuration from environment variables (secure)
var jwtKey = Environment.GetEnvironmentVariable("JWT_SECRET_KEY") 
    ?? builder.Configuration["Jwt:Key"];

if (string.IsNullOrEmpty(jwtKey) || jwtKey.Length < 32)
{
    throw new InvalidOperationException(
        "JWT Secret Key must be set via JWT_SECRET_KEY environment variable and be at least 32 characters long. " +
        "Generate one using: openssl rand -base64 64");
}

// Override configuration with environment variable
builder.Configuration["Jwt:Key"] = jwtKey;

// Load connection string from environment variable
var connectionString = Environment.GetEnvironmentVariable("AUTH_DB_CONNECTION_STRING")
    ?? Environment.GetEnvironmentVariable("AUTH_DB_CONNECTION_STRING_DEV")
    ?? builder.Configuration.GetConnectionString("AuthDb");

if (string.IsNullOrEmpty(connectionString))
{
    throw new InvalidOperationException(
        "Database connection string must be set via AUTH_DB_CONNECTION_STRING environment variable.");
}

builder.Configuration["ConnectionStrings:AuthDb"] = connectionString;

// Configurar opções de JWT
builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection("Jwt"));

// Rate limiting configuration
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
            Limit = 20 // 20 login attempts per minute per IP (demo mode)
        },
        new RateLimitRule
        {
            Endpoint = "*",
            Period = "1m",
            Limit = 30 // 30 requests per minute for all other endpoints
        }
    };
});
builder.Services.AddSingleton<IIpPolicyStore, MemoryCacheIpPolicyStore>();
builder.Services.AddSingleton<IRateLimitCounterStore, MemoryCacheRateLimitCounterStore>();
builder.Services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();
builder.Services.AddSingleton<IProcessingStrategy, AsyncKeyLockProcessingStrategy>();

// Add services to the container.
builder.Services.AddControllers();

// Health checks (SQLite for demo)
builder.Services.AddHealthChecks();

// Infra + Application do m�dulo Auth
builder.Services.AddAuthInfrastructure(builder.Configuration); 
builder.Services.AddAuthApplication();

// Swagger (para testar mais f�cil)
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Auth API", Version = "v1" });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Enter: Bearer {your JWT token}"
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

var app = builder.Build();

// Configurar Security Headers
app.Use(async (context, next) =>
{
    // Prevenir clickjacking
    context.Response.Headers.Add("X-Frame-Options", "DENY");
    
    // Prevenir MIME type sniffing
    context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
    
    // Proteção XSS (navegadores modernos)
    context.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
    
    // Content Security Policy
    context.Response.Headers.Add("Content-Security-Policy", 
        "default-src 'self'; frame-ancestors 'none'; form-action 'self'");
    
    // Referrer Policy
    context.Response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin");
    
    // Permissions Policy
    context.Response.Headers.Add("Permissions-Policy", 
        "geolocation=(), microphone=(), camera=()");
    
    // HSTS (HTTP Strict Transport Security) - apenas em produção
    if (!app.Environment.IsDevelopment())
    {
        context.Response.Headers.Add("Strict-Transport-Security", 
            "max-age=31536000; includeSubDomains; preload");
    }
    
    // Remover headers que revelam informação do servidor
    context.Response.Headers.Remove("Server");
    context.Response.Headers.Remove("X-Powered-By");
    
    await next();
});

// SEED: criar usu�rio admin/admin em mem�ria
using (var scope = app.Services.CreateScope())
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
    }
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

//app.UseHttpsRedirection();

// Rate limiting middleware (must be before authentication)
app.UseIpRateLimiting();

// Health checks endpoints
app.MapHealthChecks("/health");
app.MapHealthChecks("/health/ready", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
{
    Predicate = check => check.Tags.Contains("ready")
});
app.MapHealthChecks("/health/live", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
{
    Predicate = _ => false // Only basic liveness check
});

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();