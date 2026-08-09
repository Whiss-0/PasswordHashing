using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Text.Json;
using Api.Modules.AuthorizationModule;
using Api.Modules.RegisterModule;
using Api.Modules.LoginModule;
using Api.Modules.AccountModule;
using Api.Modules.UserModule;
using Api.Main;
using Api.DTOs;
using Api.Security;
using Api.HTTP;
using Api.Infrastrucures.Cookies;


try
{
    var builder = WebApplication.CreateBuilder(args);

    builder.Services.AddControllers();
    builder.Services.AddSwaggerGen();
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSignalR();

    builder.Services.AddSingleton<IJwtTokenService, JwtTokenService>();

    builder.Services.AddScoped<MyCon>();
    builder.Services.AddScoped<IUserRepository, UserRepository>();

    builder.Services.AddScoped<ISessionService, DatabaseSessionService>();

    builder.Services.AddScoped<ILoginAttemptService, DatabaseLoginAttemptService>();

    builder.Services.AddScoped<IOtpService, DatabaseOtpService>();

    builder.Services.AddScoped<SmtpOtpEmailSender>();

    if (builder.Environment.IsDevelopment())
        builder.Services.AddScoped<IOtpEmailSender, DevOtpEmailSender>();
    else
        builder.Services.AddScoped<IOtpEmailSender, SmtpOtpEmailSender>();

    builder.Services.AddSingleton<IPendingRegistrationStore, InMemoryPendingRegistrationStore>();
    builder.Services.AddSingleton<IPendingAdminRegStore,     InMemoryPendingAdminRegStore>();
    builder.Services.AddSingleton<IPendingUserOpStore,       InMemoryPendingUserOpStore>();

    builder.Services.AddScoped<IRefreshTokenStore, DatabaseRefreshTokenStore>();
    builder.Services.AddHostedService<SessionCleanupService>();

    // ── Google OAuth ───────────────────────────────────────────────────────────
    builder.Services.AddScoped<IGoogleAuthService, GoogleAuthService>();

    // ── Authorization (custom role handler) ────────────────────────────────────
    builder.Services.AddSingleton<IAuthorizationHandler, RoleRequirementHandler>();

    // ── Auth Services (Modules/) ───────────────────────────────────────────────────
    // Business logic lives here — AuthController only handles HTTP plumbing.
    builder.Services.AddScoped<IRegistrationService, RegistrationService>();
    builder.Services.AddScoped<ILoginService,        LoginService>();
    builder.Services.AddScoped<IAccountService,      AccountService>();

    // ── HTTP / Cookie infrastructure ───────────────────────────────────────────────
    // IHttpContextAccessor is required by both RequestsContext and AuthCookies.
    builder.Services.AddHttpContextAccessor();
    builder.Services.AddScoped<IRequestContext, RequestContext>();
    builder.Services.AddScoped<ICookies,         AuthCookies>();
    builder.Services.AddScoped<IHttpResponse,    HttpResponseHandler>();


    var jwtKey      = builder.Configuration["Jwt:Key"]      ?? "p7XJ9qA4tZf2LwR8mC0uVbN6yHkT3sPdQ5rE";
    var jwtIssuer   = builder.Configuration["Jwt:Issuer"]   ?? "ContactDB-API";
    var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "ContactDB-Client";

    builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer           = true,
                ValidateAudience         = true,
                ValidateLifetime         = true,         
                ValidateIssuerSigningKey = true,
                ValidIssuer              = jwtIssuer,
                ValidAudience            = jwtAudience,
                IssuerSigningKey         = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
                ClockSkew                = TimeSpan.FromSeconds(30)
            };

            options.Events = new JwtBearerEvents
            {
                OnMessageReceived = ctx =>
                {
                    var accessToken = ctx.Request.Query["access_token"];
                    var path = ctx.HttpContext.Request.Path;
                    if (!string.IsNullOrEmpty(accessToken) && path.StartsWithSegments("/dashboardHub"))
                    {
                        ctx.Token = accessToken;
                    }
                    else if (string.IsNullOrEmpty(ctx.Token))
                    {
                        ctx.Token = ctx.Request.Cookies["access_token"];
                    }
                    return Task.CompletedTask;
                },

                OnTokenValidated = async ctx =>
                {
                    var publicIdClaim = ctx.Principal?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
                    var roleIdClaim   = ctx.Principal?.FindFirst("user_role_id")?.Value;

                    if (!string.IsNullOrEmpty(publicIdClaim) && Guid.TryParse(publicIdClaim, out var publicId))
                    {
                        var userRepo   = ctx.HttpContext.RequestServices.GetRequiredService<IUserRepository>();
                        var sessionSvc = ctx.HttpContext.RequestServices.GetRequiredService<ISessionService>();

                        var dbUser = await userRepo.GetByIdAsync(publicId);
                        if (dbUser == null || dbUser.IsDeleted || dbUser.Status != "ACTIVE")
                        {
                            ctx.Fail("ACCOUNT_INVALIDATED");
                            return;
                        }

                        // Promoted or demoted role check
                        if (!string.IsNullOrEmpty(roleIdClaim) && int.TryParse(roleIdClaim, out var tokenRoleId))
                        {
                            if (dbUser.AccessId != tokenRoleId)
                            {
                                ctx.Fail("ROLE_CHANGED");
                                return;
                            }
                        }

                        // Force logout / session termination check
                        if (!sessionSvc.IsUserLoggedIn(dbUser.UserId))
                        {
                            ctx.Fail("SESSION_TERMINATED");
                            return;
                        }
                    }
                },

                OnChallenge = async ctx =>
                {
                    ctx.HandleResponse();

                    string code    = "UNAUTHORIZED";
                    string message = "Authentication is required.";

                    if (ctx.AuthenticateFailure is SecurityTokenExpiredException)
                    {
                        code    = "TOKEN_EXPIRED";
                        message = "Your session has expired. Please refresh your token or log in again.";
                        ctx.Response.StatusCode = 401;
                    }
                    else if (ctx.AuthenticateFailure != null)
                    {
                        code    = "INVALID_TOKEN";
                        message = "The provided token is invalid.";
                        ctx.Response.StatusCode = 401;
                    }
                    else
                    {
                        ctx.Response.StatusCode = 401;
                    }

                    ctx.Response.ContentType = "application/json";
                    var payload = JsonSerializer.Serialize(new { code, message });
                    await ctx.Response.WriteAsync(payload);
                },

                OnAuthenticationFailed = ctx =>
                {
                    if (ctx.Exception is SecurityTokenExpiredException)
                    {
                        ctx.Response.Headers["X-Token-Expired"] = "true";
                    }
                    return Task.CompletedTask;
                }
            };
        });

    // ── Authorization policies — all defined centrally in Authorization/AppPolicies.cs ──
    builder.Services.AddAuthorization(options => options.AddAppPolicies());


    var allowedOrigins = builder.Configuration
        .GetSection("AllowedOrigins")
        .Get<string[]>()
        ?? new[]
        {
            "http://localhost:3000",   
            "http://localhost:3001",
            "https://localhost:3000",
            "https://localhost:3001",
        };

    builder.Services.AddCors(options =>
    {
        options.AddPolicy("AllowAll", policy =>
        {
            policy.WithOrigins(allowedOrigins)
                  .AllowAnyMethod()
                  .AllowAnyHeader()
                  .AllowCredentials();
        });
    });


    var app = builder.Build();

    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI(c =>
        {
            c.SwaggerEndpoint("/swagger/v1/swagger.json", "Guns API V1");
            c.RoutePrefix = "swagger";
        });
    }

    app.UseCors("AllowAll");
    app.UseAuthentication();
    app.UseAuthorization();

    app.MapGet("/", () => Results.Redirect("/swagger"));
    app.MapGet("/index.html", () => Results.Redirect("/swagger"));
    app.MapControllers();
    app.MapHub<DashboardHub>("/dashboardHub");


    app.MapGet("/health", () =>
        Results.Ok(new { status = "healthy", timestamp = DateTime.UtcNow }));

    app.MapGet("/db-test", async (MyCon db) =>
    {
        try
        {
            var canConnect = await db.CanConnectAsync();
            return canConnect
                ? Results.Ok(new { status = "Database connection successful", timestamp = DateTime.UtcNow })
                : Results.Problem("Database connection failed");
        }
        catch (Exception ex)
        {
            return Results.Problem(detail: ex.Message, statusCode: 500, title: "Database connection error");
        }
    });

    Console.WriteLine("Starting Student Portal API...");
    app.Run();
}
catch (Exception ex)
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine("ERROR: Backend failed to start!");
    Console.WriteLine(ex.ToString());
    Console.ResetColor();
    Environment.Exit(1);
}