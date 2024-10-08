using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using TimeOffManager.Core.DTO;
using TimeOffManager.Core.Services;
using TimeOffManager.Core.Services.Interfaces;
using TimeOffManager.DataAccess.Context;
using TimeOffManager.DataAccess.Extensions;
using TimeOffManager.DataAccess.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddCors(options =>
{
    options.AddPolicy("AuthPolicy",
            policy =>
            {
                policy.WithOrigins("http://localhost:5173");
                policy.AllowAnyMethod();
                policy.AllowAnyHeader();
                policy.AllowCredentials();
            });
});

builder.Services.AddScoped<ICompanyService, CompanyService>();
builder.Services.AddScoped<IAccountService, AccountService>();
builder.Services.AddScoped<ITimeOffService, TimeOffService>();
builder.Services.AddScoped<ITeamService, TeamService>();
builder.Services.AddScoped<IEmailService, EmailService>();

builder.Services.AddIdentity<User, CustomRole>(o =>
{
    o.Lockout.AllowedForNewUsers = false;
})
.AddRoles<CustomRole>()
    .AddRoleManager<RoleManager<CustomRole>>()
.AddEntityFrameworkStores<DataContext>()
.AddTokenProvider<DataProtectorTokenProvider<User>>(TokenOptions.DefaultProvider);


var connectionStrings = builder.Configuration.GetSection("ConnectionStrings").GetChildren().AsEnumerable();
var dbConnection = connectionStrings.FirstOrDefault(x => x.Key == "TimeOffManagerConnection");
builder.Services.AddDbContext<DataContext>(options =>
{
    options.UseSqlServer(dbConnection.Value).LogTo(Console.WriteLine, LogLevel.Information);
    options.EnableDetailedErrors();
    options.EnableSensitiveDataLogging();
}, optionsLifetime: ServiceLifetime.Scoped, contextLifetime: ServiceLifetime.Scoped);

var jwtOptions = builder.Configuration.GetSection("JwtSettings");
var key = jwtOptions["Key"];
var refresh = jwtOptions["RefreshKey"];
var signinKey = Convert.FromBase64String(key);
var refreshKey = Convert.FromBase64String(refresh);
var accessKey = new SymmetricSecurityKey(signinKey);
var refreshSymmetric = new SymmetricSecurityKey(refreshKey);
builder.Services.Configure<JwtOptions>(options =>
{
    int.TryParse(jwtOptions["AccessExpire"], out var accessExpireDays);
    if (accessExpireDays > 0)
    {
        options.AccessValidFor = TimeSpan.FromSeconds(30);
    }
    options.Issuer = jwtOptions["Issuer"];
    options.Audience = jwtOptions["Audience"];
    options.AccessSecret = signinKey;
    options.RefreshSecret = refreshKey;
    options.AccessSigningCredentials = new SigningCredentials(accessKey, SecurityAlgorithms.HmacSha256);
    options.RefreshCredentials = new SigningCredentials(refreshSymmetric, SecurityAlgorithms.HmacSha256);
});

builder.Services.AddAuthentication(op =>
{
    op.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    op.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    op.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(x =>
{
    x.ClaimsIssuer = jwtOptions["Issuer"];
    x.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidIssuer = jwtOptions["Issuer"],
        ValidAudience = jwtOptions["Audience"],
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = accessKey,
        RequireExpirationTime = true,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero
    };
});
builder.Services.AddAuthorization();

builder.Services.AddDefaultDbRoles();
builder.Services.AddHttpContextAccessor();

var app = builder.Build();

app.UseCors("AuthPolicy");

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapControllers();

app.UseAuthentication();
app.UseAuthorization();

app.Run();
