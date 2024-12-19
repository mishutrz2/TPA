using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Serilog;
using TPA.Domain.Models;
using TPA.Domain.Services;
using TPA.Domain.Services.Interfaces;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Azure.Identity;
using Azure.Security.KeyVault.Keys.Cryptography;
using Azure.Security.KeyVault.Keys;
using System.Security.Cryptography;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddScoped<IListsService, ListsService>();

builder.Services.AddControllers().AddNewtonsoftJson();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Load configuration
var config = builder.Configuration;

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString),
    ServiceLifetime.Transient);

/*// Azure Key Vault setup
var keyVaultUrl = config["AzureKeyVault:VaultUrl"];
var rsaKeyName = config["AzureKeyVault:KeyName"];

// Configure Azure Key Vault client
var keyClient = new KeyClient(new Uri(keyVaultUrl!), new DefaultAzureCredential());
var rsaKey = keyClient.GetKey(rsaKeyName).Value;

// Cryptography client for signing tokens
var cryptoClient = new CryptographyClient(new Uri($"{keyVaultUrl}/keys/{rsaKeyName}"), new DefaultAzureCredential());
builder.Services.AddSingleton(cryptoClient);*/

// RSA with key from file
var localRsaKey = RSA.Create();
string xmlKey = File.ReadAllText(config["JwtSettings:PrivateKeyPath"]!);
localRsaKey.FromXmlString(xmlKey);

// Create TokenValidationParameters
var tokenValidationParameters = new TokenValidationParameters
{
    ValidateIssuerSigningKey = true,

    // HMAC Symmetric
    // IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["JwtSettings:Secret"]!)), // Use a strong key

    /*// RSA Asymmetric - Azure Key Vault
    IssuerSigningKey = new RsaSecurityKey(rsaKey.Key.ToRSA(true)), // 'true' means we want the private key*/

    IssuerSigningKey = new RsaSecurityKey(localRsaKey),

    ValidateIssuer = true,
    ValidIssuer = config["JwtSettings:Issuer"],

    ValidateAudience = true,
    ValidAudience = config["JwtSettings:Audience"],

    ValidateLifetime = true,
    ClockSkew = TimeSpan.Zero,
};

builder.Services.AddSingleton(tokenValidationParameters);

// Use AddIdentity to include both user and role management
builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
    options.SignIn.RequireConfirmedAccount = false)
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// JWT authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
    {
        options.SaveToken = true;
        options.RequireHttpsMetadata = false;
        options.TokenValidationParameters = tokenValidationParameters;
    });

builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

builder.Services.AddAuthorization();

// for Serilog logging
builder.Host.UseSerilog((context, configuration) => configuration.ReadFrom.Configuration(context.Configuration));

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseCors();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.UseSerilogRequestLogging();

app.Run();
