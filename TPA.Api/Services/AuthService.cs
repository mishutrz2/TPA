using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using TPA.Api.Services.Interfaces;
using TPA.Domain.Models;

namespace TPA.Api.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _config;

        public AuthService(UserManager<ApplicationUser> userManager, IConfiguration config)
        {
            _userManager = userManager;
            _config = config;
        }

        public async Task<bool> RegisterUser(RegisterModel user)
        {
            var identityUser = new ApplicationUser
            {
                UserName = user.Username,
                Email = user.Email
            };

            var result = await _userManager.CreateAsync(identityUser, user.Password);
            return result.Succeeded;
        }

        public async Task<AuthResultModel> Login(LoginModel user)
        {
            var response = new AuthResultModel();
            var identityUser = await _userManager.FindByNameAsync(user.Username);

            if (identityUser is null || (await _userManager.CheckPasswordAsync(identityUser, user.Password)) == false)
            {
                return response;
            }

            await GeneratetokensAndUpdatetSataBase(response, identityUser);

            return response;
        }

        public async Task<AuthResultModel> RefreshToken(TokenRequestModel model)
        {
            var principal = GetTokenPrincipal(model.JwtToken);

            var response = new AuthResultModel();
            if (principal?.Identity?.Name is null)
                return response;

            var identityUser = await _userManager.FindByNameAsync(principal.Identity.Name);

            if (identityUser is null || identityUser.RefreshToken != model.RefreshToken || identityUser.RefreshTokenExpiry < DateTime.Now)
                return response;

            await GeneratetokensAndUpdatetSataBase(response, identityUser);

            return response;
        }

        #region PRIVATE

        private async Task GeneratetokensAndUpdatetSataBase(AuthResultModel response, ApplicationUser? identityUser)
        {
            response.IsLogedIn = true;
            response.JwtToken = this.GenerateTokenString(identityUser!.UserName!);
            response.RefreshToken = this.GenerateRefreshTokenString();
            response.ExpiresAt = DateTime.Now.AddMinutes(10);

            identityUser.RefreshToken = response.RefreshToken;
            identityUser.RefreshTokenExpiry = DateTime.Now.AddHours(12);
            await _userManager.UpdateAsync(identityUser);
        }

        private string GenerateRefreshTokenString()
        {
            var randomNumber = new byte[64];

            using (var numberGenerator = RandomNumberGenerator.Create())
            {
                numberGenerator.GetBytes(randomNumber);
            }

            return Convert.ToBase64String(randomNumber);
        }

        private ClaimsPrincipal? GetTokenPrincipal(string token)
        {
            //var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetSection("Jwt:Key").Value));

            var securityKey = GetRsaKey();

            var validation = new TokenValidationParameters
            {
                IssuerSigningKey = securityKey,
                ValidateLifetime = false,
                ValidateActor = false,
                ValidateIssuer = false,
                ValidateAudience = false,
            };

            return new JwtSecurityTokenHandler().ValidateToken(token, validation, out _);
        }

        private string GenerateTokenString(string userName)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name,userName),
                new Claim(ClaimTypes.Role,"Admin"),
            };

            //var staticKey = _config.GetSection("Jwt:Key").Value;
            //var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(staticKey));
            //var signingCred = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);

            RsaSecurityKey rsaSecurityKey = GetRsaKey();
            var signingCred = new SigningCredentials(rsaSecurityKey, SecurityAlgorithms.RsaSha256);

            var securityToken = new JwtSecurityToken(
                issuer: _config["JwtSettings:Issuer"],
                audience: _config["JwtSettings:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(10),
                signingCredentials: signingCred
                );

            string tokenString = new JwtSecurityTokenHandler().WriteToken(securityToken);
            return tokenString;
        }

        private RsaSecurityKey GetRsaKey()
        {
            var rsaKey = RSA.Create();
            string xmlKey = File.ReadAllText(_config.GetSection("JwtSettings:PrivateKeyPath").Value!);
            rsaKey.FromXmlString(xmlKey);
            var rsaSecurityKey = new RsaSecurityKey(rsaKey);
            return rsaSecurityKey;
        }

        private async Task<RSA> GetPrivateKeyFromAzureKeyVault()
        {
            // Get private RSA key from Azure Key Vault
            var keyClient = new KeyClient(new Uri(_config["AzureKeyVault:VaultUrl"]!), new DefaultAzureCredential());
            var rsaKey = await keyClient.GetKeyAsync(_config["AzureKeyVault:KeyName"]);

            // Convert to RSA
            return rsaKey.Value.Key.ToRSA(true);  // 'true' means we want the private key
        }

        #endregion
    }
}
