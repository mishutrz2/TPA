using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using TPA.Api.Services.Interfaces;
using TPA.Domain.Models;

namespace TPA.Api.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _config;
        private readonly CryptographyClient _cryptoClient;
        private readonly KeyClient _keyClient;

        public AuthService(UserManager<ApplicationUser> userManager, IConfiguration config, CryptographyClient cryptoClient, KeyClient keyClient)
        {
            _userManager = userManager;
            _config = config;
            _cryptoClient = cryptoClient;
            _keyClient = keyClient;
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
            var principal = await GetTokenPrincipal(model.JwtToken);

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
            response.JwtToken = await this.GenerateTokenString(identityUser!.UserName!);
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

        private async Task<ClaimsPrincipal?> GetTokenPrincipal(string token)
        {
            //var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetSection("Jwt:Key").Value));

            var securityKey = await GetPrivateKeyFromAzureKeyVault();

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

        private async Task<string> GenerateTokenString(string userName)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name,userName),
                new Claim(ClaimTypes.Role,"Admin"),
            };

            RsaSecurityKey rsaSecurityKey = await GetPrivateKeyFromAzureKeyVault();
            var signingCred = new SigningCredentials(rsaSecurityKey, SecurityAlgorithms.RsaSha256);

            // JWT Header
            var header = new JwtHeader(signingCred);

            // JWT Payload
            var payload = new JwtPayload(
                _config["JwtSettings:Issuer"],
                _config["JwtSettings:Audience"],
                claims,
                DateTime.Now,
                DateTime.Now.AddMinutes(10) // Set expiration as needed
            );

            // Base64 URL encode the header and payload
            var headerBase64 = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(header)));
            var payloadBase64 = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(payload)));
            
            // Combine the header and payload to form the data to be signed
            var dataToSign = headerBase64 + "." + payloadBase64;

            // Convert the signing input to bytes
            byte[] signingInputBytes = Encoding.UTF8.GetBytes(dataToSign);

            // Compute the SHA-256 hash
            byte[] hash = SHA256.HashData(signingInputBytes);

            // Sign the JWT data using the private RSA key
            var signResult = await _cryptoClient.SignAsync(SignatureAlgorithm.RS256, hash);

            // Combine the signed data with the signature to form the final JWT
            var tokenString = dataToSign + "." + Base64UrlEncoder.Encode(signResult.Signature);

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

        private async Task<RsaSecurityKey> GetPrivateKeyFromAzureKeyVault()
        {
            // Get private RSA key from Azure Key Vault
            var vaultRsaKey = await _keyClient.GetKeyAsync(_config["AzureKeyVault:KeyName"]);
            var rsaKey = new RsaSecurityKey(vaultRsaKey.Value.Key.ToRSA(true)); // 'true' means we want the private key
            return rsaKey;
        }

        #endregion
    }
}
