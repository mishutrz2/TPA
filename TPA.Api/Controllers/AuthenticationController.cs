using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using TPA.Api.Services.Interfaces;
using TPA.Domain.Models;

[Route("api/[controller]")]
[ApiController]
public class AuthenticationController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IConfiguration _configuration;
    private readonly TokenValidationParameters _tokenValidationParameters;

    private readonly IAuthService _authService;

    public AuthenticationController(
        ApplicationDbContext context,
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IConfiguration configuration,
        TokenValidationParameters tokenValidationParameters,
        IAuthService authService)
    {
        _context = context;
        _userManager = userManager;
        _signInManager = signInManager;
        _configuration = configuration;
        _tokenValidationParameters = tokenValidationParameters;
        _authService = authService;
    }

    [HttpPost("register")]
    public async Task<IActionResult> RegisterUser(RegisterModel user)
    {
        if (await _authService.RegisterUser(user))
        {
            return Ok("Successfully done");
        }
        return BadRequest("Something went wrong");
    }

    /*[HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest("Please provide the required fields");
        }

        var user = await _userManager.FindByNameAsync(loginModel.Username);
        if (user == null || !await _userManager.CheckPasswordAsync(user, loginModel.Password))
        {
            return Unauthorized(new { Message = "Invalid username or password" });
        }

        var existingRefreshToken = await _context.RefreshTokens.FirstOrDefaultAsync(x => x.UserId == user.Id);
        if (existingRefreshToken != null)
        {
            var onlyAccessToken = await GenerateJwtTokenAsync(user, existingRefreshToken);
            return Ok(onlyAccessToken);
        }

        var token = await GenerateJwtTokenAsync(user, null);
        return Ok(token);
    }*/

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginModel user)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest();
        }
        var loginResult = await _authService.Login(user);
        if (loginResult.IsLogedIn)
        {
            return Ok(loginResult);
        }
        return Unauthorized();
    }

    /*[HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken([FromBody] TokenRequestModel tokenRequestModel)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest("Please provide the required fields");
        }

        var result = await VerifyAndGenerateTokenAsync(tokenRequestModel);
        return Ok(result);
    }*/

    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken(TokenRequestModel model)
    {

        var loginResult = await _authService.RefreshToken(model);
        if (loginResult.IsLogedIn)
        {
            return Ok(loginResult);
        }
        return Unauthorized();
    }

    /*private async Task<AuthResultModel> VerifyAndGenerateTokenAsync(TokenRequestModel tokenRequestModel)
    {
        var jwtTokenHandler = new JwtSecurityTokenHandler();
        var storedToken = await _context.RefreshTokens.FirstOrDefaultAsync(x => x.Token == tokenRequestModel.RefreshToken);
        var dbUser = await _userManager.Users.FirstOrDefaultAsync(u => u.Id == storedToken.UserId);

        try
        {
            var tokenCheckResult = jwtTokenHandler.ValidateToken(tokenRequestModel.Token, _tokenValidationParameters, out var validatedToken);

            return await GenerateJwtTokenAsync(dbUser, storedToken);
        }
        catch (SecurityTokenExpiredException)
        {
            if (storedToken.DateExpire >= DateTime.UtcNow)
            {
                return await GenerateJwtTokenAsync(dbUser, storedToken);
            }
            else
            {
                return await GenerateJwtTokenAsync(dbUser, null);
            }
        }
    }

    private async Task<AuthResultModel> GenerateJwtTokenAsync(ApplicationUser user, RefreshToken rToken)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.UserName),
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.Sub, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        // JWT Header
        var header = new JwtHeader(new SigningCredentials(new RsaSecurityKey(GetPrivateKeyFromAzureKeyVault().Result), SecurityAlgorithms.RsaSha256));

        // JWT Payload
        var payload = new JwtPayload(
            _configuration["JwtSettings:Issuer"],
            _configuration["JwtSettings:Audience"],
            claims,
            DateTime.Now,
            DateTime.Now.AddMinutes(10) // Set expiration as needed
        );

        // Base64 URL encode the header and payload
        var headerBase64 = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(header)));
        var payloadBase64 = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(payload)));

        // Combine the header and payload to form the data to be signed
        var dataToSign = headerBase64 + "." + payloadBase64;

        // Get private RSA key from Azure Key Vault for signing
        var keyClient = new KeyClient(new Uri(_configuration["AzureKeyVault:VaultUrl"]!), new DefaultAzureCredential());
        var rsaKey = keyClient.GetKey(_configuration["AzureKeyVault:KeyName"]).Value;
        var cryptoClient = new CryptographyClient(new Uri($"{_configuration["AzureKeyVault:VaultUrl"]}/keys/{_configuration["AzureKeyVault:KeyName"]}"), new DefaultAzureCredential());

        // Sign the JWT data using the private RSA key
        var signResult = await cryptoClient.SignAsync(SignatureAlgorithm.RS256, Encoding.UTF8.GetBytes(dataToSign));

        // Combine the signed data with the signature to form the final JWT
        var finalJwt = dataToSign + "." + Base64UrlEncode(signResult.Signature);

        // Return the JWT token
        var jwtToken = finalJwt;

        if (rToken != null)
        {
            return new AuthResultModel()
            {
                Token = jwtToken,
                RefreshToken = rToken.Token,
                ExpiresAt = DateTime.UtcNow.AddMinutes(10)
            };
        }

        // Generate and return a new refresh token
        var refreshToken = new RefreshToken()
        {
            JwtId = Guid.NewGuid().ToString(),
            IsRevoked = false,
            UserId = user.Id,
            DateAdded = DateTime.UtcNow,
            DateExpire = DateTime.UtcNow.AddMonths(6),
            Token = Guid.NewGuid().ToString() + "-" + Guid.NewGuid().ToString(),
        };

        await _context.RefreshTokens.AddAsync(refreshToken);
        await _context.SaveChangesAsync();

        return new AuthResultModel()
        {
            Token = jwtToken,
            RefreshToken = refreshToken.Token,
            ExpiresAt = DateTime.UtcNow.AddMinutes(10)
        };
    }*/
}