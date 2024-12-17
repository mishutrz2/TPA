using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
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

    public AuthenticationController(
        ApplicationDbContext context,
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IConfiguration configuration,
        TokenValidationParameters tokenValidationParameters)
    {
        _context = context;
        _userManager = userManager;
        _signInManager = signInManager;
        _configuration = configuration;
        _tokenValidationParameters = tokenValidationParameters;
    }

    [HttpPost("login")]
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
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterModel registerModel)
    {
        var user = new ApplicationUser
        {
            UserName = registerModel.Username,
            Email = registerModel.Email
        };

        var result = await _userManager.CreateAsync(user, registerModel.Password);
        if (!result.Succeeded)
        {
            return BadRequest(result.Errors);
        }

        return Ok(new { Message = "Registration successful" });
    }

    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken([FromBody] TokenRequestModel tokenRequestModel)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest("Please provide the required fields");
        }

        var result = await VerifyAndGenerateTokenAsync(tokenRequestModel);
        return Ok(result);
    }

    private async Task<AuthResultModel> VerifyAndGenerateTokenAsync(TokenRequestModel tokenRequestModel)
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

        // HMAC Symmetric
        // var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtSettings:Secret"]));
        // var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        // RSA Asymmetric
        var rsaKey = RSA.Create();
        // to be continued ...

        var token = new JwtSecurityToken(
            issuer: _configuration["JwtSettings:Issuer"],
            audience: _configuration["JwtSettings:Audience"],
            claims: claims,
            expires: DateTime.Now.AddMinutes(10),
            signingCredentials: creds);

        var jwtToken = new JwtSecurityTokenHandler().WriteToken(token);

        if (rToken != null)
        {
            var rTokenResponse = new AuthResultModel()
            {
                Token = jwtToken,
                RefreshToken = rToken.Token,
                ExpiresAt = token.ValidTo
            };

            return rTokenResponse;
        }

        var refreshToken = new RefreshToken()
        {
            JwtId = token.Id,
            IsRevoked = false,
            UserId = user.Id,
            DateAdded = DateTime.UtcNow,
            DateExpire = DateTime.UtcNow.AddMonths(6),
            Token = Guid.NewGuid().ToString()+"-"+Guid.NewGuid().ToString(),
        };

        await _context.RefreshTokens.AddAsync(refreshToken);
        await _context.SaveChangesAsync();

        var response = new AuthResultModel()
        {
            Token = jwtToken,
            RefreshToken = refreshToken.Token,
            ExpiresAt = token.ValidTo
        };

        return response;
    }
}

public class LoginModel
{
    public string Username { get; set; }
    public string Password { get; set; }
}

public class RegisterModel
{
    public string Username { get; set; }
    public string Email { get; set; }
    public string Password { get; set; }
}

public class AuthResultModel
{
    public string Token { get; set; }
    public string RefreshToken { get; set; }
    public DateTime ExpiresAt { get; set; }
}

public class TokenRequestModel
{
    [Required]
    public string Token { get; set; }
    [Required]
    public string RefreshToken { get; set; }
}