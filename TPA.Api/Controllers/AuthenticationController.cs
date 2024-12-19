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
    private readonly IAuthService _authService;

    public AuthenticationController(
        IAuthService authService)
    {
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
}