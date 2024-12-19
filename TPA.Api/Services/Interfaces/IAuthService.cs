namespace TPA.Api.Services.Interfaces
{
    public interface IAuthService
    {
        Task<AuthResultModel> Login(LoginModel user);
        Task<AuthResultModel> RefreshToken(TokenRequestModel model);
        Task<bool> RegisterUser(RegisterModel user);
    }
}