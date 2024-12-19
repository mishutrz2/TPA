public class AuthResultModel
{
    public bool IsLogedIn { get; set; } = false;
    public string JwtToken { get; set; }
    public string RefreshToken { get; internal set; }
    public DateTime ExpiresAt { get; set; }
}
