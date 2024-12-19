using Newtonsoft.Json;
using System.ComponentModel.DataAnnotations;

public class TokenRequestModel
{
    [Required]
    public string JwtToken { get; set; }
    [Required]
    public string RefreshToken { get; set; }
}