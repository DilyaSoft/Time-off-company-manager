using Microsoft.IdentityModel.Tokens;

namespace TimeOffManager.Core.DTO
{
    public class JwtOptions
    {
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public byte[] AccessSecret { get; set; }
        public byte[] RefreshSecret { get; set; }
        public DateTime IssuedAt => DateTime.UtcNow;
        public TimeSpan AccessValidFor { get; set; } = TimeSpan.FromHours(4);
        public TimeSpan RefreshValidFor { get; set; } = TimeSpan.FromDays(90);
        public DateTime AccessExpiration => IssuedAt.Add(AccessValidFor);
        public DateTime RefreshExpiration => IssuedAt.Add(RefreshValidFor);
        public SigningCredentials AccessSigningCredentials { get; set; }
        public SigningCredentials RefreshCredentials { get; set; }
    }
}
