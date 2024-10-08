using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using TimeOffManager.Core.DTO;

namespace TimeOffManager.Core.Services
{
    public class JwtManager
    {
        private readonly JwtOptions _jwtOptions;

        public JwtManager(IOptions<JwtOptions> jwtOptions)
        {
            _jwtOptions = jwtOptions.Value;
        }

        public Token GenerateToken(int id)
        {
            var token = new Token
            {
                ExpireIn = _jwtOptions.AccessValidFor.TotalMilliseconds,
                AccessToken = CreateToken(id, _jwtOptions.AccessExpiration, _jwtOptions.AccessSigningCredentials),
                RefreshToken = CreateToken(id, _jwtOptions.RefreshExpiration, _jwtOptions.RefreshCredentials)
            };

            return token;
        }

        private string CreateToken(int id, DateTime expirationTime, SigningCredentials credentials)
        {
            var identity = GenerateClaimsIdentity(id);
            var jwt = new JwtSecurityToken(
                issuer: _jwtOptions.Issuer,
                audience: _jwtOptions.Audience,
                claims: identity.Claims,
                expires: expirationTime,
                signingCredentials: credentials);

            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

            return encodedJwt;
        }

        private ClaimsIdentity GenerateClaimsIdentity(int id)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, id.ToString()),
            };

            return new ClaimsIdentity(claims, "Token", ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);
        }
    }
}
