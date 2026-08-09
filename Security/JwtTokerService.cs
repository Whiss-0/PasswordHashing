using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Api.Modules.UserModule;

namespace Api.Security
{
    public interface IJwtTokenService
    {
        string GenerateToken(User user);
        TimeSpan AccessTokenLifetime { get; }
        TimeSpan RefreshTokenLifetime { get; }
        Guid? GetUserIdFromExpiredToken(string token);
    }

    public class JwtTokenService : IJwtTokenService
    {
        private readonly IConfiguration _configuration;
        private readonly string _secretKey;
        private readonly string _issuer;
        private readonly string _audience;

        public TimeSpan AccessTokenLifetime { get; }
        public TimeSpan RefreshTokenLifetime { get; }

        public JwtTokenService(IConfiguration configuration)
        {
            _configuration = configuration;
            _secretKey   = _configuration["Jwt:Key"]      ?? "p7XJ9qA4tZf2LwR8mC0uVbN6yHkT3sPdQ5rE";
            _issuer      = _configuration["Jwt:Issuer"]   ?? "ContactDB-API";
            _audience    = _configuration["Jwt:Audience"] ?? "ContactDB-Client";

            int expirationMinutes = int.TryParse(
                _configuration["Jwt:ExpirationMinutes"], out int exp) ? exp : 15;

            int refreshDays = int.TryParse(
                _configuration["Jwt:RefreshTokenDays"], out int rDays) ? rDays : 7;

            AccessTokenLifetime  = TimeSpan.FromMinutes(expirationMinutes);
            RefreshTokenLifetime = TimeSpan.FromDays(refreshDays);
        }

        public string GenerateToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_secretKey);

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.PublicId.ToString()),
                new Claim("internal_user_id",        user.UserId.ToString()),
                new Claim(ClaimTypes.Name,           user.UserName),
                new Claim(ClaimTypes.Email,          user.UserEmail),
                new Claim("user_role_id",            user.RoleId.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject            = new ClaimsIdentity(claims),
                Expires            = DateTime.UtcNow.Add(AccessTokenLifetime),
                Issuer             = _issuer,
                Audience           = _audience,
                SigningCredentials  = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public Guid? GetUserIdFromExpiredToken(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.UTF8.GetBytes(_secretKey);

                var parameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey        = new SymmetricSecurityKey(key),
                    ValidateIssuer          = true,
                    ValidIssuer             = _issuer,
                    ValidateAudience        = true,
                    ValidAudience           = _audience,
                    ValidateLifetime        = false
                };

                var principal = tokenHandler.ValidateToken(token, parameters, out _);
                var idClaim   = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                return Guid.TryParse(idClaim, out Guid userId) ? userId : null;
            }
            catch
            {
                return null;
            }
        }
    }
}