using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

public interface IJwtTokenService
{
    string GenerateToken(string email);
}

public class JwtTokenService:IJwtTokenService
{
    private readonly string _key;
    private readonly string _issuer;
    private readonly string _audience;
    private readonly TimeSpan _expiry;

    public JwtTokenService(IConfiguration configuration)
    {
        _key = configuration["Jwt:Key"];
        _issuer = configuration["Jwt:Issuer"];
        _audience = configuration["Jwt:audience"];
        _expiry = TimeSpan.FromMinutes(int.Parse(configuration["Jwt:ExpiryMinutes"]));

    }

    public string GenerateToken(string email)
    {
        // define the security key and credential
        var jwtKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_key));
        var credential = new SigningCredentials(jwtKey, SecurityAlgorithms.HmacSha256);

        // define the claims 
        var claims = new List<Claim>()
        {
            new Claim(ClaimTypes.Email, email),
        };

        // create the token 
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.Add(_expiry),
            Issuer = _issuer,
            Audience = _audience,
            SigningCredentials = credential

        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);

    }



}

