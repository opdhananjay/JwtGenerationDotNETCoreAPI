using JwtGeneration.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtGeneration.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class Login_TokenGeneration : ControllerBase
    {

        public readonly IJwtTokenService _IJwtTokenService;
        public Login_TokenGeneration(IJwtTokenService iJwtTokenService)
        {

            _IJwtTokenService = iJwtTokenService;
        }


        [HttpPost("Login")]
        public ActionResult Login(string email ,string pass)
        {

            try
            {  
                Db d =  new Db();
                bool rt = d.LoginValidate(email,pass);
                if (rt) {


                    //var jwtKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("your_strong_secret_key_for_jwt_signing_1234")); // Use a strong key
                    //var credential = new SigningCredentials(jwtKey, SecurityAlgorithms.HmacSha256);  // Use HS256 algorithm for signing

                    //List<Claim> claims = new List<Claim>()
                    //        {
                    //            new Claim("Email", "test@gmail.com")
                    //        };

                    //// Include SigningCredentials in the JwtSecurityToken creation
                    //var sToken = new JwtSecurityToken(
                    //    issuer: "dhanudhanu",
                    //    audience: "your_audience",  // Replace with your audience value
                    //    claims: claims,
                    //    expires: DateTime.Now.AddHours(1),
                    //    signingCredentials: credential);  // This signs the token


                    //var token = new JwtSecurityTokenHandler().WriteToken(sToken);

                    var token = _IJwtTokenService.GenerateToken(email); // pass email thet get from paramters // do after login succefully
                    return Ok(new { message = "Login Successfully", token = token });

                }
                else
                {
                    return BadRequest(new { message = "Invalid" });
                }

            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);

            }
        }

        [Authorize]
        [HttpGet("get")]
        public IActionResult get()
        {
            return Ok("valid");
        }

    }

 
    public class Db
    {
        public bool LoginValidate(string email , string pass)
        {
            string cons = "Data Source=DESKTOP-4MBNUGA;Initial Catalog=MainProject;Persist Security Info=True;User ID=sa;Password=12345;Encrypt=False;Trust Server Certificate=True";
            using (SqlConnection con = new SqlConnection(cons))
            {
                con.Open();
                using (SqlCommand cmd = new SqlCommand("SELECT * FROM JwtLoginCore WHERE Email=@email AND Password=@pass", con))
                {
                    cmd.Parameters.AddWithValue("@email", email);
                    cmd.Parameters.AddWithValue("@pass", pass);
                    using (SqlDataReader reader = cmd.ExecuteReader())
                    {
                        

                        // If reader has rows, it means email/password match was found
                        if (reader.HasRows)
                        {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

    }


}
