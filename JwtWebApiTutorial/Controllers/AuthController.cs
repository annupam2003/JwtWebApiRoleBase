using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JwtWebApiTutorial.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration configuration;

        public AuthController(IConfiguration configuration)
        {
            this.configuration = configuration;
        }

        [HttpPost("Register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.UserName = request.UserName;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            return Ok(user);
        }

        [HttpPost("Login")]
        public async Task<ActionResult<User>> Login(UserDto request)
        {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            if (user.UserName != request.UserName)
                return BadRequest("User not found");
            if(! PasswordVerifyHash(request.Password,user.PasswordHash,user.PasswordSalt))
                return BadRequest("Wrong Password");
            var token = CreateToken(user);
            return Ok(token);
        }

        private string CreateToken(User user)
        {
            var claims = new List<Claim> { new Claim(ClaimTypes.Name, user.UserName), new Claim(ClaimTypes.Role, "Admin") };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(this.configuration.GetSection("AppSetting:Token").Value));
            var siginCredintial = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: siginCredintial
                );
            var jwt = new  JwtSecurityTokenHandler().WriteToken(token);
            return jwt;

        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using var hmac = new HMACSHA512();
            passwordSalt = hmac.Key;
            passwordHash=hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
        }
        private bool PasswordVerifyHash(string password, byte[] passwordHashExist, byte[] passwordSalt)
        {
            using var hmac = new HMACSHA512(passwordSalt);
            var passwordHashNew = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            return passwordHashNew.SequenceEqual(passwordHashExist);
        }
    }
}
