using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using JWT_Authorization_Example.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace JWT_Authorization_Example.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private IConfiguration _config;

        public LoginController(IConfiguration config)
        {
            _config = config;
        }

        [HttpGet]
        public IActionResult Login(string UserName , string Pass)
        {
            UserModel login = new UserModel();
            login.UserName = UserName;
            login.Password = Pass;
            IActionResult response = Unauthorized();

            var user = AuthenticateUser(login);

            if (user!= null)
            {
                var tokenStr = GenarateJSONWebToken(user);
                response = Ok(new { token = tokenStr });
            }
            return response;
        }

        private string GenarateJSONWebToken(UserModel userInfo)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub,userInfo.UserName),
                new Claim(JwtRegisteredClaimNames.Email,userInfo.Email),
                new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
                //  new Claim(JwtRegisteredClaimNames.Sub,userInfo.UserName),
                //new Claim(JwtRegisteredClaimNames.NameId,userInfo.UserName),
                //new Claim("Name",userInfo.UserName),
                //new Claim(ClaimsIdentity.DefaultNameClaimType,userInfo.UserName),
                //new Claim(JwtRegisteredClaimNames.Email,userInfo.Email),
                //new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                    issuer: _config["Jwt:Issuer"],
                    audience: _config["Jwt:Issuer"],
                    claims,
                    expires: DateTime.Now.AddMinutes(120),
                    signingCredentials: credentials);
            var encodetoken = new JwtSecurityTokenHandler().WriteToken(token);
            return encodetoken;
        }

        private UserModel AuthenticateUser(UserModel login)
        {
            UserModel user = null;
            if (login.UserName == "kaveen" && login.Password == "123")
            {
                user = new UserModel { UserName = "Kaveen", Email = "kaveen@gmail.com", Password = "123" };
            }
            return user;
        }

        [Authorize]
        [HttpPost("post")]
        public string post()
        {
            var identity = HttpContext.User.Identity as ClaimsIdentity;
            IList<Claim> claim = identity.Claims.ToList();
            var userName = claim[0].Value;
            return "Welcome to : " + userName;
        }

        [Authorize]
        [HttpGet("GetValue")]
        public ActionResult<IEnumerable<string>> Get()
        {
            return new string[] { "value1", "value2" };
        }
    }
}
