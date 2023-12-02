using AuthServices.Model.Account;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthServices.Controllers
{
    [Route("api/account")]
    [ApiController]
    public class AccountController : Controller
    {
        private readonly UserManager<UserModel> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<UserModel> _signInManager;
        private readonly IConfiguration _configuration;
        public AccountController( UserManager<UserModel> userManager,RoleManager<IdentityRole> roleManager,SignInManager<UserModel> signInManager,IConfiguration configuration)
        {
            _userManager= userManager;
            _roleManager= roleManager;
            _signInManager= signInManager;
            _configuration= configuration;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel registerModel)
        {
            if(!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var user = new UserModel
            {
                FirstName = registerModel.FirstName,
                LastName = registerModel.LastName,
                Email = registerModel.Email,
                PhoneNumber = registerModel.PhoneNumber,
                UserName=registerModel.UserName
            };
            if(user !=null && registerModel.Password != null)
            {
                var result = await _userManager.CreateAsync(user, registerModel.Password);
                if(!result.Succeeded)
                {
                    var errors = result.Errors.Select(x => x.Description);
                    return BadRequest(ModelState);
                }
                var roleExists = await _roleManager.RoleExistsAsync("user");
                if (!roleExists)
                {
                    await _roleManager.CreateAsync(new IdentityRole("user"));
                }
                await _userManager.AddToRoleAsync(user, "user");
            }
            return Ok("user registration success!!");
        }

        [HttpPost("login")]
        public async Task<ActionResult<LoginResponse>> login([FromBody] LoginModel loginModel)
        {
            var user = await _userManager.FindByEmailAsync(loginModel.Email);
            var passwordValid=await _userManager.CheckPasswordAsync(user,loginModel.Password);
            if(user==null || passwordValid == false)
            {
                return Unauthorized();
            }
            var tokenString = await GeneratedToken(user);
            var response = new LoginResponse
            {
                Token = tokenString
            };
            return Ok(response);
        }

        private async Task<string> GeneratedToken(UserModel user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var roles=await _userManager.GetRolesAsync(user);
            var roleClaims = roles.Select(q => new Claim(ClaimTypes.Role, q)).ToList();
            var userClaims=await _userManager.GetClaimsAsync(user);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email,user.Email),
                new Claim(JwtRegisteredClaimNames.FamilyName, user.LastName),
                new Claim(JwtRegisteredClaimNames.GivenName, user.FirstName),

                new Claim(ClaimTypes.NameIdentifier,user.Id)

            }.Union(userClaims)
            .Union(roleClaims);

            var token=new JwtSecurityToken(

                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims:claims,
                expires: DateTime.UtcNow.AddHours(Convert.ToInt32(_configuration["Jwt:Duration"])),
                signingCredentials:credentials
                );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
