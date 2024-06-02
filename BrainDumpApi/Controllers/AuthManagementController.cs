using BrainDumpApi.Models.DTOs;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace BrainDumpApi.Controllers
{
    public class AuthManagementController : ControllerBase
    {

        private readonly ILogger<AuthManagementController> _logger;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly JwtConfig _jwtConfig;
        public AuthManagementController(ILogger<AuthManagementController> logger, UserManager<IdentityUser> userManager, IOptionsMonitor<JwtConfig> _optionsMonitor)
        {
            _logger = logger;
            _userManager = userManager;
            _jwtConfig = _optionsMonitor.CurrentValue;
        }

        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] UserRegistrationRequestDto requestDto)
        {
            if (ModelState.IsValid)
            {
                // check if email exists
                var emailExists = await _userManager.FindByEmailAsync(requestDto.Email);

                if (emailExists != null)
                {
                    return BadRequest("Email already exists");
                }

                var newUser = new IdentityUser
                {
                    Email = requestDto.Email,
                    UserName = requestDto.Name,
                };

                var isCreated = await _userManager.CreateAsync(newUser, requestDto.Password);

                if(isCreated.Succeeded)
                {
                    // Generate token
                    var token = GenerateJwtToken(newUser);

                    return Ok(new RegistrationRequestResponse()
                    {
                        Result = true,
                        Token = token
                    });
                }

                return BadRequest(isCreated.Errors.Select(e => e.Description).ToList());

            }

            return BadRequest("Invalid request payload");
        }

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] UserLoginRequestDto requestDto)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(requestDto.Email);

                if(user == null)
                {
                    return BadRequest("Invalid authentication");
                }

                var isPasswordValid = await _userManager.CheckPasswordAsync(user, requestDto.Password);

                if (isPasswordValid)
                {
                    var token = GenerateJwtToken(user);

                    return Ok(new LoginRequestResponse()
                    {
                        Token = token,
                        Result = true
                    });
                }

            }

            return BadRequest("Invalid authentication");
        }

        private string GenerateJwtToken(IdentityUser user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            var key = Encoding.ASCII.GetBytes(_jwtConfig.Secret);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("Id", user.Id),
                    new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                    new Claim(JwtRegisteredClaimNames.Email, user.Id),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                }),
                Expires = DateTime.UtcNow.AddHours(4),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = jwtTokenHandler.WriteToken(token);
        
            return jwtToken;
        }
    }
}
