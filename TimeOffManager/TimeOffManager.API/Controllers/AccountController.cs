using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using TimeOffManager.Core.DTO;
using TimeOffManager.Core.Services.Interfaces;
using TimeOffManager.DataAccess.Models;

namespace TimeOffManager.API.Controllers
{
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class AccountController : ControllerBase
    {
        private readonly IAccountService _accountService;
        private readonly ITeamService _teamsService;
        private readonly ICompanyService _companyService;
        private readonly IHttpContextAccessor _contextAccessor;
        private readonly IOptions<JwtOptions> _jwtOptions;

        public AccountController(IAccountService accountService, IHttpContextAccessor contextAccessor,
            ICompanyService companyService,
            ITeamService teamService,
            IOptions<JwtOptions> options)
        {
            _jwtOptions = options;
            _teamsService = teamService;
            _companyService = companyService;
            _accountService = accountService;
            _contextAccessor = contextAccessor;
        }

        [AllowAnonymous]
        [HttpGet("get-authorized")]
        public async Task<IActionResult> GetAuthorizedCompany([FromQuery] bool withCompany)
        {
            if (_contextAccessor?.HttpContext?.User == null) return Ok();
            
            var signed = await _accountService.GetIfAuthorized(_contextAccessor.HttpContext.User, withCompany);
            
            if (signed == null) return Ok();
            
            var user = await _accountService.GetIdentity(_contextAccessor.HttpContext.User);
            if (user is Manager manager && await _accountService.IsOwner(manager))
            {
                signed.RoleName = "Owner";
            }

            return Ok(signed);

        }

        [AllowAnonymous]
        [HttpPost("refresh-token")]
        public async Task<IActionResult> GenerateTokenAsync([FromBody] Token token)
        {
            var refreshed = await _accountService.RefreshToken(token.RefreshToken);
            return Ok(refreshed);
        }

        [AllowAnonymous]
        [HttpPost("login-to-company-workspace")]
        public async Task<IActionResult> Login([FromBody] LoginToCompanyDTO loginToCompany)
        {
            var result = await _accountService.SignIn(loginToCompany.Email, loginToCompany.Password);

            if (result.Success)
            {
                return Ok(result);
            }

            return Ok(result);
        }

        [AllowAnonymous]
        [HttpPost("sign-up")]
        public async Task<IActionResult> SignUp([FromBody] SignUpDTO singUp)
        {
            var res = await _accountService.SignUpOwner(singUp.Email, singUp.Password, singUp.FirstName, singUp.LastName,
                singUp.BirthDate, singUp.JobTitle ?? "");

            return Ok(res);
        }

        [AllowAnonymous]
        [HttpGet("is-invite-valid")]
        public async Task<IActionResult> IsInviteValid([FromQuery] string emeil)
        {
            var isValid = await _accountService.IsInviteValid(emeil);
            return Ok(isValid);
        }

        [AllowAnonymous]
        [HttpPost("accept-invite")] 
        public async Task<IActionResult> AcceptInvite([FromBody] AcceptInviteDto acceptInvite)
        {
            var res = await _teamsService.AcceptInvite(acceptInvite);
            return Ok(res);
        }

        [HttpPost("update-profile")]
        public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileDTO updateProfile)
        {
            var user = await _accountService.GetIfAuthorized(_contextAccessor.HttpContext.User);
            var res = await _accountService.UpdateProfile(updateProfile, user);
            return Ok(res);
        }

        [HttpPost("sign-out")]
        public async Task<IActionResult> SignOut()
        {
            var user = await _accountService.GetIfAuthorized(_contextAccessor.HttpContext.User);
            if (user is null)
            {
                return Unauthorized();
            }
            await _accountService.SignOut();
            await _contextAccessor.HttpContext.SignOutAsync(JwtBearerDefaults.AuthenticationScheme);

            return Ok();
        }

        [Authorize]
        [HttpPatch("update-allowance-timeoff")]
        public async Task<IActionResult> UpdateAllowanceTimeOff(UpdateAllowanceTimeOffDTO timeOffDTO)
        {
            await _accountService.UpdateAllowanceTimeOffForUser(timeOffDTO.UserId, timeOffDTO.TotalTimeOff,
                timeOffDTO.TookTimeOff);

            return Ok();
        }
    }
}
