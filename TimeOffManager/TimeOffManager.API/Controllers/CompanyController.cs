using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TimeOffManager.Core.DTO;
using TimeOffManager.Core.Services.Interfaces;
using TimeOffManager.DataAccess.Models;

namespace TimeOffManager.API.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class CompanyController : ControllerBase
    {
        private readonly ICompanyService _companyService;
        private readonly IAccountService _accountService;
        private readonly ITeamService _teamService;
        private readonly IHttpContextAccessor _contextAccessor;

        public CompanyController(ICompanyService companyService, IHttpContextAccessor contextAccessor,
            ITeamService teamService,
            IAccountService accountService)
        {
            _accountService = accountService;
            _companyService = companyService;
            _teamService = teamService;
            _contextAccessor = contextAccessor;
        }

        [Authorize]
        [HttpPost("create-company")]
        public async Task<IActionResult> CreateCompany()
        {
            var files = _contextAccessor.HttpContext.Request.Form.Files;
            var company = new Company();
            if (files.Any())
            {
                using var stream = new MemoryStream();
                files[0].CopyTo(stream);
                var bytes = stream.ToArray();
                company.Logo = bytes;
            }
            var currentManager = await _accountService.GetIfAuthorized(_contextAccessor.HttpContext.User) as Manager;
            company.Name = _contextAccessor.HttpContext.Request.Form["companyName"];
            var created = await _companyService.CreateCompany(company);
            await _companyService.AssignCompanyToManager(created.Id, currentManager);
            return Ok(new
            {
                Name = created.Name,
                LogoBase64 = created.Logo != null ?
                    Convert.ToBase64String(created.Logo) : ""
            });
        }

        [Authorize]
        [HttpGet("get-company-users")]
        public async Task<IActionResult> GetCompanyUsers([FromQuery] int companyId)
        {
            var users = await _companyService.GetAllUsersFromCompany(companyId);
            var usersDto = new List<User>();
            foreach (var user in users)
            {
                usersDto.Add(new User()
                {
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    Email = user.Email,
                    StartWorkDate = user.StartWorkDate,
                    BirthDate = user.BirthDate,
                    Id = user.Id,
                    RoleName = user is Manager man && await _accountService.IsOwner(man) ? "Owner" : user.RoleName,
                    JobTitle = user.JobTitle,
                    InviteStatus = user.InviteStatus,
                    TotalAllowanceTimeOffInYear = user.TotalAllowanceTimeOffInYear,
                    TookAllowanceTimeOff = user.TookAllowanceTimeOff,
                });
            }

            return Ok(usersDto);
        }

        [Authorize]
        [HttpPatch("edit-company-name")]
        public async Task<IActionResult> EditComapnyName([FromQuery] string teamName, [FromQuery] int id)
        {
            await _teamService.EditTeamName(id, teamName);
            return Ok();
        }

        [Authorize]
        [HttpDelete("remove-from-team")]
        public async Task<IActionResult> RemvoeFromTeam([FromQuery] int userId)
        {
            await _teamService.RemoveFromTeam(userId);
            return Ok();
        }

        [Authorize]
        [HttpPost("send-invite")]
        public async Task<IActionResult> SendInviteToTeam([FromBody] SendInviteDto sendInvite)
        {
            var defaultUser = await _accountService.CreateDefaultUser(sendInvite.FirstName, sendInvite.LastName, sendInvite.Email,
                    sendInvite.TeamId);

            await _accountService.SendInviteToTeam(defaultUser, sendInvite.TeamId);

            return Ok(defaultUser);
        }
    }
}
