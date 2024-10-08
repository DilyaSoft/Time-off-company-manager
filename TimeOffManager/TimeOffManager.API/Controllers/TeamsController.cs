using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TimeOffManager.Core.Services.Interfaces;
using TimeOffManager.DataAccess.Models;

namespace TimeOffManager.API.Controllers;

[Authorize]
[ApiController]
[Route("[controller]")]
public class TeamsController(ITeamService teamService, 
    IAccountService accountService,
    IHttpContextAccessor contextAccessor) : ControllerBase
{
    [HttpPost("create")]
    public async Task<IActionResult> CreateTeam([FromQuery] string name)
    {
        if (contextAccessor.HttpContext?.User == null || !contextAccessor.HttpContext.User.Identity.IsAuthenticated)
        {
            return Unauthorized();
        }
        
        var user = await accountService.GetIfAuthorized(contextAccessor.HttpContext.User);
        if (user is null)
        {
            return Unauthorized();
        }
        
        var createResult = await teamService.CreateTeam(new Team()
        {
            Name = name
        });
        
        return Ok(createResult);
    }
}