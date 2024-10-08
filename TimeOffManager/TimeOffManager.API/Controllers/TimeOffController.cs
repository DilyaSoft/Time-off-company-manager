using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TimeOffManager.Core.DTO;
using TimeOffManager.Core.Services.Interfaces;
using TimeOffManager.DataAccess.Models;

namespace TimeOffManager.API.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TimeOffController : ControllerBase
    {
        private readonly ITimeOffService _timeOffService;
        private readonly ITeamService _teamService;

        public TimeOffController(ITimeOffService timeOffService, ITeamService teamService)
        {
            _teamService = teamService;
            _timeOffService = timeOffService;
        }

        [Authorize]
        [HttpPost("get-time-offs-by-user-and-months")]
        public async Task<IActionResult> GetTimeOffsByUserAndMonths([FromBody] GetTimeOffsByUserRequest getTimeOffsBy)
        {
            var timeOffs = await _timeOffService.GetTimeOffsByUserIdAndPeriod(getTimeOffsBy.UserId, 
                getTimeOffsBy.Months, getTimeOffsBy.Year ,getTimeOffsBy.IsApproved);
            return Ok(timeOffs);
        }

        [Authorize]
        [HttpPost("add-time-off")]
        public async Task<IActionResult> AddTimeOff([FromBody] AddTimeOffDto timeOff)
        {
            var manId = await _teamService.GetManagerIdByTeamId(timeOff.TeamId);
            var added = await _timeOffService.AddTimeOffRequest(new TimeOff()
            {
                EmployeeId = timeOff.EmployeeId,
                StartDate = timeOff.StartDate,
                EndDate = timeOff.EndDate,
                Note = timeOff.Note,
                Type = timeOff.Type,
            }, manId);
            return Ok(added);
        }
    }
}
