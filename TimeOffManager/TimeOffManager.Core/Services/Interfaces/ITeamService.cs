using TimeOffManager.Core.DTO;
using TimeOffManager.Core.DTO.Team;
using TimeOffManager.DataAccess.Models;

namespace TimeOffManager.Core.Services.Interfaces
{
    public interface ITeamService
    {
        public Task<CreateTeamResult> CreateTeam(Team team);
        public Task<Team> CreateDefaultTeamForManager(int companyId);
        public Task<Manager> AssignTeamToManager(Manager manager, int teamId);
        public Task EditTeamName(int teamId, string teamName);
        public Task RemoveFromTeam(int userId);
        public Task<int> GetManagerIdByTeamId(int teamId); 
        public Task<SignInResult> AcceptInvite(AcceptInviteDto acceptInvite);
    }
}
