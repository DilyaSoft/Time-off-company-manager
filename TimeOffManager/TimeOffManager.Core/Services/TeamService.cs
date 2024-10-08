using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using TimeOffManager.Core.DTO;
using TimeOffManager.Core.DTO.Team;
using TimeOffManager.Core.Services.Interfaces;
using TimeOffManager.DataAccess.Context;
using TimeOffManager.DataAccess.Models;

namespace TimeOffManager.Core.Services
{
    public class TeamService(DataContext dataContext,
        IAccountService accountService,
        UserManager<User> userManager) : ITeamService
    {
        public async Task<DTO.SignInResult> AcceptInvite(AcceptInviteDto acceptInvite)
        {
            var user = await dataContext.Users.FirstOrDefaultAsync(x => x.Email == acceptInvite.Email);
            if (user is null)
            {
                return DTO.SignInResult.Error("Not found user with provided email");
            }
            var reset = await userManager.ResetPasswordAsync(user, acceptInvite.ResetToken, acceptInvite.NewPassword);
            user.InviteStatus = DataAccess.Enums.InviteStatus.Accepted;
            user.JobTitle = acceptInvite.JobTitle;
            user.BirthDate = acceptInvite.BirthDate;
            user.StartWorkDate = DateTime.UtcNow;
            await dataContext.SaveChangesAsync();
            var res = await accountService.SignIn(user.UserName ?? "", acceptInvite.NewPassword);
            return res;
        }

        public async Task<Manager> AssignTeamToManager(Manager manager, int teamId)
        {
            manager.TeamId = teamId;
            await dataContext.SaveChangesAsync();
            return manager;
        }

        public async Task<CreateTeamResult> CreateTeam(Team team)
        {
            await dataContext.Teams.AddAsync(team);
            await dataContext.SaveChangesAsync();
            return CreateTeamResult.Ok(team);
        }

        public async Task<Team> CreateDefaultTeamForManager(int companyId)
        {
            var team = new Team()
            {
                Name = "Auto-created",
            };
            await dataContext.Teams.AddAsync(team);
            await dataContext.SaveChangesAsync();
            return team;
        }

        public async Task EditTeamName(int teamId, string teamName)
        {
            var team = await dataContext.Teams.FindAsync(teamId);
            team.Name = teamName;
            await dataContext.SaveChangesAsync();
        }

        public async Task<int> GetManagerIdByTeamId(int teamId)
        {
            var team = await dataContext.Teams
                .Include(x => x.Employees)
                .FirstOrDefaultAsync(x => x.Id == teamId);
            
            var man = team.Employees.FirstOrDefault(x => x is Manager);
            return man.Id;
        }

        public async Task RemoveFromTeam(int userId)
        {
            var user = await dataContext.Users.Include(x => x.Team).FirstOrDefaultAsync(x => x.Id == userId);
            await userManager.DeleteAsync(user);
            await dataContext.SaveChangesAsync();
        }
    }
}
