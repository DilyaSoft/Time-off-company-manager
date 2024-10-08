using Microsoft.EntityFrameworkCore;
using TimeOffManager.Core.Services.Interfaces;
using TimeOffManager.DataAccess.Context;
using TimeOffManager.DataAccess.Models;

namespace TimeOffManager.Core.Services
{
    public class CompanyService(DataContext dataContext, ITeamService teamService) : ICompanyService
    {
        public async Task<Manager> AssignCompanyToManager(int companyId, Manager manager)
        {
            var defaultTeam = await teamService.CreateDefaultTeamForManager(companyId);
            manager.TeamId = defaultTeam.Id;
            await dataContext.SaveChangesAsync();
            return manager;
        }

        public async Task<Company> CreateCompany(Company company)
        {
            await dataContext.Companies.AddAsync(company);
            await dataContext.SaveChangesAsync();
            return company;
        }

        public async Task<IEnumerable<Team>> GetAllTeamsFromCompany(int companyId)
        {
            var teams = await dataContext.Teams
                .Include(x => x.Employees).ThenInclude(x => x.Company)
                .Where(x => x.Employees.Any(y => y.CompanyId == companyId)).ToListAsync();
            
            return teams;
        }

        public async Task<IEnumerable<User>> GetAllUsersFromCompany(int companyId)
        {
            var company = await dataContext.Companies
                .Include(x => x.Employees).Where(x => x.Id == companyId)
                .ToListAsync();

            return company.SelectMany(x => x.Employees);
        }
    }
}
