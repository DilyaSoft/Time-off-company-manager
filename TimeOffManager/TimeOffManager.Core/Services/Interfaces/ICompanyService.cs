using TimeOffManager.DataAccess.Models;

namespace TimeOffManager.Core.Services.Interfaces
{
    public interface ICompanyService
    {
        public Task<Company> CreateCompany(Company company);
        public Task<Manager> AssignCompanyToManager(int companyId, Manager manager);
        public Task<IEnumerable<User>> GetAllUsersFromCompany(int companyId);
        public Task<IEnumerable<Team>> GetAllTeamsFromCompany(int companyId);
    }
}
